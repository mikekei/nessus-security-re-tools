# nbin — Nessus Plugin Decompiler

Two commands for working with Nessus `.nbin` compiled plugin files.

---

## Commands

### `/nbin-disasm <path>`
Disassemble an `.nbin` file: shows the raw instruction listing **plus** logic
pseudocode. Stops at the pseudocode level — does not attempt to reconstruct
clean NASL syntax. Good for verifying decompiler output and studying VM
behavior.

### `/nbin-decompile <path>`
Full decompilation: runs the same pipeline as `/nbin-disasm`, then rewrites
the pseudocode into clean, idiomatic NASL source. The output is meant to be
readable and close to what the original `.nasl` source looked like.

---

## Step 0 — verify and install

Before doing anything else, check if the `nbin_tools` package is installed:

```bash
python3 -c "import nbin_tools; print('nbin_tools', nbin_tools.__version__)" 2>/dev/null
```

If that prints a version, skip to Step 1.

If it fails, try installing from PyPI first:

```bash
pip install nbin-tools
```

If not on PyPI yet, install from the latest GitHub Release:

```bash
pip install \
  "$(python3 -c "
import urllib.request, json
rel = json.loads(urllib.request.urlopen('https://api.github.com/repos/mikekei/nessus-security-re-tools/releases/latest').read())
assets = [a['browser_download_url'] for a in rel['assets'] if a['name'].endswith('.whl')]
print(assets[0] if assets else '')
")"
```

If the release wheel is not yet available (e.g. CI still running), install directly from source:

```bash
pip install "git+https://github.com/mikekei/nessus-security-re-tools.git"
```

If pip is restricted (system Python), add `--break-system-packages` or use a venv:

```bash
python3 -m venv ~/.venv/nbin && source ~/.venv/nbin/bin/activate
pip install nbin-tools
```

After installation, confirm:

```bash
python3 -c "import nbin_tools; print('nbin_tools', nbin_tools.__version__)"
nbin-decompile --help
```

Only proceed once `import nbin_tools` succeeds.

---

## Decompiler location (after install)

The CLI entry points are installed globally:

| Command | Role |
|---------|------|
| `nbin-disasm` | Raw disassembly + logic pseudocode |
| `nbin-decompile` | Logic pseudocode (cleaner output) |
| `nbin-vm` | Low-level VM parser / opcode stats |

---

## Step 1 — run the decompiler

```bash
nbin-decompile <path> 2>/dev/null
```

- For `/nbin-disasm` use `nbin-disasm <path> 2>/dev/null` which automatically
  adds `--raw --functions` to show the instruction listing alongside pseudocode.
- Capture the full output. It will be large (often 1000–3000 lines).

---

## Step 2 — locate the plugin body

The output always has this structure:

```
// === MAIN CODE ===
<shared library preamble>     ← global_settings init, v4=0, v5=1, hundreds of lines
if (v0 != 0) {                ← description block guard
  script_id(NNNNN);
  ...
  exit(0);                    ← description block ends here
}
<plugin logic>                ← THIS is what matters
...
function func_0xHHHH() { ... } ← helper functions
```

Find the `exit(0)` inside the description block and focus on everything after it.

---

## Step 3A — for `/nbin-disasm`

After running the decompiler:

1. Extract the **description block** (between `if (v0 != 0) {` and `exit(0)`).
2. Extract the **plugin logic** (from after `exit(0)` to the first function definition).
3. Extract the **function definitions** (all `function func_0x...` blocks).
4. Present these three sections clearly labeled.
5. Then review the pseudocode and annotate:
   - Resolve any `func_0xHHHH` whose body makes the purpose obvious (e.g., a one-liner that calls `script_tag` → label it `script_tag_wrapper`).
   - Replace `__acc__` / `__ret__` / `__flag__` with more readable names where the data flow is clear.
   - Add a one-line comment before each function explaining what it does.
   - Flag any `builtin_0xNNN` that can be identified from context (see known map below).

---

## Step 3B — for `/nbin-decompile`

After running the decompiler and reading the pseudocode:

Rewrite the output as clean, idiomatic NASL. Follow these rules:

### Description block
Reconstruct as a proper `if (description)` block:
```nasl
if (description) {
  script_id(NNNNN);
  script_version("...");
  script_name("...");
  script_cve_id("CVE-XXXX-YYYY");
  script_tag(name:"synopsis",     value:"...");
  script_tag(name:"description",  value:"...");
  script_tag(name:"see_also",     value:"...");
  script_tag(name:"solution",     value:"...");
  script_tag(name:"cvss_base",    value:"X.X");
  script_tag(name:"cvss_base_vector", value:"CVSS2#...");
  script_tag(name:"vuln_publication_date",   value:"YYYY/MM/DD");
  script_tag(name:"plugin_publication_date", value:"YYYY/MM/DD");
  script_tag(name:"cpe",          value:"cpe:/...");
  script_tag(name:"plugin_type",  value:"...");
  script_category(ACT_GATHER_INFO);
  script_family("...");
  script_copyright("...");
  script_dependencies("...");
  script_require_keys("...");
  exit(0);
}
```

### Function renaming
Replace `func_0xHHHH` with a descriptive name derived from reading the function body:
- Body only calls `script_tag(__acc__)` → rename to `script_tag_wrapper` (or just inline it)
- Body calls `get_kb_item_or_exit` pattern → rename to `kb_require`
- Body does a DB query → rename to `query_devices` or similar
- Body reports a vuln → rename to `report_vuln`
- If the function is a one-liner, inline it at the call site instead

### Builtin resolution
Replace `builtin_0xNNN` with real function names using the map below.
For unknowns, use the context (arguments, surrounding code) to infer the name
and add a `# ?` comment.

### Variable renaming
Replace `vN` slot names with descriptive names where the value is clear from context:
- Assigned from `get_kb_item("some/key")` → name it `kb_val` or `some_key`
- Loop iterator → `item`, `row`, `serial`, etc.
- Counters → `i`, `count`, `n`
- Report string being built up → `report`
- Only rename when you are confident — leave `vN` otherwise

### Control flow cleanup
- `while (__acc__ < __acc__)` artifacts → remove (decompiler artifact)
- Deeply nested if-chains that are really a switch on a string → rewrite as
  an array/list check: `if (model_name >< model_list)`
- `if (__flag__) { // JZ → [N] }` with empty body → remove
- Obvious `while(1)` loops that contain a single exit → rewrite as
  `do { ... } while(FALSE)` or just flatten

### Accumulator cleanup
- `__acc__` after a `CALL` is the return value — replace with the return variable
  name that follows (the MOV after the CALL captures it)
- `__ret__` → use the variable name it gets assigned to
- `__flag__` → the boolean condition; replace with the actual comparison if visible

### Output format

```nasl
##
# <filename>.nasl
# <one-line description>
##

if (description) {
  ...
  exit(0);
}

# ── Helper functions ─────────────────────────────────────────────────────────

function <name>(<params>) {
  ...
}

# ── Main plugin logic ─────────────────────────────────────────────────────────

<logic here>
```

---

## Known builtin index → NASL function name

Use this map to resolve `builtin_0xNNN`:

```
0x01  script_name            0x02  script_version
0x05  script_copyright       0x06  script_summary
0x07  script_category        0x08  script_family
0x09  script_oid             0x0a  script_dependencies
0x0b  script_require_keys    0x0c  script_require_ports
0x0d  script_exclude_keys    0x0e  script_require_udp_ports
0x0f  script_add_preference  0x10  script_get_preference
0x12  script_mandatory_keys  0x13  script_id
0x15  script_cve_id          0x16  script_bugtraq_id
0x17  get_kb_item            0x18  script_xref
0x19  set_kb_item            0x1a  get_host_ip
0x1b  get_kb_item            0x1c  open_sock_tcp
0x1d  open_sock_udp          0x1e  send
0x1f  recv                   0x20  recv_line
0x21  close                  0x22  get_port_state
0x23  get_udp_port_state     0x25  security_message
0x26  security_warning       0x27  security_note
0x28  security_hole          0x29  log_message
0x2a  display                0x2b  string
0x2c  strcat                 0x2d  strlen
0x2e  substr                 0x2f  chomp
0x30  ereg                   0x31  ereg_replace
0x32  eregmatch              0x33  split
0x34  int                    0x35  hex
0x36  hexstr                 0x37  ord
0x38  chr                    0x39  strtoul
0x3a  tolower                0x3b  toupper
0x3c  str_replace            0x3d  crap
0x3e  raw_string             0x3f  insstr
0x40  max_index              0x41  sort
0x42  keys                   0x43  values
0x44  typeof                 0x45  isnull
0x46  defined_func           0x47  make_array
0x48  make_list              0x49  list_uniq
0x4c  forge_ip_packet        0x4e  get_ip_element
0x4f  set_ip_elements        0x50  get_tcp_element
0x51  forge_tcp_packet       0x52  get_udp_element
0x53  forge_udp_packet       0x54  send_packet
0x55  pcap_next              0x56  dump_tcp_packet
0x57  display                0x58  exit
0x5a  keys                   0x5b  chomp
0x5c  split                  0x5d  ereg
0x5e  substr                 0x5f  strlen
0x60  int                    0x61  sort
0x62  tolower                0x63  toupper
0x64  str_replace            0x65  string
0x66  strcat                 0x67  hexstr
0x68  hex                    0x69  ord
0x6a  exit                   0x6b  get_kb_list
0x6c  replace_kb_item        0x6d  rm_kb_item
0xc3  string                 0xcf  max_index
0xe4  set_kb_item            0xe5  get_kb_item
0x128 script_set_attribute   0x133 log_message
0x13a security_message       0x1a0 isnull
0x1ff make_list
```

---

## NASL language reference (for reconstruction)

### Types and literals
```nasl
x = 5;               # integer
x = "hello";         # string (double-quoted)
x = 'hello';         # string (single-quoted)
x = NULL;            # null
x = TRUE;  x = FALSE; # booleans (also 1 / 0)
x = make_list(a, b); # list
x = make_array("k","v"); # associative array
```

### Operators
```nasl
+  -  *  /  %  **    # arithmetic
&  |  ^  ~  <<  >>   # bitwise
&&  ||  !            # logical
==  !=  <  <=  >  >= # comparison
=~  !~               # regex match / no-match
><  >!<              # substring contains / not contains
+=  -=  *=  /=  |=   # compound assign
x++;  x--;           # increment/decrement
```

### Control flow
```nasl
if (cond) { ... } else { ... }
for (i = 0; i < n; i++) { ... }
while (cond) { ... }
foreach item (list) { ... }
foreach key (keys(array)) { ... }
break;  continue;
try { ... } catch { ... }
```

### Functions
```nasl
function name(param1, param2) {
  local_var x, y;
  return value;
}
result = name(val1, val2);          # positional call
result = name(param1:val1, param2:val2);  # named-arg call
```

### KB operations
```nasl
val = get_kb_item("path/to/key");
set_kb_item(name:"path/to/key", value:val);
vals = get_kb_list("path/to/*");
```

### Reporting
```nasl
security_message(port:port, data:report);
log_message(data:"message", port:0);
exit(0);   # normal exit
exit(1);   # error exit
```

### Regex
```nasl
if (ereg(pattern:"regex", string:str)) { ... }
result = ereg_replace(pattern:"regex", replace:"\\1", string:str);
match = eregmatch(pattern:"regex", string:str);
# match[0]=full match, match[1]=group1, ...
```

---

## VM pseudocode → NASL translation cheat sheet

| Pseudocode pattern | Clean NASL |
|--------------------|-----------|
| `builtin_0xe5(key)` followed by `v42 = __ret__` | `v42 = get_kb_item(key)` |
| `builtin_0xe4(key:k, value:v)` | `set_kb_item(name:k, value:v)` |
| `builtin_0x13a(0, report)` | `security_message(port:0, data:report)` |
| `builtin_0x3(0)` | `exit(0)` |
| `builtin_0x1ff(a, b, c)` | `make_list(a, b, c)` |
| `builtin_0x1a0(x)` then `if (__ret__ != 0)` | `if (isnull(x))` |
| `builtin_0xcf(x)` then `v = __ret__` | `v = max_index(x)` |
| `builtin_0xc3(a, b)` | `string(a, b)` or `a + b` |
| `strlen(x)` then `if (__ret__ == 0)` | `if (strlen(x) == 0)` or `if (!x)` |
| `display(sep:S, K:F)` | `split(str, sep:S, keep:FALSE)` |
| `__acc__ += X` after function result | `result += X` |
| `if (__flag__) { // JZ → [N] }` with empty body | (remove — decompiler artifact) |
| `loc_26` (function-local temp) | rename to descriptive var based on use |
| `// JNZ → [N]` at end of if-body with no else | `} // end if` |
| `while (1 != 0) { ... break }` | Flatten or `do { ... } while(FALSE)` |

---

## Important notes

- The **preamble** (v4=0, v5=1, hundreds of vN assignments) is inlined library
  initialization from included `.inc` files. Skip it entirely in the output —
  it belongs to the runtime, not the plugin.
- `func_0xHHHH` hashes are stable within one nbin but will differ across
  different plugin files (they are FRAME_END byte offsets, not content hashes).
- `loc_26` is always the first local variable inside a function (it maps to
  the function's first local slot). Rename it per context.
- NASL has no type declarations — drop all `local_var` declarations that came
  from the decompiler unless they were explicit in the original.
- `ereg()` in the decompiler output with strange named args like `%b:TRUE`
  is a date-formatting function wrapper — these are internal library calls,
  not raw regex calls.
