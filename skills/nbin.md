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

## Step 2 — split the output into three regions

Every decompiled nbin has exactly this layout:

```
// === MAIN CODE ===

[PREAMBLE]          ← hundreds of assignments: v4=0, v5=1, v6="string", ...
                       ends just before the description guard

if (v0 != 0) {      ← description block guard (v0 is always the description flag)
  script_id(...);
  ...
  exit(0);          ← last line of description block
}

[PLUGIN LOGIC]      ← the actual plugin code; starts on the line after exit(0)

function func_0x...() {   ← helper / library functions follow
  ...
}
```

**Cut points:**
1. Preamble ends at the line immediately before `if (v0 != 0) {`
2. Description block = from `if (v0 != 0) {` through `exit(0);` (inclusive)
3. Plugin logic = from the line after `exit(0);` through the last line before
   the first `function func_0x` declaration
4. Helper functions = everything from the first `function func_0x` to end of output

Do this split before any rewriting. Work on each region in order: description →
helpers → plugin logic.

---

## Step 3A — for `/nbin-disasm`

After splitting:

1. Present the **description block** with a `--- DESCRIPTION ---` header.
2. Present the **plugin logic** with a `--- PLUGIN LOGIC ---` header.
3. Present each **helper function** with a `--- FUNCTION func_0xHHHH ---` header.
4. Annotate each section (do not rewrite — just add comments):
   - One-line `# Purpose: ...` comment before each function explaining what it does.
   - Replace `__acc__` / `__ret__` / `__flag__` with inline comments `/* return value */` etc.
   - For each `func_0xHHHH` call site, add `# → <inferred purpose>` on the same line.
   - For each `builtin_0xNNN`, look it up in the map below and add `# builtin_0xNNN = <name>`.

---

## Step 3B — for `/nbin-decompile`

Work through the five tasks below in order. Each task is independent — complete
one fully before starting the next.

---

### Task 1 — Reconstruct the description block

**How to do it efficiently:**

The description block is fully recoverable verbatim because every value in it
is a string or integer literal that survived compilation intact in the symbol table.

1. Collect every call inside `if (v0 != 0) { ... exit(0); }`.
2. Map each call to its canonical NASL form using this lookup:

   | Pseudocode pattern | NASL |
   |--------------------|------|
   | `script_id(NNNNN)` | `script_id(NNNNN);` |
   | `script_version("...")` | `script_version("...");` |
   | `script_set_attribute(attribute:"synopsis", value:"...")` | `script_tag(name:"synopsis", value:"...");` |
   | `script_set_attribute(attribute:"description", value:"...")` | `script_tag(name:"description", value:"...");` |
   | `script_set_attribute(attribute:"solution", value:"...")` | `script_tag(name:"solution", value:"...");` |
   | `script_set_attribute(attribute:"cvss_base", value:"...")` | `script_tag(name:"cvss_base", value:"...");` |
   | `script_set_attribute(attribute:"see_also", value:"...")` | `script_tag(name:"see_also", value:"...");` |
   | `script_set_attribute(attribute:"plugin_publication_date", value:"...")` | `script_tag(name:"plugin_publication_date", value:"...");` |
   | `script_set_attribute(attribute:"plugin_modification_date", value:"...")` | `script_tag(name:"plugin_modification_date", value:"...");` |
   | `script_cve_id("CVE-...")` | `script_cve_id("CVE-...");` |
   | `script_category(N)` | Look up N: 0=ACT_ATTACK 3=ACT_GATHER_INFO 8=ACT_SETTINGS |
   | `script_family("...")` | `script_family("...");` |
   | `script_copyright("...")` | `script_copyright("...");` |
   | `script_dependencies("a.nasl", "b.nasl")` | `script_dependencies("a.nasl", "b.nasl");` |
   | `script_require_keys("Host/X")` | `script_require_keys("Host/X");` |
   | `script_require_ports("Services/www", 80)` | `script_require_ports("Services/www", 80);` |
   | `script_mandatory_keys("Host/X")` | `script_mandatory_keys("Host/X");` |
   | `script_add_preference(name:"...", type:"...", value:"...")` | keep as-is |

3. Any call in the description block whose name is `func_0xHHHH` — read its body.
   It will be a thin wrapper (e.g., just calls `script_tag` with a fixed `name:`
   arg). Inline the actual call directly; discard the wrapper.

4. Output as:
   ```nasl
   if (description) {
     script_id(NNNNN);
     script_version("...");
     ...
     exit(0);
   }
   ```

---

### Task 2 — Rename variables

**How to do it efficiently:**

Do NOT scan the whole file first. Instead, build a rename table as you encounter
each first assignment to a slot, then apply it everywhere. Use this decision tree:

```
For each assignment  vN = <expr>:

  expr is get_kb_item("A/B/C")
    → name = last path segment, snake_case: "Host/DuckDB/version" → "version"
      if ambiguous (e.g. two vars both from "Host/*/version"), prefix: "duckdb_version"

  expr is get_kb_list("A/B/*")
    → name = plural of last non-wildcard segment: "Host/App/Installs/*" → "installs"

  expr is ereg(pattern:"...", string:vM)  or  eregmatch(...)
    → name = "match" or "ver_match" if the pattern looks like a version regex

  expr is open_sock_tcp(port) or open_sock_udp(port)
    → name = "sock" or "soc"

  expr is recv(...) or recv_line(...)
    → name = "res" or "banner"

  expr is string(...) or strcat(...)  and later used in security_message(data:vN)
    → name = "report"

  expr is integer and vN is used only as a loop counter  (vN++; foreach or for)
    → name = "i" (or "j" if nested)

  expr is integer 0 or 1 and vN is used only as a flag
    → name = "found" or "vuln"

  vN is a function parameter (appears as arg in SLOT list before CALL)
    → use the NASL named-arg key from the SLOT: SLOT(port:vN) → "port"

  no clear context
    → leave as vN
```

After building the table, do a single global substitution pass. Replace every
occurrence of `vN` with its new name, including inside expressions and
across all functions.

**Important:** `loc_26` in a function body is the function's first local slot.
Apply the same decision tree to it using its usage within that function.

---

### Task 3 — Rename and inline `func_0xHHHH` functions

**How to do it efficiently:**

Process every function definition before touching call sites. For each
`function func_0xHHHH() { ... }`:

**Step A — classify the body:**

```
Body has only 1–2 statements and calls a well-known builtin
  → inline candidate: replace every call site with the body, then delete the function

Body calls security_message / security_hole / security_warning
  → rename to report_<target>  (e.g. report_vuln, report_finding)
    keep as function if called from >1 place, else inline

Body calls get_kb_item + isnull check + exit
  → rename to kb_require_<key_suffix>  (e.g. kb_require_version)

Body calls set_kb_item for multiple keys
  → rename to register_<subject>  (e.g. register_install)

Body calls ssh / sshlib functions
  → rename to ssh_<verb>  (e.g. ssh_run_cmd, ssh_connect)

Body is a data-building loop (string += ..., report += ...)
  → rename to build_<thing>  (e.g. build_report)

Body contains ereg / eregmatch on a version string
  → rename to check_version or parse_version

Body calls exit(0) or exit(1) directly
  → rename to exit_if_<condition>  (e.g. exit_if_not_affected)

Body purpose unclear after reading
  → leave as func_0xHHHH but add a # Purpose: ... comment above it
```

**Step B — update call sites:**

For inlined functions: substitute the body at every call site, adjusting
argument names. For renamed functions: do a global find-and-replace of the
`func_0xHHHH` token.

---

### Task 4 — Resolve unresolved cross-plugin calls

These appear as `func_0xHHHH(named_arg:"...", ...)` where the function is NOT
defined anywhere in the current file — it comes from a loaded .nbin library.

**Algorithm — use named args as the primary signal:**

```
Named arg keys reveal the function name or its purpose:

  func_0xXXXX(attribute:"synopsis", value:"...")
    → script_set_attribute(attribute:"synopsis", value:"...")
      (any call with attribute: + value: is script_set_attribute)

  func_0xXXXX(name:"Host/App/version", value:ver)
    → set_kb_item(name:"Host/App/version", value:ver)
      (name: + value: pattern with a KB-path string is set_kb_item)

  func_0xXXXX("Host/App/version")     (single positional string arg, KB-path form)
    → get_kb_item("Host/App/version")

  func_0xXXXX(port:p, data:report)
    → security_message(port:p, data:report)  or  log_message(port:p, data:report)
      distinguish: if called after a vuln condition → security_message
                   if informational → log_message

  func_0xXXXX(cmd:str, session:sess)
    → sshlib::run_command(cmd:str, session:sess)  (or similar sshlib call)

  func_0xXXXX(string:str, pattern:"regex")
    → ereg(string:str, pattern:"regex")  or  eregmatch(...)

  func_0xXXXX(ver:v, fix:"1.2.3")
    → ver_compare(ver:v, fix:"1.2.3")  or  vcf::check_version(...)

  func_0xXXXX()   called with no args, return value used as port
    → get_kb_item("Services/www")  or similar port-fetching call

  func_0xXXXX(port:p)  return value used as a socket
    → open_sock_tcp(p)

  No named args, single arg, return value used in ereg/eregmatch
    → get_kb_item(...)

  No named args, result compared to NULL then exit
    → get_kb_item_or_exit(...)  (or inline as: x = get_kb_item(...); if (isnull(x)) exit(0);)
```

If the call still cannot be identified after checking named args and return-value
usage, emit it as-is but add a `# ? unresolved cross-plugin call` comment.

---

### Task 5 — Strip the preamble

The preamble is the block of code from the top of `// === MAIN CODE ===` up to
(but not including) `if (v0 != 0) {`. It consists entirely of:

- Variable slot initializations: `v4 = 0; v5 = 1; v6 = "some_string";`
- Object instantiations for shared libraries: `v42 = new sshlib::session();`
- These are injected by the compiler from all `include("*.inc")` directives.
  They are **not** plugin-specific logic.

**Rule:** Delete the preamble entirely. Do not emit any of it.

**Exception:** If any variable initialized in the preamble is referenced in the
plugin logic AND the preamble init is the *only* place it is set (no later
reassignment), carry the initialization forward as a `local_var` declaration at
the top of the plugin body:

```nasl
# original preamble had: v99 = "Linux Kernel";
local_var os_name;
os_name = "Linux Kernel";
```

This is rare — almost all preamble variables are overwritten in plugin logic.
When in doubt, omit.

---

### Accumulator and flag cleanup (applies across all tasks)

Apply these substitutions mechanically before finalizing output:

| Pattern | Replace with |
|---------|-------------|
| `__acc__` immediately after a CALL | the variable the next MOV assigns it to |
| `vN = __acc__;` after a CALL | `vN = <function_call>(...)` (merge the two lines) |
| `if (__flag__) {` | `if (<last_comparison_expression>) {` |
| `if (!__flag__) {` | `if (!(<last_comparison_expression>)) {` |
| `__ret__` | the variable name it is assigned to, or `result` |
| `// slot: vN=val` comments before a CALL | merge into the call as named arg: `vN:val` → remove comment |
| `if (__flag__) { // JZ → [N] }` with empty body | remove entirely |
| `while (1 != 0) { ... }` containing only a single `break` path | flatten or rewrite as `do { ... } while(FALSE)` |

---

### Control flow cleanup (applies across all tasks)

| Pattern | Rewrite |
|---------|---------|
| `while (__acc__ < __acc__)` | remove (decompiler artifact, never executes) |
| Deeply nested `if` chain testing the same variable against many string literals | rewrite as `if (x == "a" \|\| x == "b" \|\| ...)` or a list check |
| `if (isnull(x)) { exit(0); }` immediately after `x = get_kb_item(...)` | `x = get_kb_item_or_exit(...);` |
| `if (cond) { ... } else { }` (empty else) | remove the else branch |
| `for (vN = 0; vN < max_index(list); vN++)` with `vM = list[vN]` as first body line | `foreach vM (list)` |

---

### Output format

```nasl
##
# <filename>.nasl
# <one-line description of what the plugin detects or does>
##

if (description) {
  script_id(NNNNN);
  script_version("YYYY/MM/DD");
  script_name("...");
  script_cve_id("CVE-XXXX-YYYY");       # omit if none
  script_tag(name:"synopsis",     value:"...");
  script_tag(name:"description",  value:"...");
  script_tag(name:"solution",     value:"...");
  script_tag(name:"see_also",     value:"...");
  script_tag(name:"cvss_base",    value:"X.X");
  script_tag(name:"cvss_base_vector", value:"CVSS2#...");
  script_tag(name:"plugin_publication_date", value:"YYYY/MM/DD");
  script_category(ACT_GATHER_INFO);
  script_family("...");
  script_copyright("...");
  script_dependencies("dep1.nasl", "dep2.nasl");
  script_require_keys("Host/...");
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
