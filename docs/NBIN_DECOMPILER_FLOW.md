# Nessus nbin → NASL: Complete Reverse Engineering Flow

Everything needed to go from a raw `.nbin` binary to readable NASL source code —
no Ghidra required for routine use.

---

## 1. What is a .nbin file?

Nessus ships plugins as `.nbin` (compiled NASL) instead of plain `.nasl` text.
They live at `/opt/nessus/lib/nessus/plugins/*.nbin`.

Content is **not encrypted** — only signed (RSA-4096) and zlib-compressed.
The signing key is at `/opt/nessus/var/nessus/nessus_org.pem`.

---

## 2. File Format

```
[4 bytes BE: uncompressed_size]
[zlib-compressed payload]
```

After zlib decompression, the payload is a stream of **TLV records**:

```
[type: 4 bytes BE][length: 4 bytes BE][data: length bytes]
```

### TLV record types

| Type | Name | Contents |
|------|------|----------|
| 0x01 | Symbol table A | String constants + variable names used in bytecode |
| 0x02 | Symbol table B | Metadata strings, preference keys |
| 0x04 | Code header | 12-byte copy of first FUNC_INIT instruction |
| 0x05 | File header | ABI version [0], hash [4], timestamps [8][12], flags |
| 0x06 | Include list | Names of `.inc` files included by this plugin |
| 0x07 | Signature B | RSA-4096 signature (second copy) |
| 0x0b | Plugin metadata | Name, family, description strings |
| 0x0c | Function table | User-defined function names, parameter lists, bytecode offsets |
| 0x0f | **Bytecode** | Flat array of 12-byte instructions |
| 0x10 | Script metadata | OID, version, family |
| 0x1a | Signature A | RSA-4096 signature (first copy) |

**The bytecode is entirely in TLV 0x0f.**  
TLV 0x0c and 0x06 were false leads — they are metadata only.

### Symbol table entry format

```
[4 bytes BE: key][2 bytes BE: value_type][4 bytes BE: data_len][data_len bytes: UTF-8 string]
```

- `key` = integer used by KEY/INT_KEY addressing modes in bytecode instructions
- `value_type` = NaslValue type (0x10 = STRING_SHORT, 0x11 = STRING_HEAP, etc.)
- String content = variable name OR string literal

There are two symbol tables (TLV 0x01 and 0x02); both are read and merged.
Symbol lookup: `sym[key]` → string.

---

## 3. Instruction Format

Every instruction is exactly **12 bytes**, big-endian:

```
Byte  0    : opcode
Byte  1    : src_mode   (addressing mode for source operand)
Byte  2    : dst_mode   (addressing mode for destination operand)
Byte  3    : flags      (0x20 = normal, 0x22 = special assignment variant)
Bytes 4-7  : src_op     (32-bit signed integer, big-endian)
Bytes 8-11 : dst_op     (32-bit signed integer, big-endian)
```

### Addressing modes

| Mode | Name | Meaning |
|------|------|---------|
| 0x00 | NULL | No operand / null value |
| 0x03 | INT | Inline signed integer literal |
| 0x08 | INT_HASH | Integer (used for function IDs and jump offsets) |
| 0x0c | FREF | Function reference |
| 0x14 | STACK | Stack top (push/pop) |
| 0x16 | REG | Named register (REG[0x1a]=temp acc, REG[0x1f]=return value) |
| 0x17 | KEY | Symbol table lookup by key → string name |
| 0x18 | INT_KEY | Symbol table lookup by key → string name (integer variant) |
| 0x19 | DEREF | Variable slot → `v[N]` |
| 0x1a | THIS | 'this' object context |
| 0x1b | SELF | 'self' register |

**High-bit flags** on mode byte: bits 7:5 = 0xc0 marks description-block variant.
Strip with `mode & 0x1f` to get the base mode.

---

## 4. VM Execution Model

### Execution direction

The VM executes **from the END of the instruction array toward the beginning**
(PC decrements by 1 each cycle, i.e., each instruction is 12 bytes but the PC
is an instruction index, not a byte offset).

Instruction array layout in memory:

```
index [n-1]  ← FUNC_INIT (entry point; executed first)
index [n-2]  ← entry JNZ (skips over function bodies to main code)
  ...
index [M]    ← start of main code
  ...
index [k]    ← FRAME_END (end of last function body)
  ...
index [1]    ← start of first function body
index [0]    ← FRAME_END (marks end of function block group; never executed directly)
```

**In the nbin file**, instructions are stored in that same order — index 0 is
the **start of the file's bytecode section**, which corresponds to the
**last instruction executed last** (FRAME_END of the last function).

The decompiler reverses the array so index 0 = first executed.

### Jump formula

For JZ / JNZ / CJMP with `src_op = N`:

```
target_index = total_instructions - N - 1
```

- Positive N → forward jump (skip ahead)
- Negative N → backward jump (loop back)

The entry `JNZ` at index [n-2] with N = number_of_function_instructions
lands at the first main-code instruction.

### Accumulator and flags

- `__acc__` = the accumulator register (REG[0x1a] or REG[0x1f] depending on context)
- `__ret__` = return value register (REG[0x1f])
- `__flag__` = condition flag set by CMP_* instructions and CALL results

CALL sets `__flag__` based on return value truthiness (non-NULL/non-zero = true).

### Variable slots

Slots 0–3 are reserved by the VM. User-defined variables start at slot 4
and are referenced as `v4`, `v5`, ... `vN` in decompiler output when the
name cannot be resolved from the symbol table.

---

## 5. Opcode Reference (all 56 opcodes)

### Data movement

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| 0x01 | MOV | `dst = src` — note: src field = destination, dst field = source (reversed!) |
| 0x0a | POP | Pop local var from stack into dst |
| 0x2e | GETVAR | Get variable by name into dst |
| 0x1f | LOAD_ACC | Load accumulator from addressing mode |

### Arithmetic

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| 0x02 | ADD | `dst += src` (int add or string concat) |
| 0x13 | SUB | `dst -= src` (int sub or string substr) |
| 0x14 | MUL | `dst *= src` |
| 0x15 | DIV | `dst /= src` |
| 0x16 | MOD | `dst %= src` |
| 0x17 | POW | `dst **= src` |
| 0x29 | NEG | `dst = -src` |
| 0x22 | LOAD_INC | `dst = src + 1` (compile-time optimization for `x + 1`) |
| 0x2f | INCR | `dst += n` |
| 0x37 | DECR | `dst -= n` |

### Bitwise

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| 0x0f | AND | `dst &= src` |
| 0x10 | OR | `dst \|= src` |
| 0x11 | XOR | `dst ^= src` |
| 0x12 | NOT | `dst = ~src` |
| 0x18 | SHL | `dst <<= (src & 0x1f)` |
| 0x19 | SHR | `dst >>= (src & 0x1f)` |
| 0x1a | SHR2 | `dst >>= (src & 0x1f)` (variant) |

### Comparison (all set `__flag__`)

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| 0x03 | CMP_EQ | `flag = (src == dst)` |
| 0x2b | CMP_NE | `flag = (src != dst)` |
| 0x0b | CMP_LT | `flag = (src < dst)` |
| 0x0c | CMP_LE | `flag = (src <= dst)` |
| 0x0d | CMP_GT | `flag = (src > dst)` |
| 0x0e | CMP_GE | `flag = (src >= dst)` |
| 0x24 | NOT | `flag = !flag` (logical NOT) |
| 0x35 | CMP_REG | Compare with register |
| 0x36 | CMP_REG2 | Compare with register (variant) |

### Control flow

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| 0x04 | JZ | `if flag == 0: jump` (skip true-branch when condition is false) |
| 0x05 | JNZ | `if flag != 0: jump` (loop back-edge, else-skip, entry NOP) |
| 0x06 | CJMP | `if flag != 0: jump` (logical OR short-circuit) |
| 0x00 | NOP | No operation |

### Function calls

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| 0x07 | CALL | Call function. `src_op` = function ID or `0xf0000000\|builtin_idx` |
| 0x08 | RET | Return from function. Return value in REG[0x1a] or DEREF(var) |
| 0x09 | SETVAR | Set argument count N for next CALL (emitted for even N only) |
| 0x2c | FUNC_INIT | Function/script block init — always first in TLV 0x0f |
| 0x33 | FRAME_END | End of function frame — delimits function boundaries |
| 0x30 | PUSH_ARG | Push positional function argument |
| 0x31 | SET_NAMED | Set named parameter |
| 0x32 | SLOT | Function argument slot (see §6) |

### Arrays and objects

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| 0x1b | LOAD_KEY | `dst = src[string_key]` |
| 0x1c | STORE_KEY | `src[string_key] = dst` |
| 0x1d | LOAD_IDX | `dst = src[int_index]` |
| 0x1e | STORE_IDX | `src[int_index] = dst` |
| 0x20 | PUSH_SCOPE | Push scope / read array element |
| 0x21 | NEW_OBJ | Write array element / new object |

### Iteration

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| 0x2d | FOREACH | Set up foreach iterator |
| 0x34 | ITER_NEXT | Advance iterator |

### Strings and misc

| Opcode | Mnemonic | Semantics |
|--------|----------|-----------|
| 0x22 | CONCAT | String concatenation (type-aware) |
| 0x23 | CONCAT2 | Concatenation variant |
| 0x25 | INCLUDE | Script include / namespace |
| 0x26 | THROW | Throw exception |
| 0x27 | TRY | Set exception handler |
| 0x28 | CATCH | Catch exception |
| 0x2a | TYPECHECK | typeof |

---

## 6. SLOT Encoding (Named Arguments)

SLOT (0x32) is the most-used opcode (21.3% of all instructions in the corpus).
It pushes one argument onto the call stack for the next CALL.

```
SLOT  src=<value>  dst=<name_or_count>
```

**The dst field encodes whether this is a named or positional argument:**

| dst_mode | Meaning |
|----------|---------|
| 0x17 KEY | **Named arg**: dst_op is a symbol table key → resolves to arg name string |
| 0x18 INT_KEY | **Named arg**: same as KEY (integer-keyed variant) |
| 0x19 DEREF | **Dynamic named arg**: a variable holds the name at runtime — name is NOT statically recoverable |
| 0x03 INT | **ODD-count marker**: dst value = total arg count. Used when arg count is odd (replaces a SETVAR) |
| 0x00 NULL | **Positional**: no name |
| 0x14 STACK | **Positional**: stack reference |

**Only `dst_mode=0x17` and `dst_mode=0x18` mean the argument has a statically known name.**
DEREF (0x19) is a variable holding the name — do NOT treat the variable name as the arg name.

### Named-arg call pattern

```
SLOT  src=INT(3)  dst=KEY("a")      # named arg a=3
SLOT  src=INT(4)  dst=KEY("b")      # named arg b=4
SETVAR(4)                            # 2 named args × 2 = 4 tokens
CALL  add
```

NASL output: `add(a:3, b:4)`

SETVAR(N) where N = 2 × number_of_named_args. For odd total arg count,
SETVAR is omitted and the count goes in the last SLOT's dst field instead.

### Post-CALL fast-path

The instruction immediately after CALL is executed inline (no return to
dispatch loop). In GDB this instruction is invisible, but it IS in the
bytecode. It is always a CMP for the condition of the next `if` statement.

---

## 7. Function Structure

### Function boundaries in TLV 0x0f

```
[FRAME_END]              ← index 0, never executed, sentinel
[function body N]
[FRAME_END]
...
[function body 1]
[FRAME_END]              ← last FRAME_END before main code
[main code body]
[FUNC_INIT]              ← index (n-1), executed FIRST
```

The decompiler reverses this: after reversing, FUNC_INIT is at [0],
main code follows, then function bodies.

The entry JNZ at [1] (after reversal) has `src_op = M` where M = total
instructions in all function bodies. It jumps forward past the function
bodies to the main code.

### User-defined function IDs

In CALL instructions, user function targets are small integers — the
instruction index of the function's FRAME_END in the original (unreversed)
array. The decompiler resolves these to `func_0x<hex>` labels.

### Builtin function IDs

```
0xf0000000 | builtin_index
```

Example: `CALL 0xf00000e5` = call builtin 0xe5.

### Known builtin opcode → name map (partial)

| Builtin index | NASL function |
|--------------|---------------|
| 0xe4 | `set_kb_item` |
| 0xe5 | `get_kb_item` |
| 0xc3 | `string` (intern/concat) |
| 0x128 | `script_set_attribute` |
| 0x1a0 | `isnull` |
| 0xcf | `max_index` |
| 0x1ff | `make_list` / `make_array` |
| 0x133 | `log_message` |
| 0x13a | `security_message` |
| 0x3 | `exit` |

Any builtin not in the map appears as `builtin_0xNNN` in decompiler output.

---

## 8. Decompiler Pipeline (nasl_decompiler.py)

### Step 1 — Parse file

```
.nbin  →  zlib decompress  →  TLV record stream
```

Extract:
- TLV 0x01 + 0x02 → symbol table dict `{key: string}`
- TLV 0x0f → raw bytecode bytes

### Step 2 — Decode instructions

Split bytecode into 12-byte chunks. For each chunk:

```python
opcode   = data[0]
src_mode = data[1]
dst_mode = data[2]
flags    = data[3]
src_op   = struct.unpack('>i', data[4:8])[0]   # signed BE
dst_op   = struct.unpack('>i', data[8:12])[0]  # signed BE
```

**Reverse the array** so index 0 = FUNC_INIT (first executed).

### Step 3 — Resolve operands

For each instruction, `fmt_operand(mode, op)` produces a string:

| mode | output |
|------|--------|
| 0x03 INT | `str(op)` |
| 0x17 KEY | `sym[op]` (string from symbol table) |
| 0x18 INT_KEY | `sym[op]` (string from symbol table) |
| 0x19 DEREF | `v{op}` (variable slot reference) |
| 0x00 NULL | `"NULL"` |
| 0x08 INT_HASH | `hex(op)` |
| 0x16 REG | `f"REG[{op:#x}]"` |

### Step 4 — Identify function boundaries

Walk the reversed instruction array looking for the entry JNZ.
`src_op` of the entry JNZ = M = total function-body instructions.
Everything from index 2 through 2+M-1 is function bodies.
Everything after 2+M is main code.

Build a map: `{frame_end_index: func_label}` for each FRAME_END in [2..2+M-1].
Each function body ends at a FRAME_END and starts after the previous FRAME_END (or at index 2).

### Step 5 — Resolve function call targets

For each `CALL src_op=T`:
- If `T & 0xf0000000 == 0xf0000000`: builtin, look up in builtin table → name or `builtin_0x{T & 0xfffffff:x}`
- Else: user function, look up in frame_end map → `func_0x{T:x}`

### Step 6 — Reconstruct control flow

Walk instructions in order, maintaining an indent level and a jump target stack.

**JZ (0x04)** — if-statement opener:
```
target = n_insns - src_op - 1
emit: "if (__flag__) {"    (or equivalent condition if CMP preceded it)
push_close_at(target)
indent++
```

**JNZ (0x05)**:
- At end of a true-branch with a pending close: emits `} else {` (if/else)
- At end of a loop body: emits `}` and closes the while
- Entry jump: skip past it

**CJMP (0x06)** — logical OR:
```
emit: "if (__flag__) {  // CJMP → [target]"
```

**FRAME_END (0x33)**:
```
emit: "}"    (close function body)
```

### Step 7 — Reconstruct function calls

Accumulate `pending_slots` list as SLOT instructions are seen.
When a CALL is reached, flush pending_slots as arguments:

```python
for (val, name, is_named) in pending_slots:
    if is_named:   # dst_mode was 0x17 or 0x18 only
        args.append(f"{name}:{val}")
    else:
        args.append(val)

emit: f"{func_name}({', '.join(args)})"
```

### Step 8 — Emit

The final output is NASL pseudocode with:
- Real variable names where the symbol table has them
- `vN` for any variable slot without a name
- `func_0xHHHH` for user functions (hash = FRAME_END index in original array)
- `builtin_0xNNN` for unresolved builtins
- Proper `if / while / foreach / function / return` structure
- Named and positional arguments

---

## 9. Reading the Decompiler Output

### Output structure

```nasl
// === MAIN CODE ===
<shared library preamble>        // global_settings init, v4=0, v5=1, ...
if (v0 != 0) {                   // description block guard
  script_id(NNNNN);
  ...
  exit(0);
}
<plugin-specific logic>          // actual detection code

function func_0xHHHH() { ... }  // helper functions
...
```

The preamble is included library code inlined into every plugin.
The interesting plugin logic starts after `exit(0)` in the description block.

### Common patterns

| Pattern | NASL meaning |
|---------|-------------|
| `func_0xa51(name:val)` | `script_tag(name:"...", value:"...")` |
| `func_0x773(CVSS2#...)` | `script_tag` CVSS vector |
| `func_0x784(key)` | `get_kb_item_or_exit(key)` |
| `builtin_0xe5(key)` | `get_kb_item(key)` |
| `builtin_0xe4(key:val)` | `set_kb_item(name:key, value:val)` |
| `builtin_0xc3(str)` | `string(str)` (intern/concat) |
| `builtin_0x13a(port, data)` | `security_message(port:port, data:data)` |
| `builtin_0x133(data:x, lvl:1)` | `log_message(data:x)` |
| `builtin_0x3(0)` | `exit(0)` |
| `builtin_0x1ff(a, b, ...)` | `make_list(a, b, ...)` |
| `builtin_0x1a0(x)` | `isnull(x)` |
| `builtin_0xcf(x)` | `max_index(x)` |
| `display(sep:x, 0)` | `split(str, sep:x, keep:FALSE)` |

### Known limitations

1. **`builtin_0xNNN`** for builtins not yet in the map — context usually makes them obvious.
2. **DEREF dynamic named args** — when arg name is in a variable (0x19 dst_mode), the name is not recoverable statically and will appear as a positional arg.
3. **Control flow artifacts** — deeply nested JZ/JNZ chains sometimes produce more indentation than the original source had (the compiler flattens some patterns).
4. **`__acc__` / `__flag__`** — these are VM internals that are explicit in the decompiler output but implicit in source. They correspond to the value of the last expression or CALL result.

---

## 10. End-to-End Example

**Input**: `/opt/nessus/lib/nessus/plugins/blackberry_qualcomm_bypass_check.nbin`

**Step 1** — decompress, parse TLVs, extract 318 symbol table entries + 3747 instructions.

**Step 2** — reverse instruction array. Entry JNZ `src=M` tells us M function-body instructions.

**Step 3** — walk instructions. See FUNC_INIT, entry JNZ, then main code with deep if-nesting (global_settings preamble), then `script_id(81210)`, `script_name(...)`, `exit(0)`, then plugin logic.

**Step 4** — plugin logic: checks `mdm/blackberry/check/qualcomm_bp_check` KB key (dedup), queries MDM scratchpad for enrolled BlackBerry devices, for each device matches model string against a Qualcomm-model list (bold/curve/pearl/storm/torch families), splits OS version on `.`, reports vulnerable if major < 7 OR (major == 7 AND minor <= 1).

**Step 5** — function bodies: `func_0xa51` = `script_tag()` wrapper, `func_0x784` = `get_kb_item_or_exit()`, `func_0x773` = CVSS scorer, `func_0x210` = MDM device list query, `func_0x274` = `security_message()` reporter.

**Output**: 2691 lines of NASL pseudocode. The interesting plugin-specific logic begins around line 614 (after `exit(0)` in the description block).

---

## 11. Tools

### Installed CLI commands

| Command | Purpose |
|---------|---------|
| `nbin-disasm` | Raw disassembly + logic pseudocode (`--raw --functions`) |
| `nbin-decompile` | Logic pseudocode output |
| `nbin-vm` | Low-level VM parser: symbol table, opcode stats, raw disasm |
| `nbin-analyze` | Opcode frequency analysis across a directory of `.nbin` files |

### Python API modules

| Module | Purpose |
|--------|---------|
| `nbin_tools.nasl_decompiler` | Main decompiler: `.nbin` → NASL pseudocode |
| `nbin_tools.nasl_vm` | Low-level parser: TLV parsing, instruction decoding, symbol table |
| `nbin_tools.analyze_opcodes` | Batch opcode analysis |

### Quick usage

```bash
# Install
pip install nbin-tools

# Decompile a single plugin
nbin-decompile /path/to/plugin.nbin

# Raw disassembly + pseudocode side by side
nbin-disasm /path/to/plugin.nbin

# Show only plugin-specific logic (skip preamble)
nbin-decompile /path/to/plugin.nbin | sed -n '/exit(0)/,$p'

# Batch decompile
for f in /path/to/plugins/*.nbin; do
  echo "=== $f ==="; nbin-decompile "$f" 2>/dev/null | grep -c "func_0x\|CALL"
done

# Opcode frequency analysis across a plugin directory
nbin-analyze --dir /path/to/plugins/ --out analysis.json
```

---

## 12. What Ghidra Was Used For (historical)

Ghidra was used **once** to bootstrap the reverse engineering. Everything
derived from that work is now baked into the decompiler. You do not need
Ghidra for routine `.nbin` analysis.

| Ghidra task | Status |
|-------------|--------|
| Discover 12-byte instruction format | Done — in nasl_vm.py |
| Map all 56 opcode semantics | Done — in NASL_INSTRUCTION_SET.md |
| Understand addressing modes (KEY/DEREF/STACK) | Done — in nasl_vm.py |
| Confirm SLOT named-arg disk format (KEY vs DEREF) | Done — in decompiler |
| Locate VM dispatch loop (FUN_0026b180) | Reference only |
| Map `builtin_0xNNN` → function names | **Partial** — 10 known, ~300 total |

If you want to resolve more `builtin_0xNNN` entries, that is the one task that
still requires Ghidra: look up address `FUN_0026b180` in `/opt/nessus/bin/nasl`,
find the builtin dispatch table, and read off the names.
