# NASL VM Instruction Set Reference

Derived from GDB live execution traces + Ghidra static analysis of `/opt/nessus/bin/nasl`.

> **Note**: This document covers two distinct contexts:
> - **Runtime (`.nasl` source)**: instructions observed in GDB while `/opt/nessus/bin/nasl` interprets `.nasl` source files. Operands are stored **little-endian** in memory. Jump targets are **relative** (`new_r13 = old_r13 - N*12`).
> - **nbin files**: precompiled bytecode from `/opt/nessus/lib/nessus/plugins/*.nbin`. Operands are stored **big-endian** in the file. Jump targets are **absolute from end** (`target_index = n_insns - src_op - 1`). Addressing modes may differ slightly.
> Most opcode semantics apply to both contexts. Differences are noted where relevant.

---

## Architecture Overview

### Instruction Format

Every instruction is **12 bytes**:

```
Offset  Size  Field
  0       1   opcode
  1       1   src_mode   (addressing mode for source/LHS operand)
  2       1   dst_mode   (addressing mode for destination/RHS operand)
  3       1   flags      (0x20 = normal, 0x22 = special assignment variant)
  4       4   src_op     (source operand, stored little-endian in file)
  8       4   dst_op     (destination operand, stored little-endian in file)
```

**Operand encoding in file**: 4-byte LE integers. For example, the integer value 4 is stored as bytes `04 00 00 00`.

### Execution Model

- The VM executes instructions **from HIGH address to LOW address** (PC decrements by 12 each cycle).
- The **entry instruction** is at index 0 (highest address): a `JNZ` that skips over function bodies.
  - For scripts with **no user-defined functions**: `JNZ src=1` (skips 1 instruction — effectively a NOP).
  - For scripts with functions: `JNZ src=M` where M = total number of function body instructions.
- **Variable slots**: 0–3 are reserved; user-defined variables start at slot 4.
- **`FUNC_INIT`** is always the last instruction (lowest address, index n-1). It marks the script termination.

### Jump Formula

For `JZ`/`JNZ`/`CJMP` with `src_op = N` (signed int32):

```
new_r13 = old_r13 - N * 12
```

- **Positive N**: jump FORWARD (to lower addresses = later in array, skipping instructions).
- **Negative N**: jump BACKWARD (to higher addresses = earlier in array, back to loop top).
- The entry `JNZ src=M` with M=number_of_function_instructions lands at the first main-code instruction.

**Example**: entry at index [0], `JNZ src=6` → lands at index [6] (main code starts there, function bodies were at [1]..[5]).

---

## Post-CALL Fast-Path (Critical!)

The NASL VM's **CALL opcode handler executes the immediately-following instruction inline** — it does NOT re-enter the main dispatch loop for the next instruction after a CALL returns. This means:

- Instruction immediately after CALL is dispatched via a **fast-path** (no breakpoint hit at the dispatch loop top).
- This instruction is always a **CMP** (comparison) for the condition of the *next* `if`-statement.
- The decompiler sees this instruction in the raw bytecode normally — only GDB traces miss it.

**Pattern for consecutive `if` statements:**
```
CMP_cond1 → JZ(skip1) → SLOT args → CALL → [CMP_cond2 via fast-path] → JZ(skip2) → ...
```

---

## Addressing Modes

| Mode | Name       | Operand Meaning                                              |
|------|------------|--------------------------------------------------------------|
| 0x00 | NULL       | No operand / NULL value                                      |
| 0x02 | DATA       | Immediate NULL / no value (dm only, dst=0)                   |
| 0x03 | INT        | Integer literal (signed)                                     |
| 0x08 | INT_HASH   | Function ID or jump offset                                   |
| 0x0c | FREF       | Function reference (inline: 0xf0xxxxxxx = builtin)           |
| 0x0d | AELEM      | Accumulator / array element (operand=0 → `__acc__`)          |
| 0x14 | ARG_REF    | Function argument by negative offset (e.g., -2, -3)         |
| 0x16 | REG        | Named register (REG[0x1a] = temp accumulator, REG[0x1f] = return value) |
| 0x18 | INT_KEY    | Symbol table index (string literal → sym[N])                 |
| 0x19 | DEREF      | Variable slot dereference → `v[N]`                           |
| 0x1f | RETVAL     | Return value register (alias for REG[0x1f])                  |

**High-bit modifier flags** (bits 7:5 of mode byte):
- `0xc0` prefix (e.g., 0xcc, 0xcd, 0xce) = description-block variant; strip with `mode & 0x1f` to get base mode.

### Special Registers

| Register  | Purpose                                          |
|-----------|--------------------------------------------------|
| REG[0x1a] | Temporary accumulator for arithmetic expressions |
| REG[0x1f] | Return value of last CALL (also `RETVAL`)        |

---

## Opcode Table

### Data Movement

#### 0x01 — MOV

Copies a value to a destination. **Note: src = destination, dst = source** (counter-intuitive, by design).

```
MOV  DEREF(slot)  INT(val)     →  v[slot] = val
MOV  DEREF(dst)   DEREF(src)   →  v[dst] = v[src]
MOV  DEREF(dst)   REG(r)       →  v[dst] = REG[r]
MOV  REG(r)       DEREF(src)   →  REG[r] = v[src]
MOV  DEREF(dst)   INT_KEY(k)   →  v[dst] = sym[k]
MOV  DEREF(dst)   ARG_REF(-n)  →  v[dst] = arg[-n]
MOV  DEREF(dst)   REG[0x1f]    →  v[dst] = RETVAL  (capture function return value)
```

**NASL patterns:**
```nasl
x = 5;                   → MOV DEREF(4) INT(5)
x = y;                   → MOV DEREF(4) DEREF(5)
x = get_kb_item("key");  → [CALL get_kb_item] → MOV DEREF(4) REG(0x1f)
x = "hello";             → MOV DEREF(4) INT_KEY(0)  // sym[0]="hello"
```

---

### Arithmetic

All arithmetic operates in-place: `v[src] op= operand`.

#### 0x02 — ADD
```
ADD  DEREF(dst)  DEREF(src)  →  v[dst] += v[src]
ADD  DEREF(dst)  INT(val)    →  v[dst] += val
ADD  REG(r)      DEREF(src)  →  REG[r] += v[src]
ADD  DEREF(dst)  INT_KEY(k)  →  v[dst] += sym[k]   // string concatenation!
```

**NASL patterns:**
```nasl
a = x + y;     → MOV DEREF(a) DEREF(x); ADD DEREF(a) DEREF(y)
x += 1;        → ADD DEREF(x) INT(1)
x += y;        → ADD DEREF(x) DEREF(y)
s = s + "str"; → ADD DEREF(s) INT_KEY(str_index)
```

**Note:** For expression `a = x + y`, the compiler:
1. Copies `x` to `a` with MOV
2. Adds `y` to `a` with ADD in-place

#### 0x13 — SUB
```
SUB  DEREF(dst)  DEREF(src)  →  v[dst] -= v[src]
SUB  DEREF(dst)  INT(val)    →  v[dst] -= val
```

#### 0x14 — MUL
```
MUL  DEREF(dst)  DEREF(src)  →  v[dst] *= v[src]
MUL  DEREF(dst)  INT(val)    →  v[dst] *= val
```

#### 0x15 — DIV
```
DIV  DEREF(dst)  DEREF(src)  →  v[dst] /= v[src]
```

#### 0x16 — MOD
```
MOD  DEREF(dst)  DEREF(src)  →  v[dst] %= v[src]
```

#### 0x17 — POW
```
POW  DEREF(dst)  INT(exp)    →  v[dst] **= exp
POW  DEREF(dst)  DEREF(src)  →  v[dst] **= v[src]
```

#### 0x22 — LOAD_INC / INC_CONCAT (dual-purpose increment)

Two distinct usages:

**Usage 1 — Load and add 1** (compiler optimization for `x + 1`):
```
LOAD_INC  REG(0x1a)  ARG_REF(-2)  →  REG[0x1a] = ARG_REF[-2] + 1
LOAD_INC  REG(0x1a)  DEREF(v)     →  REG[0x1a] = v[v] + 1
```
Used when the compiler detects `<expr> + 1` — loads the operand and adds 1 in a single instruction.

**Usage 2 — In-place increment** (`i++`, `v[i]++`):
```
INC_CONCAT  DEREF(var)  DATA(0)   →  v[var]++
```

**NASL patterns:**
```nasl
i++;                 → INC_CONCAT DEREF(i) DATA(0)
function f(x) { return x + 1; }
                     → LOAD_INC REG(0x1a) ARG_REF(-2)
                        RET REG(0x1a)
```

**Note**: For `x + 2` or larger literals, the compiler falls back to `MOV` + `ADD INT(n)` rather than using this opcode.

---

### Bitwise Operations

#### 0x0f — AND (bitwise)
```
AND  DEREF(dst)  DEREF(src)  →  v[dst] &= v[src]
```

#### 0x10 — OR (bitwise)
```
OR   DEREF(dst)  DEREF(src)  →  v[dst] |= v[src]
```

#### 0x11 — XOR (bitwise)
```
XOR  DEREF(dst)  DEREF(src)  →  v[dst] ^= v[src]
```

#### 0x12 — NOT (bitwise complement)
```
NOT  DEREF(dst)  DEREF(src)  →  v[dst] = ~v[src]
```
Note: dst ≠ src is allowed (NOT is not in-place; it's a 2-operand form).

#### 0x18 — SHL (shift left)
```
SHL  DEREF(dst)  INT(n)      →  v[dst] <<= n
```

#### 0x19 — SHR (shift right)
```
SHR  DEREF(dst)  INT(n)      →  v[dst] >>= n
```

---

### Comparison (set flag register)

All comparisons set a VM-internal **condition flag**: 1 (true) or 0 (false).

**Critical**: The condition flag IS modified by certain instructions:
- CMP_* instructions: explicitly set flag to comparison result.
- CALL instruction: sets flag based on the return value's truthiness (non-NULL/non-zero = 1).
- MOV from INT_KEY: sets flag to truthiness of the loaded string.

#### 0x03 — CMP_EQ
```
CMP_EQ  DEREF(lhs)  DEREF(rhs)  →  flag = (v[lhs] == v[rhs])
```

#### 0x2b — CMP_NE
```
CMP_NE  DEREF(lhs)  DEREF(rhs)  →  flag = (v[lhs] != v[rhs])
CMP_NE  DEREF(var)  INT(0)      →  flag = (v[var] != 0)   // truthiness check
```

#### 0x0b — CMP_LT
```
CMP_LT  DEREF(lhs)  DEREF(rhs)   →  flag = (v[lhs] < v[rhs])
CMP_LT  DEREF(var)  INT(val)     →  flag = (v[var] < val)
```

#### 0x0c — CMP_LE
```
CMP_LE  DEREF(lhs)  DEREF(rhs)   →  flag = (v[lhs] <= v[rhs])
CMP_LE  DEREF(var)  INT(val)     →  flag = (v[var] <= val)
```

#### 0x0d — CMP_GT
```
CMP_GT  DEREF(lhs)  DEREF(rhs)   →  flag = (v[lhs] > v[rhs])
CMP_GT  DEREF(lhs)  INT(val)     →  flag = (v[lhs] > val)
```

#### 0x0e — CMP_GE
```
CMP_GE  DEREF(lhs)  DEREF(rhs)   →  flag = (v[lhs] >= v[rhs])
CMP_GE  DEREF(var)  INT(val)     →  flag = (v[var] >= val)
```

---

### Control Flow

#### 0x04 — JZ (Jump if Zero / Jump if False)

```
JZ  INT_HASH(offset)  →  if flag == 0: pc = n_insns - offset - 1
```

Used to skip the **true-branch** of an `if` when condition is false.

#### 0x05 — JNZ (Jump if Non-Zero / Jump if True)

```
JNZ  INT_HASH(offset)  →  if flag != 0: pc = n_insns - offset - 1
```

Used for:
1. **Entry NOP**: `JNZ src=1` at `insn[n-1]` — always jumps to `insn[n-2]`, effectively a NOP that skips itself.
2. **Loop back-edge**: `JNZ src=back_offset` at end of loop body to jump back to condition check.
3. **`if/else` separator**: `JNZ src=offset` at end of true-branch to jump past else-branch.

#### 0x06 — CJMP (Conditional Jump — `||` short-circuit)

```
CJMP  INT_HASH(offset)  →  if flag != 0: pc = n_insns - offset - 1
```

Same semantics as JNZ but used specifically for **logical OR (`||`) short-circuit**:
- If left operand is truthy (flag=1), jump FORWARD to the OR body (skipping evaluation of right operand).

---

### Function Calls

#### 0x07 — CALL

```
CALL  INT_HASH(target)  →  call function
```

`target` is:
- **User-defined function**: small integer = instruction index of the callee's `FRAME_END`. Example: `CALL src=7` → jump to instruction [7].
- **Builtin function**: `0xf0000000 | builtin_index`. Example: `CALL src=0xf0000047` → call `display` (builtin 0x47).

After return, `REG[0x1f]` holds the return value. The caller captures it with `MOV DEREF(result_slot) REG(0x1f)`.

**Important**: The instruction immediately following CALL is executed via the **post-CALL fast-path** — not through the main dispatch loop. This makes it invisible to GDB breakpoints but present in bytecode.

#### 0x08 — RET (Return)

```
RET  REG(0x1a)         →  return REG[0x1a]      (arithmetic result)
RET  DEREF(var)        →  return v[var]          (variable)
```

The return value is placed in REG[0x1a] (for arithmetic results) or directly from a variable slot, then returned to the caller via REG[0x1f].

#### 0x09 — SETVAR (Set Argument Count)

```
SETVAR  INT(n)  →  set the argument count for the next CALL to n
```

Emitted only for **even** argument counts. For odd argument counts, the count is embedded directly in the last SLOT instruction's `dst` field (see SLOT below).

```nasl
display(a, b, c, d);   // 4 args (even)
→ SLOT d c; SLOT b a; SETVAR(4); CALL display
```

#### 0x32 — SLOT (Push Argument)

Pushes one argument onto the call argument stack. Each SLOT encodes a `(value, name)` pair:

```
SLOT  src=value  dst=arg_name_or_count
```

**Named-arg encoding** (nbin disk format): `dst` holds the **argument name** as a symbol-table index:

| dst mode | Meaning |
|----------|---------|
| 0x17 KEY | Static named arg: `dst_op` is a symtable index → string name |
| 0x18 INT_KEY | Static named arg: `dst_op` is a symtable index → string name |
| 0x19 DEREF | Dynamic named arg: `dst_op` is a variable slot holding the name at runtime |
| 0x03 INT | ODD-count marker: dst value = total arg count (not a real name) |
| 0x00 NULL | Positional / placeholder (no name) |
| 0x14 STACK | Positional (stack reference) |

Only `dst_mode=0x17` and `dst_mode=0x18` encode a **statically known** named-arg key. All other dst modes are positional or metadata.

**Named-arg call** (one SLOT per arg, KEY/INT_KEY in dst):
```
SLOT  src=val_of_arg1  dst=KEY("a")     ← named arg a=val1
SLOT  src=val_of_arg2  dst=KEY("b")     ← named arg b=val2
SETVAR(4)                               ← 2 named args × 2 = 4 total slots
CALL  target
```

**1-arg call** (ODD count=1, no SETVAR):
```
SLOT  src=val  dst=INT(1)     ← sole arg + count in dst
CALL  target
```

**ODD-arg call** (K≥3 args, no SETVAR):
```
SLOT  src=arg[K-1]  dst=KEY("param_K")    ← last named arg
...
SLOT  src=arg[1]    dst=KEY("param_2")
SLOT  src=arg[0]    dst=INT(K)            ← first arg + count in dst
CALL  target
```

> **Note on SETVAR count**: `SETVAR(N)` where N = 2 × (number of named args). The VM counts both the name and value tokens for each named arg. ODD-count calls embed the count in the last SLOT's dst instead of using SETVAR.

**Example forms:**
```
SLOT  DEREF(v)     KEY(k)      → variable value, static arg name sym[k]
SLOT  INT(n)       KEY(k)      → integer literal value, static arg name
SLOT  INT_KEY(k)   INT(m)      → string literal (sym[k]) value, ODD count m
SLOT  DEREF(v)     INT(1)      → variable value, ODD count=1
SLOT  REG(0x1f)    KEY(k)      → return value, static arg name
SLOT  STACK        KEY(k)      → stack top value, static arg name
SLOT  NULL         NULL        → positional arg placeholder (see positional calling)
SLOT  DEREF(v1)    DEREF(v2)   → value from v1, dynamic arg name from v2 (runtime)
```

#### 0x33 — FRAME_END (Function Frame Start Marker)

```
FRAME_END  INT(4)  →  function entry point / frame setup marker
```

The **first instruction of every user-defined function body** in the instruction array. Its raw LE src operand is always `4` (constant, not byteswapped). The VM uses FRAME_END locations to build its function lookup table at load time.

**Layout**: For a script with N function body instructions, the instruction array is:
```
[0]         JNZ src=N          ← entry: skip over all function bodies
[1..X]      ... function 1 body ...   (starts with FRAME_END)
[X+1..Y]    ... function 2 body ...   (starts with FRAME_END)
...
[N+1..]     ... main script code ...
[n-1]       FUNC_INIT          ← termination marker
```

**CALL target = instruction index** of the callee's FRAME_END. For `CALL src=7`, execution jumps to instruction [7].

**Note**: FRAME_END operands use native LE encoding (raw bytes `00 00 00 04` = value 4). Do NOT apply the byteswap that other instructions require.

#### 0x2c — FUNC_INIT (Function Initializer / End Marker)

```
FUNC_INIT  (no meaningful operands)
```

Always at instruction index 0 (lowest address). Marks the function start/end in the static layout. When execution reaches this, the function returns normally.

---

### Array / Hash Operations

#### 0x1f — LOAD_KEY (Load Array Key)

```
LOAD_KEY  INT_KEY(k)    →  set internal key register = sym[k]  (string key)
LOAD_KEY  INT(n)        →  set internal key register = n       (integer index)
```

Must precede SETELEM or GETELEM. Sets the key for the next array operation.

**NASL patterns:**
```nasl
arr["key1"] = 42;  → LOAD_KEY INT_KEY(0); SETELEM DEREF(arr) INT(42)
arr[0] = "x";     → LOAD_KEY INT(0);     SETELEM DEREF(arr) INT_KEY(str_idx)
```

#### 0x21 — SETELEM (Set Array Element)

```
SETELEM  DEREF(arr)  INT(val)      →  v[arr][current_key] = val
SETELEM  DEREF(arr)  INT_KEY(k)    →  v[arr][current_key] = sym[k]
SETELEM  DEREF(arr)  DEREF(src)    →  v[arr][current_key] = v[src]
```

Uses the key loaded by the most recent LOAD_KEY.

#### 0x20 — GETELEM (Get Array Element)

```
GETELEM  DEREF(dst)  DEREF(arr)    →  v[dst] = v[arr][current_key]
```

---

### Iterator / `foreach` Operations

#### 0x25 — ITER_INIT

```
ITER_INIT  DEREF(arr)  →  initialize iterator over v[arr]; push iterator state
```

Sets up a foreach iteration over the list/hash stored in `v[arr]`.

#### 0x28 — ITER_NEXT

```
ITER_NEXT  DEREF(arr)  INT_HASH(exit_offset)  →
    advance iterator; if exhausted: jump to target = n - exit_offset - 1
    else: set current element ready for ITER_DEREF
```

The `exit_offset` jump target points past the loop body (exit when done).

#### 0x26 — ITER_DEREF

```
ITER_DEREF  DEREF(item)  DEREF(arr)  →  v[item] = current element of v[arr]'s iterator
```

Stores the current iterator element into the loop variable.

#### 0x27 — ITER_END

```
ITER_END  DEREF(arr)  →  cleanup iterator for v[arr]
```

Always immediately follows the last ITER_NEXT (when iterator is exhausted).

**Full `foreach` pattern:**
```nasl
foreach item (lst) { body }

→ ITER_INIT DEREF(lst)
  ITER_NEXT DEREF(lst) INT_HASH(exit_target)   ← loop top
  ITER_DEREF DEREF(item) DEREF(lst)
  ... body ...
  JNZ(loop_top)                                ← jump back to ITER_NEXT
  ITER_END DEREF(lst)                          ← only after ITER_NEXT fails
```

---

## Control Flow Patterns

### `if (cond) body`

```
CMP_*    lhs  rhs                       ← evaluate condition
JZ(skip_to_after)                       ← jump past body if false
  ... body ...
[after]:
```

### `if (cond) body1 else body2`

```
CMP_*    lhs  rhs
JZ(to_else)                             ← jump to else if false
  ... true body ...
JNZ(past_else)                          ← jump past else when done
  ... else body ...
[past_else]:
```

### `if (a && b) body`

```
CMP_NE  DEREF(a)  INT(0)               ← test truthiness of a
JZ(skip_body)                           ← if a is false, skip
CMP_NE  DEREF(b)  INT(0)               ← test truthiness of b
JZ(skip_body)                           ← if b is false, skip
  ... body ...
[skip_body]:
```

### `if (a || b) body`

```
CMP_NE  DEREF(a)  INT(0)               ← test a
CJMP(to_body)                           ← if a is true, jump to body (short-circuit)
CMP_NE  DEREF(b)  INT(0)               ← test b (only if a was false)
JZ(skip_body)                           ← if b is false, skip
[to_body]:
  ... body ...
[skip_body]:
```

### `if (!b) body`

```
CMP_NE  DEREF(b)  INT(0)               ← test b
JNZ(skip_body)                          ← skip if b is truthy (NOT → invert)
  ... body ...
[skip_body]:
```

Note: logical NOT is implemented as `CMP_NE` + `JNZ` (jump if NOT zero = jump if truthy, i.e., skip when condition is true).

### `while (i < N) { body }`

```
[loop_top]:
CMP_LT  DEREF(i)  INT(N)
JZ(exit)                                ← exit when condition false
  ... body ...
JNZ(loop_top)                           ← jump back (flag must be 1 — loop continues)
[exit]:
```

**Note**: `JNZ(loop_top)` always has flag=1 because the last CMP was true (we just executed the body), and JNZ uses the flag as-is without re-evaluating.

### `for (i = start; i <= end; i++) { body }`

```
MOV  DEREF(i)  INT(start)              ← init
[loop_top]:
CMP_LE  DEREF(i)  INT(end)
JZ(exit)
  ... body ...
INC_CONCAT  DEREF(i)  NULL             ← i++
JNZ(loop_top)
[exit]:
```

### `foreach item (lst) { body }`

```
[setup make_list if needed]
ITER_INIT   DEREF(lst)
[loop_top]:
ITER_NEXT   DEREF(lst)  INT_HASH(exit_offset)
ITER_DEREF  DEREF(item)  DEREF(lst)
  ... body ...
JNZ(loop_top)                           ← note: ITER_NEXT sets flag
[exit]:
ITER_END  DEREF(lst)
```

---

## Function Call Convention

### Named vs Positional Arguments

NASL's calling convention uses **named arguments** (`func(a:1, b:2)`). The compiler resolves argument names to declaration order at compile time — the VM only deals with positional slots.

**Positional calls** (`func(1, 2)` without `name:`) generate different bytecode that pushes extra NULL slots for arg names, causing `ARG_REF[-2]` and later to read as NULL. **Always use named arguments for user-defined functions.**

Positional call bytecode for `add(3, 4)` (broken):
```
SLOT  INT(4)   INT(3)    ← values (same as named)
SLOT  NULL     NULL      ← arg name placeholders (NULL = no name)
SETVAR(4)                ← 4 slots total
CALL  src=<index>
```
Inside the function, `ARG_REF[-2]` reads the NULL name slot, not the value slot → returns empty.

### Calling a builtin

Builtins use positional-style calling (no named argument requirement):

```nasl
n = strlen(s);
```
```
SLOT  DEREF(s)  INT(1)        ← 1 arg (odd count: dst=1=count)
CALL  0xf0000056              ← call strlen builtin
MOV   DEREF(n)  REG(0x1f)    ← capture return value
```

```nasl
display("hello", x, y);       // 3 args (odd)
// Positional builtins use NULL in dst (no named-arg key), with the
// first arg's SLOT carrying the ODD count in dst. Exact order TBD
// from confirmed nbin traces; the 1-arg pattern below is confirmed.
```

```nasl
display(a, b, c, d);          // 4 args (even)
// EVEN positional calls: K SLOTs + SETVAR(K). Each SLOT has dst=NULL.
// The decompiler treats any non-KEY/INT_KEY SLOT dst as positional.
```

### Calling a user-defined function

The compiler maps named args to declaration order at compile time. In the **nbin disk format**, user-defined function calls use one SLOT per argument with `dst=KEY(name)` (mode 0x17 or 0x18) encoding the argument name as a symbol-table string, and SETVAR(2N) for N named args:

```nasl
function add(a, b) { ... }

r = add(a:3, b:4);            // named call, 2 args (even)
```
```
SLOT  src=INT(3)  dst=KEY("a")   ← named arg a=3
SLOT  src=INT(4)  dst=KEY("b")   ← named arg b=4
SETVAR(4)                         ← 2 named args × 2 = 4 total tokens
CALL  src=<frame_end_index>       ← e.g., CALL src=1 if FRAME_END at insn[1]
MOV   DEREF(r)  REG(0x1f)        ← r = return value
```

> **SETVAR count formula**: N = 2 × (number of named args). Each named arg contributes a name token plus a value token. ODD-count calls embed the count in the last SLOT's dst field instead of using SETVAR.

```nasl
r = add(b:4, a:3);            // reversed call order → same bytecode (compiler reorders)
```

```nasl
function one(x) { ... }

r = one(x:10);                // 1 arg (odd — count embedded in SLOT dst)
```
```
SLOT  src=INT(10)  dst=INT(1)    ← sole arg x=10, dst=1=count
CALL  src=<frame_end_index>
MOV   DEREF(r)  REG(0x1f)
```

```nasl
function three(a, b, c) { ... }

r = three(a:1, b:2, c:3);    // 3 args (odd)
```
```
SLOT  src=INT(3)  dst=KEY("c")    ← named arg c=3
SLOT  src=INT(2)  dst=KEY("b")    ← named arg b=2
SLOT  src=INT(1)  dst=INT(3)      ← named arg a=1, dst=3=count
CALL  src=<frame_end_index>
```

```nasl
r = quad(a:1, b:2, c:3, d:4);  // 4 args (even)
```
```
SLOT  src=INT(4)  dst=KEY("d")    ← named arg d=4
SLOT  src=INT(3)  dst=KEY("c")    ← named arg c=3
SLOT  src=INT(2)  dst=KEY("b")    ← named arg b=2
SLOT  src=INT(1)  dst=KEY("a")    ← named arg a=1
SETVAR(8)                          ← 4 named args × 2 = 8 total tokens
CALL  src=<frame_end_index>
```

> **GDB runtime note**: GDB traces may show a different packed representation where SLOT packs two VALUES per instruction (src=val[i+1], dst=val[i]) without KEY mode, reflecting an internal layout transformation the interpreter performs after loading the nbin. The nbin disk format always uses KEY/INT_KEY mode for named arg names.

### Function body layout

```nasl
function add(a, b) {
  return a + b;
}
```
```
[N]   FRAME_END              ← function entry point (insn[N])
[N-1] MOV   REG(0x1a)  ARG_REF(-2)   ← load a (1st param)
[N-2] ADD   REG(0x1a)  ARG_REF(-3)   ← REG += b (2nd param)
[N-3] RET   REG(0x1a)                ← return result
[N-4] RET   NULL                     ← fallthrough return (dead code)
```

**ARG_REF parameter offsets** (from FRAME_END perspective):
| Offset | Parameter     |
|--------|---------------|
| -2     | 1st (param[0]) |
| -3     | 2nd (param[1]) |
| -4     | 3rd (param[2]) |
| -5     | 4th (param[3]) |

**Note**: Each function body ends with TWO `RET` instructions — one explicit return and one `RET NULL` fallthrough guard (in case execution falls off the end).

---

## String Operations

```nasl
s = "Hello, World!";   → MOV DEREF(s) INT_KEY(0)          // sym[0]="Hello, World!"
joined = s + " Extra"; → MOV DEREF(joined) DEREF(s)
                           ADD DEREF(joined) INT_KEY(extra_sym)  // concat via ADD
```

String concatenation uses the **ADD** instruction with `INT_KEY` mode for string literals.

---

## Builtin Function IDs

Format: `0xf0000000 | builtin_index`

| Builtin Index | Function Name    |
|---------------|------------------|
| 0x47          | `display`        |
| 0x4b          | `strstr`         |
| 0x51          | `substr`         |
| 0x54          | `toupper`        |
| 0x56          | `strlen`         |
| 0x5c          | `make_list`      |

Full list can be enumerated by scanning `find_files_with_call(DIR, "func_name")` via nasl_py.

---

## GDB Tracing Notes

### Setup

```gdb
# VM dispatch loop entry (ASLR disabled: -R flag, or setarch -R)
b *0x55555556b296
commands
  silent
  set $op  = *(uint8_t*)($r13+0)
  set $sm  = *(uint8_t*)($r13+1)
  set $dm  = *(uint8_t*)($r13+2)
  set $fl  = *(uint8_t*)($r13+3)
  set $b4  = *(uint8_t*)($r13+4)
  set $b5  = *(uint8_t*)($r13+5)
  set $b6  = *(uint8_t*)($r13+6)
  set $b7  = *(uint8_t*)($r13+7)
  set $src = ($b4<<24)|($b5<<16)|($b6<<8)|$b7
  set $b8  = *(uint8_t*)($r13+8)
  ...
  set $dst = ($b8<<24)|($b9<<16)|($ba<<8)|$bb
  printf "INS op=0x%02x sm=0x%02x dm=0x%02x fl=0x%02x src=0x%08x dst=0x%08x\n",...
  continue
end
run
```

Run: `setarch $(uname -m) -R gdb -batch -x trace.gdb --args /opt/nessus/bin/nasl /tmp/test.nasl`

### Operand Value Decoding

GDB's `($b4<<24)|...` formula reads **LE memory bytes as if they were BE**. To recover the real integer value, **byteswap the GDB result**:

```python
import struct
def bs(gdb_value):
    return struct.unpack('<I', struct.pack('>I', gdb_value))[0]

# Example: GDB shows src=0x04000000 → bs(0x04000000) = 4  (variable slot 4)
# Example: GDB shows src=0x0a000000 → bs(0x0a000000) = 10
# Example: GDB shows src=0x470000f0 → bs(0x470000f0) = 0xf0000047  (display builtin)
```

**Exception**: FRAME_END instruction operands do NOT need byteswapping — they are stored in a different format.

### Known Invisible Instructions

The following instructions are NOT seen by a breakpoint at `0x55555556b296` due to the post-CALL fast-path:

- **CMP_*** instructions that immediately follow a CALL instruction in the bytecode.

To verify/trace these, break at the CALL handler's return or at a different VM loop address. They ARE present in the raw `.nbin` bytecode.

---

## Complete Example: t_cmp Trace Analysis

Source:
```nasl
x = 5; y = 3;
if (x == y) display("eq");
if (x != y) display("ne");
if (x > y)  display("gt");
if (x < y)  display("lt");
if (x >= y) display("ge");
if (x <= y) display("le");
```

Full bytecode layout (n=28 instructions, indices 0=lowest → 27=highest):

```
[27] JNZ(1)       ENTRY_NOP
[26] MOV v[4]=5
[25] MOV v[5]=3
[24] CMP_EQ(v4,v5)
[23] JZ(7)        → target[20]: skip eq-body if false
[22] SLOT "eq"    SKIPPED (x≠y)
[21] CALL display SKIPPED
[20] CMP_NE(v4,v5)              ← JZ(7) target
[19] JZ(11)       → target[16]: skip ne-body if false
[18] SLOT "ne"
[17] CALL display("ne")
[16] CMP_GT(v4,v5) ← POST-CALL (invisible to BP, sets flag=1 since 5>3)
[15] JZ(15)       → target[12]: skip gt-body if false
[14] SLOT "gt"
[13] CALL display("gt")
[12] CMP_LT(v4,v5) ← POST-CALL (invisible to BP, sets flag=0 since 5≮3)
[11] JZ(19)       → target[8]:  skip lt-body if false  [TAKEN: flag=0]
[10] SLOT "lt"    SKIPPED (x≥y)
 [9] CALL display SKIPPED
 [8] CMP_GE(v4,v5)              ← JZ(19) target [VISIBLE via jump]
 [7] JZ(23)       → target[4]:  skip ge-body if false
 [6] SLOT "ge"
 [5] CALL display("ge")
 [4] CMP_LE(v4,v5) ← POST-CALL (invisible to BP, sets flag=0 since 5≰3)
 [3] JZ(27)       → target[0]:  skip le-body if false  [TAKEN: flag=0]
 [2] SLOT "le"    SKIPPED (x>y)
 [1] CALL display SKIPPED
 [0] FUNC_INIT    ← JZ(27) target
```

GDB-visible executed trace: 19 instructions
Post-CALL hidden: 3 (CMP_GT, CMP_LT, CMP_LE)
JZ-skipped: 6 (SLOT+CALL for eq, lt, le)
Total: 19 + 3 + 6 = 28 ✓

---

## Decompiler Implications

1. **Flag-tracking**: The decompiler must track the condition flag register through CMP instructions AND through CALL instructions (CALL sets flag = truthy(RETVAL)).

2. **Post-CALL CMP**: When decoding, expect CMP_* immediately after CALL — this is the condition check for the *next* if-statement's branch. The decompiler should pair each `JZ/JNZ` with the CMP that precedes it, even when separated by CALL+SLOT chains.

3. **Variable naming**: Slots 4, 5, 6, ... → map to user variables in declaration order. The symbol table provides the actual names.

4. **REG[0x1a] folding**: Intermediate arithmetic uses REG[0x1a] as temp. The decompiler should fold these into inline expressions:
   ```
   MOV  REG(0x1a) DEREF(a) + ADD REG(0x1a) DEREF(b) + MOV DEREF(c) REG(0x1a)
   → c = a + b
   ```

5. **SLOT pairing**: When multiple SLOT instructions appear before a CALL with SETVAR(N), they should be reconstructed into the function's argument list in reverse-pair order.
