# NASL VM Reverse Engineering Notes

## Goal
Build a Python library that:
1. Takes a `.nbin` file → outputs readable disassembly
2. Converts those instructions back to high-level NASL source code (decompiler)

---

## nbin File Format

```
[4 bytes BE: uncompressed_size][zlib compressed payload]
```

Inner payload (after zlib decompress) = stream of TLV records:
```
[type: 4 bytes BE][length: 4 bytes BE][data: length bytes]
```

### TLV Record Types
| Type | Meaning |
|------|---------|
| 0x01 | Symbol/constant table (script-level strings and variable names) |
| 0x02 | Symbol/constant table (secondary — metadata strings, preference values) |
| 0x04 | Code section header (12 bytes = copy of first FUNC_INIT instruction) |
| 0x05 | File header (ABI version at [0], hash at [4], timestamps at [8][12], flags) |
| 0x06 | Include file list |
| 0x07 | RSA-4096 signature B |
| 0x0b | Plugin metadata (name, family, description) |
| 0x0c | Function definition table (functions with names, parameter lists, bytecode offsets) |
| 0x0f | **BYTECODE** (12-byte fixed instructions, flat array) |
| 0x10 | Script metadata (OID, version, family) |
| 0x1a | RSA-4096 signature A |

### Symbol Table Format (TLV 0x01 and 0x02)
Each entry: `[4 bytes BE: key][2 bytes BE: value_type][4 bytes BE: data_len][data_len bytes: value]`

- `key` = integer key used by KEY[N] or INT[N] addressing modes in bytecode
- `value_type` = NaslValue type (0x10=STRING_SHORT, 0x11=STRING_HEAP, etc.)
- `value` = UTF-8 string content (variable name OR string literal)

Example from `gcp_settings.nbin` TLV 0x01:
- key=0 → "true", key=1 → "/feed_build", key=2 → " ", key=3 → "Service Account JSON Key File :"

Example from TLV 0x02 (metadata/preference strings):
- key=0 → "run_on_all_nessus_versions", key=9 → "Google Cloud Platform Settings"
- key=12 → "synopsis", key=14 → "description", key=20 → "plugin_publication_date"

### Signature Verification
- Public key: `/opt/nessus/var/nessus/nessus_org.pem` (RSA-4096)
- Also: `tenable-plugins-a-20210201.pem`, `tenable-plugins-b-20210201.pem`
- Signatures at record types 0x07 and 0x1a
- Content is NOT encrypted — only signed + compressed

---

## VM Architecture

### Binary
- `/opt/nessus/bin/nasl` — ELF 64-bit, statically linked, stripped
- Ghidra load bias: +0x100000 (Ghidra_addr = actual_VMA + 0x100000)

### Key Functions
| Ghidra Addr | Role |
|------------|------|
| `FUN_0026b180` | **VM DISPATCH LOOP** (54KB, main execution engine) |
| `FUN_0020c3f0` | ADD / string concat handler (opcode 0x02) |
| `FUN_0020a960` | Comparison engine (opcodes 0x03, 0x0b–0x0e, 0x2b) |
| `FUN_0020c8b0` | Arithmetic & bitwise (opcodes 0x0f–0x1a, 0x29) |
| `FUN_0020cc70` | SUB and string substr (opcode 0x13) |
| `FUN_00266280` | RETURN handler (opcode 0x08) |
| `FUN_00269c40` | CALL handler (opcode 0x07) — dispatches to builtin or user function |
| `FUN_00265800` | SETVAR handler (opcode 0x09) — increments local var frame |
| `FUN_00266970` | POP handler (opcode 0x0a) — decrements frame_pos |
| `FUN_00267050` | Array/string element READ (opcode 0x20) |
| `FUN_002676b0` | Array element WRITE (opcode 0x21) |
| `FUN_00269eb0` | FOREACH iterator (opcode 0x2d) |
| `FUN_0025f400` | CALL_METHOD setup (opcode 0x30) |
| `FUN_00264570` | DEREF addressing mode (0x19) — dereference variable by ID |
| `FUN_00264890` | KEY mode (0x17) — hash keyed lookup |
| `FUN_00264800` | INT mode (0x18) — integer keyed lookup |
| `FUN_0025b590` | nbin deserializer loop |
| `FUN_00259750` | Signature verifier (EVP DigestVerify) |
| `FUN_003a6e20` | master.key loader / SQLCipher setup |

### Instruction Format (12 bytes, big-endian operands)
```
byte[0]   = opcode
byte[1]   = src addressing mode
byte[2]   = dst addressing mode
byte[3]   = flags
bytes[4-7]  = src operand (32-bit BE)
bytes[8-11] = dst operand (32-bit BE)
```

### Dispatch Type Table (`DAT_00a875c0`, file offset `0x9875c0`)
Controls how each opcode's operands are pre-resolved before execution:
- `0 = raw` — opcode reads pbVar3 directly (jumps, FUNC_INIT, NOP)
- `1 = dst` — only DST operand resolved
- `2 = src` — only SRC operand resolved
- `3 = both` — both SRC + DST resolved (most arithmetic/comparison ops)
- `4 = spec` — special pre-processing (RET, LOAD_ACC, CONCAT, INCLUDE, TRY, CATCH)

### Addressing Modes (byte[1] = src_mode, byte[2] = dst_mode)
| Value | Mode | Description |
|-------|------|-------------|
| 0x00–0x0d | Direct | Mode byte IS the NaslValue type; operand is the value |
| 0x00 | null | Null/undefined value |
| 0x01 | bool | Boolean value in operand |
| 0x02 | data | Raw data |
| 0x03 | int | Inline signed integer |
| 0x04 | uint | Inline unsigned integer |
| 0x05 | bool2 | Boolean variant |
| 0x08 | ihash | Integer hash (function IDs) |
| 0x0b | bytes | Raw bytes |
| 0x0c | fref | Function reference |
| 0x0d | aelem | Array element |
| 0x14 | STACK | Stack top (push/pop) |
| 0x15 | LOCAL | Local variable: operand + frame_pos indexes into local_var_array |
| 0x16 | REG | Register 0–31 (stored at vm_state + (reg_idx + 0x25) * 0x10) |
| 0x17 | KEY | Hash/string-keyed lookup: operand is key into symbol table; value is variable name |
| 0x18 | INT | Integer-keyed lookup |
| 0x19 | DEREF | Dereference: resolve variable by encoded function/variable ID |
| 0x1a | THIS | 'this' object context |
| 0x1b | SELF | 'self' (vm_state+0x498) |

**DEREF (0x19) ID encoding:**
- `(id & 0xf0000000) == 0xf0000000` → builtin function
- `(id & 0xff800000) == 0x800000` → user-defined function
- Otherwise → local/scoped variable

### Jump Addressing
**Formula:** `target_PC = code_block[+0x68] - operand`

Where `code_block` is the runtime code block structure. Empirically, `code_block[+0x68]` equals the total number of instructions in the TLV 0x0f section. The operand is the raw src_op field (read with src_mode=0x08/INT_HASH for jump instructions).

**Example** (gcp_settings.nbin, 186 total instructions):
- `JZ 0xb9` at insn[4] → target = 186 - 185 = 1
- `JNZ 0x6d` at insn[185] → target = 186 - 109 = 77

---

## Opcode Table (Complete — All 56 opcodes 0x00–0x37)

| Opcode | Mnemonic | Dispatch | Description |
|--------|----------|----------|-------------|
| 0x00 | NOP | raw | No operation |
| 0x01 | MOV | both | dst = src (assignment) |
| 0x02 | ADD | both | dst += src (int add or string concat) — FUN_0020c3f0 |
| 0x03 | CMP_EQ | both | flag = (src == dst) — FUN_0020a960 |
| 0x04 | JZ | raw | if flag==0: PC = N - src_op |
| 0x05 | JNZ | raw | if flag!=0: PC = N - src_op |
| 0x06 | CJMP | raw | if flag!=0 AND cond: PC = N - src_op |
| 0x07 | CALL | src | Call function (src_op=func_id; 0xf0000000 prefix = builtin) |
| 0x08 | RET | spec | Return from function — FUN_00266280 |
| 0x09 | SETVAR | src | Push variable/set arg count in local frame — FUN_00265800 |
| 0x0a | POP | dst | Pop local var from stack → dst — FUN_00266970 |
| 0x0b | CMP_LT | both | flag = (src < dst) — FUN_0020a960 |
| 0x0c | CMP_LE | both | flag = (src <= dst) — FUN_0020a960 |
| 0x0d | CMP_GT | both | flag = (src > dst) — FUN_0020a960 |
| 0x0e | CMP_GE | both | flag = (src >= dst) — FUN_0020a960 |
| 0x0f | AND | both | dst &= src (bitwise AND) — FUN_0020c8b0 |
| 0x10 | OR | both | dst \|= src (bitwise OR) — FUN_0020c8b0 |
| 0x11 | XOR | both | dst ^= src (bitwise XOR) — FUN_0020c8b0 |
| 0x12 | NOT_BIT | both | dst = ~src (bitwise NOT) — FUN_0020c8b0 |
| 0x13 | SUB | both | dst -= src (int sub or string substr) — FUN_0020cc70 |
| 0x14 | MUL | both | dst *= src — FUN_0020c8b0 |
| 0x15 | DIV | both | dst /= src — FUN_0020c8b0 |
| 0x16 | MOD | both | dst %= src — FUN_0020c8b0 |
| 0x17 | POW | both | dst = dst ** src — FUN_0020c8b0 |
| 0x18 | SHL | both | dst <<= (src & 0x1f) — FUN_0020c8b0 |
| 0x19 | SHR | both | dst >>= (src & 0x1f) — FUN_0020c8b0 |
| 0x1a | SHR2 | both | dst >>= (src & 0x1f) variant — FUN_0020c8b0 |
| 0x1b | LOAD_KEY | both | Load array element by string key |
| 0x1c | STORE_KEY | both | Store array element by string key |
| 0x1d | LOAD_IDX | both | Load array element by integer index |
| 0x1e | STORE_IDX | both | Store array element by integer index |
| 0x1f | LOAD_ACC | spec | Load accumulator from addressing mode |
| 0x20 | PUSH_SCOPE | both | Push new scope / read array element — FUN_00267050 |
| 0x21 | NEW_OBJ | both | Write array element / new object — FUN_002676b0 |
| 0x22 | CONCAT | spec | String concatenation (type-aware) |
| 0x23 | CONCAT2 | spec | Concatenation variant |
| 0x24 | NOT | raw | flag = (flag == 0) — logical NOT of condition |
| 0x25 | INCLUDE | spec | Script include / namespace operation |
| 0x26 | THROW | both | Throw exception — FUN_00267aa0 |
| 0x27 | TRY | spec | Set exception handler |
| 0x28 | CATCH | spec | Catch exception |
| 0x29 | NEG | both | dst = -src (negate) — FUN_0020c8b0 |
| 0x2a | TYPECHECK | both | Type check (typeof) |
| 0x2b | CMP_NE | both | flag = (src != dst) — FUN_0020a960 |
| 0x2c | FUNC_INIT | raw | Function block init (first insn of every code section) |
| 0x2d | FOREACH | raw | Foreach iterator setup — FUN_00269eb0 |
| 0x2e | GETVAR | dst | Get variable by name into dst — FUN_00265800 |
| 0x2f | INCR | dst | dst += n (increment) |
| 0x30 | PUSH_ARG | src | Push function argument — FUN_0025f400 |
| 0x31 | SET_NAMED | src | Set named parameter |
| 0x32 | SLOT | dst | Function argument slot (passes src=value, dst=param_name to builtin call) |
| 0x33 | FRAME_END | raw | End of function frame |
| 0x34 | ITER_NEXT | both | Iterator next |
| 0x35 | CMP_REG | spec | Compare with register |
| 0x36 | CMP_REG2 | spec | Compare with register variant |
| 0x37 | DECR | dst | dst -= n (decrement) |

---

## Bytecode Structure

### Layout of TLV 0x0f
- Single flat array of 12-byte instructions
- Starts with exactly ONE `FUNC_INIT` (0x2c) at instruction index 0
- Multiple `FRAME_END` (0x33) markers delimit embedded function blocks
- Main code body: from FUNC_INIT to first FRAME_END
- Function bodies: each block terminated by FRAME_END
- Functions are NOT prefixed with FUNC_INIT (only the whole section starts with one)

### Function Call Pattern (SLOT + CALL)
Named-argument function calls (e.g., `script_tag(name:"synopsis", value:"...")`):

```
SLOT  <value_key>  →  <name_key>    # Pass named argument: src=value, dst=name
CALL  fn:<func_id>                  # Execute the function
SETVAR #<n>                         # Commit result / update local frame
```

For builtin functions: `func_id` has prefix `0xf0000000`, index = func_id & 0x0fffffff

### Common Builtin Function IDs (from gcp_settings.nbin analysis)
Identified by context (cross-referencing NASL source patterns):
| Func ID | Likely Name |
|---------|-------------|
| fn:0xf00000ee | script_tag |
| fn:0xf0000001 | get_kb_item or script_require... |
| fn:0xf0000002 | set_kb_item or script_name |
| fn:0xf0000005 | script_add_preference |
| fn:0xf0000006 | script_name |
| fn:0xf0000007 | script_family |
| fn:0xf0000008 | script_copyright |
| fn:0xf0000012 | script_category |
| fn:0xf0000013 | script_version |
| fn:0xf0000017 | script_oid |
| fn:0xf0000019 | script_add_preference or script_dependencies |
| fn:0xf000006a | get_kb_item |
| fn:0xf000006e | set_kb_item |
| fn:0xf000006f | security_message |
| fn:0xf0000057 | display or log_message |
| fn:0xf00000ef | exit |
| fn:0xf00000a2 | ereg_replace or ereg |
| fn:0xf000010a | ereg or ereg_replace |
| fn:0xf0000121 | ereg or similar |

---

## NaslValue Struct (16 bytes)
```
{
  uint32  data0   @ 0   (length for strings)
  int16   type    @ 4   (value type enum)
  int16   flags   @ 6
  union {
    uint32  ival  @ 8   (integer value)
    uint64  ptr   @ 8   (pointer to heap data)
  }
}
```

### Value Types
| Value | Name | Description |
|-------|------|-------------|
| 0x00 | NULL | Undefined/null |
| 0x03 | INT32 | Signed 32-bit integer |
| 0x04 | UINT32 | Unsigned 32-bit integer |
| 0x05 | BOOL | Boolean |
| 0x08 | INT_HASH | Integer used as hash key (for function IDs) |
| 0x0b | DATA | Raw bytes |
| 0x0c | FUNC_REF | Function reference |
| 0x0d | ARRAY_ELEM | Array element |
| 0x10 | STRING_SHORT | Short string (inline SSO) |
| 0x11 | STRING_HEAP | Heap-allocated string |
| 0x17 | STRING_RAW | Raw/binary string |
| 0x18 | STRING_UNI | Unicode string |
| 0x1e | LIST | Linked list |
| 0x1f | ARRAY | Hash array (NASL array) |
| 0x20 | OBJECT_REF | Ref-counted object |

---

## VM State Layout (RDI = vm_state pointer)
| Offset | Field | Description |
|--------|-------|-------------|
| +0x06c | flags | bit0=error, bit1=allow_err, bit7=taint |
| +0x070 | func_type | 0x14=running, 0xd=interrupted, 0x17=exit |
| +0x198 | last_result | Last return value |
| +0x1b0 | func_table | Pointer to function table |
| +0x1b8 | code_block | Pointer to current code block (code_block[+0x68]=N for jumps) |
| +0x1c0 | insn_counter | Total instructions executed |
| +0x218 | builtin_table | Pointer to builtin function dispatch table |
| +0x230 | locals_base | Pointer to local variable array |
| +0x238 | local_count | Max local variable count |
| +0x23c | PC | Current instruction index |
| +0x240 | frame_pos | Local var frame position (stack top) |
| +0x244 | block_base | Code block base index |
| +0x434 | cond_type | Condition type code |
| +0x438 | cond_flag | Condition flag (0=false, 1=true) |
| +0x460 | accumulator | Accumulator register value |
| +0x464 | acc_type | Accumulator type |
| +0x488 | iter_ctx | Active iteration context |
| +0x490 | call_stack | Call stack frame pointer |
| +0x498 | self_reg | 'self' register |
| +0x4a0 | code_ptr | Code pointer |
| +0x4b0 | call_depth | Call depth counter |
| +0x4d0 | ret_val | Return value |
| +0x4d8 | exit_flag | Exit flag |

---

## master.key (SQLCipher)
- Path: `/opt/nessus/var/nessus/master.key`
- 2048 bytes, 1 SQLCipher page
- Salt (first 16 bytes): `b67ef65def6bf919b3fec0a073e3495d`
- Hardcoded default key at file offset `0xcfac40` (Ghidra `DAT_00ffac40`):
  `7b815a686e0a7c1c567b72f1d413796c6ef1fd4846c947ab886aacdf5f604695`
- Contains PASSWD table → plugin DB key

---

## Confirmed Findings (from 3081 nbin batch test)
- **100% opcode coverage** — all 3081 nbin files parse successfully
- **110M+ total instructions** analyzed
- **Top opcodes by frequency**: 0x32 SLOT(21.3%), 0x07 CALL(13.7%), 0x01 MOV(12.8%), 0x04 JZ(6.7%)
- TLV 0x0f is the ONLY bytecode section (not 0x06 or 0x0c as initial guesses)
- All valid opcodes: 0x00–0x37 (38h = 56 total; opcodes 0x38+ are garbage/off-table)

---

## TODO / Remaining Work
- [x] Correct opcode table (all 56 opcodes identified)
- [x] Fix symbol table parser (format confirmed: [4BE key][2B type][4BE len][bytes])
- [x] Verify jump formula (`target = N - operand`)
- [x] Understand SLOT+CALL pattern for function calls
- [x] Identify builtin function IDs (0xf000xxxx → name mapping) — 564 builtins, 100% static coverage
  - Gap 0x1c2–0x1f4 (51 entries): absent from static registration tables in both `nasl` and `nessusd`
  - The gap integers appear coincidentally in an embedded LDAP schema table (RFC 2256 object classes:
    rFC822localPart, dNSDomain, simpleSecurityObject, pilotOrganization, pilotDSA, etc.)
  - These IDs are likely registered at runtime by a dynamically-loaded module (platform extension,
    hostlevel_funcs, or sshlib agent component); plugins guard the calls gracefully (NULL return OK)
  - Gap 0x21f–0x402 (484 entries): same — absent from static tables entirely
  - Full verified approach: RELA relocation parsing of registration table at ELF VMA 0xee2cc0 (nasl)
    / 0xf662a0 (nessusd), 168-byte entries, name ptr @ +0, index @ +8, null-terminated
- [ ] Parse TLV 0x0c (function definition table) to map user function IDs to bytecode offsets — current impl is heuristic
- [x] Build `nasl_decompiler.py` (nbin → readable NASL pseudocode)
- [x] Reconstruct control flow (JZ/JNZ/CJMP → if/while/for)
- [x] Reconstruct function boundaries from TLV 0x0c + FRAME_END positions
