#!/usr/bin/env python3
"""
NASL VM Disassembler and Executor
==================================
Reverse-engineered from Nessus 10.8.x /opt/nessus/bin/nasl (stripped ELF)
via static analysis and GDB runtime tracing.

nbin format:
  [4 bytes BE: uncompressed_size][zlib payload]

Inner TLV stream (after decompress):
  repeat: [type: 4BE][length: 4BE][data: length bytes]

Key TLV types:
  0x01  Symbol/variable name table
  0x02  External function table
  0x04  Code section header (small, 12 bytes)
  0x05  File header (ABI version, NASL_LEVEL)
  0x06  Include file list
  0x07  RSA-4096 signature B
  0x0b  Plugin metadata (name, family, description)
  0x0c  Function call dispatch table
  0x0f  *** BYTECODE *** (12-byte fixed instructions)
  0x10  Script metadata (OID, version, family)
  0x1a  RSA-4096 signature A

Instruction format (12 bytes, big-endian operands):
  byte[0]   opcode
  byte[1]   src_addr_mode
  byte[2]   dst_addr_mode
  byte[3]   flags
  bytes[4-7]  src_operand  (BE uint32)
  bytes[8-11] dst_operand  (BE uint32)

Dispatch type table (DAT_00a875c0 in nasl binary):
  0 = raw  — opcode reads pbVar3 directly (jumps, no-ops)
  1 = dst  — pre-resolve DST operand only
  2 = src  — pre-resolve SRC operand only
  3 = both — pre-resolve SRC + DST (most ops)
  4 = spec — special pre-processing

Addressing modes:
  0x00-0x0d  Direct inline: type in addr_mode byte, value in operand word
  0x14       Stack top (push/pop)
  0x15       Local variable by index (operand = var_index + frame_base)
  0x16       Global register 0-31 (operand = reg_index)
  0x17       Hash/keyed lookup (operand = key_index in string table)
  0x18       Integer-keyed lookup (operand = integer key)
  0x19       Dereference pointer
  0x1a       'this' object context
  0x1b       'self' (current object)

Value types (stored at offset +4 in NaslValue struct):
  0x00  NULL/undefined
  0x03  INT32 (signed integer)
  0x04  UINT32 (unsigned integer)
  0x05  BOOL
  0x08  INT_HASH (integer used as hash key)
  0x0b  DATA (raw bytes)
  0x0c  FUNC_REF
  0x0d  ARRAY_ELEM
  0x10  STRING_SHORT (inline SSO, up to ~6 chars inline)
  0x11  STRING_HEAP (heap-allocated string)
  0x17  STRING_RAW  (raw/binary string)
  0x18  STRING_UNI  (unicode string)
  0x1e  LIST (linked list)
  0x1f  ARRAY (hash array / NASL array)
  0x20  OBJECT_REF (ref-counted object)

VM state layout (RDI = vm_state pointer):
  +0x070  current function type (0x14=running, 0xd=interrupted, 0x17=exit)
  +0x06c  flags byte (bit0=error, bit1=allow_err, bit3=string_copy, bit4=...,
                      bit5=..., bit6=..., bit7=taint)
  +0x198  last result value
  +0x1b0  function table pointer
  +0x1b8  code block table pointer
  +0x1c0  instruction counter
  +0x218  builtin function table
  +0x23c  current instruction index (PC)
  +0x238  local var count (max)
  +0x240  local var frame position (stack top)
  +0x244  code block base index
  +0x230  local var array base pointer
  +0x434  condition type
  +0x438  condition flag (0=false, 1=true)
  +0x460  accumulator register [0]
  +0x464  accumulator type
  +0x488  active iteration context
  +0x490  call stack frame pointer
  +0x498  'self' register
  +0x4a0  code pointer
  +0x4b0  call depth counter
  +0x4d0  return value
  +0x4d4  breakpoint instruction
  +0x4d8  exit flag
  +0x4f8  function exit type
  +0x500  function exit flags
"""

import struct
import zlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Optional

# ── Opcode table (from Ghidra FUN_0026b180 analysis) ─────────────────────────
OPCODES = {
    0x00: ("NOP",       "nop",      0),  # raw
    0x01: ("MOV",       "mov",      3),  # both: dst = src
    0x02: ("ADD",       "add",      3),  # both: dst += src  (int or string concat)
    0x03: ("CMP_EQ",    "cmp ==",   3),  # both: flag = (src == dst)
    0x04: ("JZ",        "jz",       0),  # raw:  if flag==0: pc = n_insns - src_op
    0x05: ("JNZ",       "jnz",      0),  # raw:  if flag!=0: pc = n_insns - src_op
    0x06: ("CJMP",      "cjmp",     0),  # raw:  if flag!=0 AND cond: pc = n_insns - src_op
    0x07: ("CALL",      "call",     2),  # src:  call function(src_op)
    0x08: ("RET",       "ret",      4),  # spec: return (FUN_00266280)
    0x09: ("SETVAR",    "setvar",   2),  # src:  set variable in scope
    0x0a: ("POP",       "pop",      1),  # dst:  pop local var stack → dst
    0x0b: ("CMP_LT",    "cmp <",    3),  # both: flag = (src < dst)
    0x0c: ("CMP_LE",    "cmp <=",   3),  # both: flag = (src <= dst)
    0x0d: ("CMP_GT",    "cmp >",    3),  # both: flag = (src > dst)
    0x0e: ("CMP_GE",    "cmp >=",   3),  # both: flag = (src >= dst)
    0x0f: ("AND",       "and",      3),  # both: dst &= src
    0x10: ("OR",        "or",       3),  # both: dst |= src
    0x11: ("XOR",       "xor",      3),  # both: dst ^= src
    0x12: ("NOT_BIT",   "~",        3),  # both: dst = ~src
    0x13: ("SUB",       "sub",      3),  # both: dst -= src (int; string substr)
    0x14: ("MUL",       "mul",      3),  # both: dst *= src
    0x15: ("DIV",       "div",      3),  # both: dst /= src
    0x16: ("MOD",       "mod",      3),  # both: dst %= src
    0x17: ("POW",       "**",       3),  # both: dst = dst ** src
    0x18: ("SHL",       "shl",      3),  # both: dst <<= (src & 0x1f)
    0x19: ("SHR",       "shr",      3),  # both: dst >>= (src & 0x1f)
    0x1a: ("SHR2",      "shr2",     3),  # both: dst >>= (src & 0x1f) (variant)
    0x1b: ("LOAD_KEY",  "ld.key",   3),  # both: load array element by key
    0x1c: ("STORE_KEY", "st.key",   3),  # both: store array element by key
    0x1d: ("LOAD_IDX",  "ld.idx",   3),  # both: load by integer index
    0x1e: ("STORE_IDX", "st.idx",   3),  # both: store by integer index
    0x1f: ("LOAD_ACC",  "ld.acc",   4),  # spec: load accumulator from addr mode
    0x20: ("PUSH_SCOPE","push.sc",  3),  # both: push new scope / create array
    0x21: ("NEW_OBJ",   "new",      3),  # both: create new object
    0x22: ("CONCAT",    "cat",      4),  # spec: string concatenation (type-aware)
    0x23: ("CONCAT2",   "cat2",     4),  # spec: concatenation variant
    0x24: ("NOT",       "not",      0),  # raw:  flag = (flag == 0)  [logical NOT]
    0x25: ("INCLUDE",   "include",  4),  # spec: script include / namespace
    0x26: ("THROW",     "throw",    3),  # both: throw exception
    0x27: ("TRY",       "try",      4),  # spec: set exception handler
    0x28: ("CATCH",     "catch",    4),  # spec: catch exception
    0x29: ("NEG",       "neg",      3),  # both: dst = -src
    0x2a: ("TYPECHECK", "typeof",   3),  # both: type check
    0x2b: ("CMP_NE",    "cmp !=",   3),  # both: flag = (src != dst)
    0x2c: ("FUNC_INIT", "fn.init",  0),  # raw:  function init (first insn of each block)
    0x2d: ("FOREACH",   "foreach",  0),  # raw:  foreach iterator
    0x2e: ("GETVAR",    "getvar",   1),  # dst:  get variable by name into dst
    0x2f: ("INCR",      "incr",     1),  # dst:  dst += n
    0x30: ("PUSH_ARG",  "push.arg", 2),  # src:  push argument for call
    0x31: ("SET_NAMED", "setnamed", 2),  # src:  set named parameter
    0x32: ("SLOT",      "slot",     1),  # dst:  function/variable slot (table entry)
    0x33: ("FRAME_END", "frame.end",0),  # raw:  end of function frame
    0x34: ("ITER_NEXT", "iter.nx",  3),  # both: iterator next
    0x35: ("CMP_REG",   "cmp.r",    4),  # spec: compare with register
    0x36: ("CMP_REG2",  "cmp.r2",   4),  # spec: compare with register variant
    0x37: ("DECR",      "decr",     1),  # dst:  dst -= n
}

# Dispatch types (from DAT_00a875c0):
#  0=raw, 1=dst-only, 2=src-only, 3=both, 4=special
DISPATCH_TYPES = {i: OPCODES[i][2] if i in OPCODES else -1 for i in range(0x38)}

# Addressing mode names
ADDR_MODES = {
    0x00: "null",   0x01: "bool",  0x02: "data",  0x03: "int",
    0x04: "uint",   0x05: "bool2", 0x06: "?d6",   0x07: "?d7",
    0x08: "ihash",  0x09: "?d9",   0x0a: "?da",   0x0b: "bytes",
    0x0c: "fref",   0x0d: "aelem",
    0x14: "STACK",
    0x15: "LOCAL",
    0x16: "REG",
    0x17: "KEY",
    0x18: "INT",
    0x19: "DEREF",
    0x1a: "THIS",
    0x1b: "SELF",
}

# Value type names
VALUE_TYPES = {
    0x00: "NULL",
    0x03: "INT32",
    0x04: "UINT32",
    0x05: "BOOL",
    0x08: "INT_HASH",
    0x0b: "DATA",
    0x0c: "FUNC_REF",
    0x0d: "ARRAY_ELEM",
    0x10: "STRING_SHORT",
    0x11: "STRING_HEAP",
    0x17: "STRING_RAW",
    0x18: "STRING_UNI",
    0x1e: "LIST",
    0x1f: "ARRAY",
    0x20: "OBJECT_REF",
}


# ── NaslValue — runtime value struct (16 bytes) ───────────────────────────────
class NaslValue:
    """Mirrors the C NaslValue struct: {uint32 data0, int16 type, int16 flags, union{uint32 ival, uint64 ptr}}"""
    __slots__ = ("data0", "vtype", "flags", "ival", "ptr", "sval")

    def __init__(self, vtype=0, ival=0, sval=None, ptr=None, data0=0, flags=0):
        self.vtype = vtype
        self.ival  = ival
        self.sval  = sval
        self.ptr   = ptr
        self.data0 = data0
        self.flags = flags

    @classmethod
    def null(cls):
        return cls(0)

    @classmethod
    def int32(cls, v):
        return cls(0x03, ival=int(v))

    @classmethod
    def uint32(cls, v):
        return cls(0x04, ival=int(v) & 0xFFFFFFFF)

    @classmethod
    def string(cls, s):
        if isinstance(s, bytes):
            s = s.decode('utf-8', errors='replace')
        t = 0x10 if len(s) <= 4 else 0x11
        return cls(t, data0=len(s), sval=s)

    @classmethod
    def bool_(cls, b):
        return cls(0x05, ival=1 if b else 0)

    def is_null(self):   return self.vtype == 0
    def is_int(self):    return self.vtype in (0x03, 0x04, 0x08)
    def is_string(self): return self.vtype in (0x10, 0x11, 0x17, 0x18)
    def is_true(self):
        if self.is_null():   return False
        if self.is_int():    return self.ival != 0
        if self.is_string(): return bool(self.sval)
        return True

    def as_int(self):
        if self.is_int():    return self.ival
        if self.is_string():
            try: return int(self.sval)
            except: return 0
        return 0

    def as_str(self):
        if self.is_string(): return self.sval or ""
        if self.is_int():    return str(self.ival)
        if self.is_null():   return ""
        return str(self.ival)

    def __repr__(self):
        t = VALUE_TYPES.get(self.vtype, f"T{self.vtype:02x}")
        if self.is_int():    return f"{t}({self.ival})"
        if self.is_string(): return f'{t}("{self.sval}")'
        return f"{t}()"


# ── Instruction ───────────────────────────────────────────────────────────────
class Instruction:
    __slots__ = ("opcode", "src_mode", "dst_mode", "flags", "src_op", "dst_op",
                 "idx", "_opinfo")

    def __init__(self, opcode, src_mode, dst_mode, flags, src_op, dst_op, idx=0):
        self.opcode   = opcode
        self.src_mode = src_mode
        self.dst_mode = dst_mode
        self.flags    = flags
        self.src_op   = src_op
        self.dst_op   = dst_op
        self.idx      = idx
        self._opinfo  = OPCODES.get(opcode)

    @classmethod
    def from_bytes(cls, data, idx=0):
        assert len(data) >= 12
        op, sm, dm, fl = data[0], data[1], data[2], data[3]
        so = struct.unpack(">I", data[4:8])[0]
        do_ = struct.unpack(">I", data[8:12])[0]
        return cls(op, sm, dm, fl, so, do_, idx)

    @property
    def mnemonic(self):
        if self._opinfo: return self._opinfo[1]
        return f"op{self.opcode:02x}"

    @property
    def dispatch_type(self):
        if self._opinfo: return self._opinfo[2]
        return -1

    def _fmt_operand(self, mode, operand, string_pool=None):
        """Format a src or dst operand."""
        mode_name = ADDR_MODES.get(mode, f"m{mode:02x}")
        # Direct inline modes: 0x00-0x0d → mode byte IS the value type
        if 0x00 <= mode <= 0x0d:
            vtype = VALUE_TYPES.get(mode, f"T{mode:02x}")
            if mode == 0x03:   return f"#{operand}"          # inline int
            if mode == 0x04:   return f"#{operand}u"         # inline uint
            if mode == 0x05:   return f"#{bool(operand)}"    # inline bool
            if mode == 0x00:   return "null"
            return f"{vtype}:{operand:#010x}"
        # Address-based modes
        if mode == 0x14:  return f"STACK"
        if mode == 0x15:  return f"LOCAL[{operand}]"
        if mode == 0x16:  return f"REG[{operand}]"
        if mode == 0x17:
            if string_pool and operand < len(string_pool):
                return f'KEY["{string_pool[operand][:32]}"]'
            return f"KEY[{operand}]"
        if mode == 0x18:  return f"INT[{operand}]"
        if mode == 0x19:  return f"*[{operand:#x}]"
        if mode == 0x1a:  return "this"
        if mode == 0x1b:  return "self"
        return f"{mode_name}:{operand:#010x}"

    def format(self, string_pool=None):
        mnem = self.mnemonic.ljust(10)
        dt   = self.dispatch_type
        flag = f"fl={self.flags:02x}" if self.flags else "      "

        if dt == 0:  # raw — use raw operand bytes directly
            src = f"src={self.src_op:#010x}" if self.src_op else ""
            dst = f"dst={self.dst_op:#010x}" if self.dst_op else ""
            parts = [x for x in [src, dst] if x]
            return f"{self.idx:6d}  {mnem}  {flag}  {' '.join(parts)}"
        elif dt == 1:  # dst only
            dst = self._fmt_operand(self.dst_mode, self.dst_op, string_pool)
            return f"{self.idx:6d}  {mnem}  {flag}  dst={dst}"
        elif dt == 2:  # src only
            src = self._fmt_operand(self.src_mode, self.src_op, string_pool)
            return f"{self.idx:6d}  {mnem}  {flag}  src={src}"
        else:  # both (type 3 or 4)
            src = self._fmt_operand(self.src_mode, self.src_op, string_pool)
            dst = self._fmt_operand(self.dst_mode, self.dst_op, string_pool)
            return f"{self.idx:6d}  {mnem}  {flag}  {src}  →  {dst}"


# ── NbinFile — parse and hold all sections ────────────────────────────────────
class NbinFile:
    def __init__(self, path):
        self.path = str(path)
        self._raw_sections: dict[int, bytes] = {}
        self._instructions: list[Instruction] = []
        self._string_pool: list[str] = []
        self._func_table: list[dict] = []
        self._ext_funcs: list[dict] = []
        self._includes: list[str] = []
        self._symtable: dict[int, str] = {}   # combined key → name lookup
        self._loaded = False

    def load(self):
        if self._loaded:
            return
        with open(self.path, "rb") as f:
            raw = f.read()
        uncompressed_size = struct.unpack(">I", raw[:4])[0]
        payload = zlib.decompress(raw[4:])
        assert len(payload) == uncompressed_size, \
            f"Decompress mismatch: got {len(payload)}, expected {uncompressed_size}"

        # Parse TLV records
        offset = 0
        while offset + 8 <= len(payload):
            rtype = struct.unpack(">I", payload[offset:offset+4])[0]
            rlen  = struct.unpack(">I", payload[offset+4:offset+8])[0]
            offset += 8
            if rlen > len(payload) - offset:
                break
            self._raw_sections[rtype] = payload[offset:offset+rlen]
            offset += rlen

        self._parse_sections()
        self._loaded = True

    def _parse_sections(self):
        # String pool — type 0x03 (if present — some nbins don't have one)
        if 0x03 in self._raw_sections:
            data = self._raw_sections[0x03]
            parts = data.split(b'\x00')
            self._string_pool = [p.decode('utf-8', errors='replace') for p in parts if p]

        # Symbol/variable name table — type 0x01
        if 0x01 in self._raw_sections:
            sym1 = self._parse_symtable(self._raw_sections[0x01])
            self._symtable.update(sym1)
            self._func_table = [{"idx": k, "name": v} for k, v in sorted(sym1.items())]

        # Secondary symbol table — type 0x02
        if 0x02 in self._raw_sections:
            sym2 = self._parse_symtable(self._raw_sections[0x02])
            self._symtable.update(sym2)
            self._ext_funcs = [{"idx": k, "flags": 0, "name": v} for k, v in sorted(sym2.items())]

        # Include file list — type 0x06
        if 0x06 in self._raw_sections:
            self._includes = self._parse_include_list(self._raw_sections[0x06])

        # Bytecode — type 0x0f (new format) or type 0x04 when large (old format)
        code = None
        if 0x0f in self._raw_sections:
            code = self._raw_sections[0x0f]
        elif 0x04 in self._raw_sections and len(self._raw_sections[0x04]) > 12:
            # Older nbin format stores bytecode directly in section 4
            code = self._raw_sections[0x04]
        if code:
            n = len(code) // 12
            self._instructions = [
                Instruction.from_bytes(code[i*12:(i+1)*12], i)
                for i in range(n)
            ]

    def _parse_symtable(self, data):
        """Parse a symbol/constant table (type 0x01 or 0x02).
        Format per entry: [4BE key][2B value_type][4BE value_len][value_len bytes: value]
        """
        result = {}
        offset = 0
        while offset + 10 <= len(data):
            key   = struct.unpack(">I", data[offset:offset+4])[0]
            vtype = struct.unpack(">H", data[offset+4:offset+6])[0]
            vlen  = struct.unpack(">I", data[offset+6:offset+10])[0]
            offset += 10
            if offset + vlen > len(data):
                break
            val = data[offset:offset+vlen].decode('utf-8', errors='replace')
            offset += vlen
            result[key] = val
        return result

    def _parse_name_table(self, data):
        """Parse the variable/function name table (type 0x01)."""
        sym = self._parse_symtable(data)
        return [{"idx": k, "name": v} for k, v in sorted(sym.items())]

    def _parse_ext_funcs(self, data):
        """Parse secondary symbol table (type 0x02)."""
        sym = self._parse_symtable(data)
        return [{"idx": k, "flags": 0, "name": v} for k, v in sorted(sym.items())]

    def _parse_include_list(self, data):
        """Parse include file list (type 0x06)."""
        includes = []
        offset = 0
        # Format seems to be: [count:4BE][entries with length-prefixed names]
        while offset + 2 <= len(data):
            nlen = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            if nlen == 0 or offset + nlen > len(data):
                # Try 1-byte length
                if offset < len(data):
                    nlen = data[offset-1]
                    name_bytes = data[offset:offset+nlen]
                    try:
                        name = name_bytes.decode('ascii', errors='strict').rstrip('\x00')
                        if name and name.isprintable():
                            includes.append(name)
                    except:
                        pass
                    offset += nlen
                continue
            name = data[offset:offset+nlen].decode('utf-8', errors='replace').rstrip('\x00')
            offset += nlen
            if name:
                includes.append(name)
        return includes

    # Public API ──────────────────────────────────────────────────────────────

    def instructions(self) -> list:
        if not self._loaded:
            self.load()
        return self._instructions

    def string_pool(self) -> list:
        if not self._loaded:
            self.load()
        return self._string_pool

    def func_table(self) -> list:
        if not self._loaded:
            self.load()
        return self._func_table

    def ext_funcs(self) -> list:
        if not self._loaded:
            self.load()
        return self._ext_funcs

    def symtable(self) -> dict:
        """Return combined symbol table {key: name} from TLV 0x01 + 0x02."""
        if not self._loaded:
            self.load()
        return self._symtable

    def sections(self) -> dict:
        if not self._loaded:
            self.load()
        return {k: len(v) for k, v in self._raw_sections.items()}

    def disassemble(self, start=0, end=None, show_all=False) -> list[str]:
        """Return list of formatted instruction strings."""
        if not self._loaded:
            self.load()
        pool = self._string_pool
        insns = self._instructions
        if end is None:
            end = len(insns)
        lines = []
        for ins in insns[start:end]:
            if not show_all and ins.opcode == 0x32 and ins.src_mode == 0 and ins.dst_mode == 0 and ins.src_op == 0 and ins.dst_op == 0:
                continue  # skip empty slot entries
            lines.append(ins.format(pool))
        return lines

    def stats(self) -> dict:
        """Return opcode frequency stats."""
        if not self._loaded:
            self.load()
        from collections import Counter
        freq = Counter(i.opcode for i in self._instructions)
        return {
            "total_instructions": len(self._instructions),
            "opcode_freq": {f"0x{k:02x} {OPCODES.get(k, ('?','?',0))[0]}": v
                           for k, v in freq.most_common()},
        }

    def summary(self) -> str:
        """Return human-readable summary."""
        if not self._loaded:
            self.load()
        lines = [f"=== {Path(self.path).name} ==="]
        lines.append(f"Sections: " + ", ".join(f"0x{k:02x}({v}B)" for k,v in sorted(self.sections().items())))
        lines.append(f"Instructions: {len(self._instructions):,}")
        lines.append(f"String pool entries: {len(self._string_pool)}")
        if self._string_pool:
            lines.append(f"  First 5: {self._string_pool[:5]}")
        if self._ext_funcs:
            lines.append(f"Ext functions ({len(self._ext_funcs)}): {[f['name'] for f in self._ext_funcs[:5]]}")
        if self._includes:
            lines.append(f"Includes ({len(self._includes)}): {self._includes[:5]}")
        return "\n".join(lines)


# ── NaslVM — minimal executor skeleton ───────────────────────────────────────
class NaslVM:
    """
    Minimal NASL VM executor.
    Executes NASL bytecode instructions parsed from a nbin file.

    This is a faithful reconstruction of the Nessus VM based on Ghidra analysis.
    Not all opcodes are fully implemented — complex ones (CALL, INCLUDE, etc.)
    require integration with the Nessus function library.
    """

    def __init__(self, nbin: NbinFile):
        self.nbin = nbin
        self.pc = 0                    # instruction counter (index into code)
        self.flag = 0                  # condition flag (0=false, 1=true)
        self.locals: list = []         # local variable slots [NaslValue]
        self.local_frame_pos = 0       # top of local var stack
        self.registers = [NaslValue.null()] * 32  # REG[0..31]
        self.stack: list = []          # operand stack (STACK mode)
        self.accumulator = NaslValue.null()  # accumulator register
        self.self_val = NaslValue.null()
        self.this_val = NaslValue.null()
        self.result = NaslValue.null()
        self.call_stack: list = []     # list of return PCs
        self.kb: dict = {}             # knowledge base (global script vars)
        self.trace: list = []          # execution trace (for debugging)
        self._n_insns = 0              # total instructions in current code block

    def _init_locals(self, count=256):
        self.locals = [NaslValue.null() for _ in range(count)]
        self.local_frame_pos = 0

    def _resolve_src(self, ins: Instruction) -> NaslValue:
        """Resolve source operand to a NaslValue."""
        m, op = ins.src_mode, ins.src_op
        return self._resolve_operand(m, op, for_write=False)

    def _resolve_dst(self, ins: Instruction) -> NaslValue:
        """Resolve destination operand to a NaslValue (location for write)."""
        m, op = ins.dst_mode, ins.dst_op
        return self._resolve_operand(m, op, for_write=True)

    def _resolve_operand(self, mode, operand, for_write=False) -> NaslValue:
        """Decode addressing mode into a NaslValue."""
        # Direct inline modes (type encoded in mode byte)
        if 0x00 <= mode <= 0x0d:
            if mode == 0x00: return NaslValue.null()
            if mode == 0x03: return NaslValue.int32(operand)
            if mode == 0x04: return NaslValue.uint32(operand)
            if mode == 0x05: return NaslValue.bool_(operand != 0)
            if mode == 0x08: return NaslValue(0x08, ival=operand)
            return NaslValue(mode, ival=operand)  # other direct types

        if mode == 0x14:  # STACK
            if for_write:
                v = NaslValue.null()
                self.stack.append(v)
                return v
            return self.stack.pop() if self.stack else NaslValue.null()

        if mode == 0x15:  # LOCAL variable
            idx = operand + self.local_frame_pos  # adjust for frame
            # Actually: idx = operand + frame_base (from analysis: +0x240 + frame_delta)
            idx = int(operand) & 0x7FFFFFFF
            if idx < len(self.locals):
                return self.locals[idx]
            return NaslValue.null()

        if mode == 0x16:  # REG[0..31]
            r = operand & 0x1F
            return self.registers[r]

        if mode == 0x17:  # KEY lookup in string pool
            pool = self.nbin.string_pool()
            if operand < len(pool):
                key = pool[operand]
                return NaslValue.string(self.kb.get(key, ""))
            return NaslValue.null()

        if mode == 0x18:  # INT key
            return NaslValue.null()  # TODO: array int-keyed access

        if mode == 0x19:  # DEREF pointer
            return NaslValue.null()  # TODO: dereference

        if mode == 0x1a:  # THIS
            return self.this_val

        if mode == 0x1b:  # SELF
            return self.self_val

        return NaslValue.null()

    def _write_dst(self, ins: Instruction, value: NaslValue):
        """Write a value to the destination operand location."""
        m, op = ins.dst_mode, ins.dst_op
        if m == 0x15:  # LOCAL
            idx = int(op) & 0x7FFFFFFF
            while idx >= len(self.locals):
                self.locals.append(NaslValue.null())
            self.locals[idx] = value
        elif m == 0x16:  # REG
            r = op & 0x1F
            self.registers[r] = value
        elif m == 0x14:  # STACK
            self.stack.append(value)
        elif m == 0x17:  # KEY
            pool = self.nbin.string_pool()
            if op < len(pool):
                self.kb[pool[op]] = value
        elif m == 0x1a:
            self.this_val = value
        elif m == 0x1b:
            self.self_val = value
        # Direct modes are read-only (inline values in instruction)

    def _jump(self, target_operand):
        """Compute jump target: PC = n_insns - operand."""
        if self._n_insns > 0:
            self.pc = self._n_insns - target_operand
        else:
            self.pc = target_operand  # fallback

    def execute(self, max_steps=100000, trace=False):
        """Execute instructions until RET, error, or max_steps."""
        insns = self.nbin.instructions()
        self._n_insns = len(insns)
        self._init_locals()
        steps = 0

        while 0 <= self.pc < len(insns) and steps < max_steps:
            ins = insns[self.pc]
            self.pc += 1
            steps += 1

            if trace:
                self.trace.append(f"{ins.idx:6d}  PC={ins.idx}  {ins.format()}")

            try:
                self._exec_one(ins)
            except StopIteration:
                break
            except Exception as e:
                if trace:
                    self.trace.append(f"  *** ERROR at PC={ins.idx}: {e}")
                break

        return self.result

    def _exec_one(self, ins: Instruction):
        op = ins.opcode
        dt = ins.dispatch_type

        # ── Resolve operands based on dispatch type ──────────────────────────
        src_val = NaslValue.null()
        dst_val = NaslValue.null()
        if dt == 3:    # BOTH
            src_val = self._resolve_src(ins)
            dst_val = self._resolve_dst(ins)
        elif dt == 1:  # DST only
            dst_val = self._resolve_dst(ins)
        elif dt == 2:  # SRC only
            src_val = self._resolve_src(ins)

        # ── Execute ──────────────────────────────────────────────────────────
        if op == 0x00:  # NOP
            pass

        elif op == 0x01:  # MOV: dst = src
            self._write_dst(ins, src_val)

        elif op == 0x02:  # ADD / CONCAT: dst += src
            if dst_val.is_string() or src_val.is_string():
                result = NaslValue.string(dst_val.as_str() + src_val.as_str())
            else:
                result = NaslValue.int32(dst_val.as_int() + src_val.as_int())
            self._write_dst(ins, result)

        elif op == 0x03:  # CMP_EQ
            self.flag = 1 if dst_val.as_int() == src_val.as_int() else 0
            if dst_val.is_string() or src_val.is_string():
                self.flag = 1 if dst_val.as_str() == src_val.as_str() else 0

        elif op == 0x04:  # JZ: jump if flag == 0
            if self.flag == 0:
                self._jump(ins.src_op)

        elif op == 0x05:  # JNZ: jump if flag != 0
            if self.flag != 0:
                self._jump(ins.src_op)

        elif op == 0x06:  # CJMP
            if self.flag != 0:
                self._jump(ins.src_op)

        elif op == 0x07:  # CALL function
            # src_op = function ID in external function table
            # In real Nessus this calls into the NASL function library
            func_id = ins.src_op
            ext = self.nbin.ext_funcs()
            fname = ext[func_id]["name"] if func_id < len(ext) else f"func_{func_id}"
            if hasattr(self, f'_builtin_{fname.replace("::", "_")}'):
                getattr(self, f'_builtin_{fname.replace("::", "_")}')()
            # else: silently skip unknown builtins

        elif op == 0x08:  # RET: return from function
            if self.call_stack:
                self.pc = self.call_stack.pop()
            else:
                raise StopIteration("RET with empty call stack")

        elif op == 0x0a:  # POP local var → dst
            if self.local_frame_pos > 0:
                self.local_frame_pos -= 1
                val = self.locals[self.local_frame_pos]
                self._write_dst(ins, val)

        elif op == 0x0b:  # CMP_LT: flag = (dst < src)
            self.flag = 1 if dst_val.as_int() < src_val.as_int() else 0

        elif op == 0x0c:  # CMP_LE: flag = (dst <= src)
            self.flag = 1 if dst_val.as_int() <= src_val.as_int() else 0

        elif op == 0x0d:  # CMP_GT: flag = (dst > src)
            self.flag = 1 if dst_val.as_int() > src_val.as_int() else 0

        elif op == 0x0e:  # CMP_GE: flag = (dst >= src)
            self.flag = 1 if dst_val.as_int() >= src_val.as_int() else 0

        elif op == 0x0f:  # AND: dst &= src
            result = NaslValue.int32(dst_val.as_int() & src_val.as_int())
            self._write_dst(ins, result)

        elif op == 0x10:  # OR: dst |= src
            result = NaslValue.int32(dst_val.as_int() | src_val.as_int())
            self._write_dst(ins, result)

        elif op == 0x11:  # XOR: dst ^= src
            result = NaslValue.int32(dst_val.as_int() ^ src_val.as_int())
            self._write_dst(ins, result)

        elif op == 0x12:  # NOT_BIT: dst = ~src
            result = NaslValue.int32(~src_val.as_int() & 0xFFFFFFFF)
            self._write_dst(ins, result)

        elif op == 0x13:  # SUB: dst -= src
            if dst_val.is_string():
                s = dst_val.as_str()
                pat = src_val.as_str()
                idx = s.find(pat)
                result = NaslValue.string(s[:idx] + s[idx+len(pat):] if idx >= 0 else s)
            else:
                result = NaslValue.int32(dst_val.as_int() - src_val.as_int())
            self._write_dst(ins, result)

        elif op == 0x14:  # MUL: dst *= src
            result = NaslValue.int32(dst_val.as_int() * src_val.as_int())
            self._write_dst(ins, result)

        elif op == 0x15:  # DIV: dst /= src
            divisor = src_val.as_int()
            result = NaslValue.int32(dst_val.as_int() // divisor if divisor else 0)
            self._write_dst(ins, result)

        elif op == 0x16:  # MOD: dst %= src
            divisor = src_val.as_int()
            result = NaslValue.int32(dst_val.as_int() % divisor if divisor else 0)
            self._write_dst(ins, result)

        elif op == 0x17:  # POW: dst = dst ** src
            result = NaslValue.int32(int(dst_val.as_int() ** src_val.as_int()))
            self._write_dst(ins, result)

        elif op == 0x18:  # SHL: dst <<= (src & 0x1f)
            result = NaslValue.int32(dst_val.as_int() << (src_val.as_int() & 0x1f))
            self._write_dst(ins, result)

        elif op in (0x19, 0x1a):  # SHR: dst >>= (src & 0x1f)
            result = NaslValue.uint32((dst_val.as_int() & 0xFFFFFFFF) >> (src_val.as_int() & 0x1f))
            self._write_dst(ins, result)

        elif op == 0x24:  # NOT: flag = (flag == 0)
            self.flag = 1 if self.flag == 0 else 0

        elif op == 0x29:  # NEG: dst = -src
            result = NaslValue.int32(-src_val.as_int())
            self._write_dst(ins, result)

        elif op == 0x2b:  # CMP_NE: flag = (src != dst)
            self.flag = 1 if dst_val.as_int() != src_val.as_int() else 0

        elif op == 0x2c:  # FUNC_INIT: function block initializer
            pass  # header of each function block

        elif op == 0x2f:  # INCR: dst += n (n in src_op)
            v = dst_val
            v_new = NaslValue.int32(v.as_int() + ins.src_op)
            self._write_dst(ins, v_new)

        elif op == 0x37:  # DECR: dst -= n
            v = dst_val
            v_new = NaslValue.int32(v.as_int() - ins.src_op)
            self._write_dst(ins, v_new)

        # All other opcodes: silently skip (complex ops needing full runtime)


# ── CLI / demo ────────────────────────────────────────────────────────────────
def main():
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="NASL nbin disassembler/executor")
    parser.add_argument("nbin", help="Path to .nbin file")
    parser.add_argument("--disasm", action="store_true", help="Disassemble bytecode")
    parser.add_argument("--stats",  action="store_true", help="Show opcode statistics")
    parser.add_argument("--summary",action="store_true", help="Show file summary")
    parser.add_argument("--start",  type=int, default=0,    help="Start instruction index")
    parser.add_argument("--end",    type=int, default=None, help="End instruction index")
    parser.add_argument("--all",    action="store_true",    help="Include empty slot entries")
    parser.add_argument("--exec",   action="store_true",    help="Execute (experimental)")
    parser.add_argument("--trace",  action="store_true",    help="Show execution trace")
    args = parser.parse_args()

    nb = NbinFile(args.nbin)
    nb.load()

    if args.summary or not any([args.disasm, args.stats, args.exec]):
        print(nb.summary())

    if args.stats:
        s = nb.stats()
        print(f"\nOpcode frequency (top 20):")
        for op, cnt in list(s["opcode_freq"].items())[:20]:
            print(f"  {op:<30} {cnt:>8,}")

    if args.disasm:
        print(f"\nDisassembly ({args.start}..{args.end or 'end'}):")
        for line in nb.disassemble(args.start, args.end, args.all):
            print(f"  {line}")

    if args.exec:
        vm = NaslVM(nb)
        result = vm.execute(trace=args.trace)
        print(f"\nExecution result: {result}")
        if args.trace:
            print("\nTrace (last 20):")
            for line in vm.trace[-20:]:
                print(f"  {line}")


if __name__ == "__main__":
    main()
