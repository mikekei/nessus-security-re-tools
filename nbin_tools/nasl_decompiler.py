#!/usr/bin/env python3
"""
NASL nbin Decompiler
====================
Converts compiled .nbin bytecode back to readable NASL pseudocode.

Requires nasl_vm.py in the same directory (or sys.path).

Usage:
    python3 nasl_decompiler.py <file.nbin> [options]

Options:
    --raw         Show raw instruction listing alongside decompiled output
    --functions   Show function boundaries
    --verbose     Show extra annotation comments
"""

import sys
import struct
import zlib
from pathlib import Path
from collections import defaultdict

try:
    from .nasl_vm import NbinFile, OPCODES, ADDR_MODES, VALUE_TYPES
except ImportError:
    # fallback for direct script execution
    sys.path.insert(0, str(Path(__file__).parent))
    from nasl_vm import NbinFile, OPCODES, ADDR_MODES, VALUE_TYPES

# ── Known builtin function ID → name mapping ──────────────────────────────────
# Derived from analysis of gcp_settings.nbin and cross-referencing NASL patterns.
# Format: func_id_index (= func_id & 0x0fffffff) → name
BUILTIN_NAMES = {
    # ── Description-block metadata functions ────────────────────────────────
    # Confirmed via empirical analysis of gcp_settings.nbin description block
    0x01: "script_name",               # gets plugin name string
    0x02: "script_version",            # gets version string
    0x05: "script_copyright",          # gets copyright string
    0x06: "script_summary",            # gets one-line summary text
    0x07: "script_category",           # gets integer category (ACT_*)
    0x08: "script_family",             # gets family string
    0x09: "script_oid",                # OID string (old form)
    0x0a: "script_dependencies",
    0x0b: "script_require_keys",
    0x0c: "script_require_ports",
    0x0d: "script_exclude_keys",
    0x0e: "script_require_udp_ports",
    0x0f: "script_add_preference",
    0x10: "script_get_preference",
    0x11: "script_get_preference_file_content",
    0x12: "script_mandatory_keys",     # uncertain; called in body with string args
    0x13: "script_id",                 # gets integer script ID (e.g. 150079)
    0x14: "script_version",            # alternate version call? (uncertain)
    0x15: "script_cve_id",
    0x16: "script_bugtraq_id",
    0x17: "get_kb_item",               # confirmed: gets KB keys like 'cert', 'plugins_folder'
    0x18: "script_xref",
    0x19: "set_kb_item",               # confirmed: named args name:, value:
    0x1a: "get_host_ip",
    0x1b: "get_kb_item",               # confirmed: gets KB paths like 'DNS/invalid_hostname', 'global_settings/...'
    0x1c: "open_sock_tcp",
    0x1d: "open_sock_udp",
    0x1e: "send",
    0x1f: "recv",
    0x20: "recv_line",
    0x21: "close",
    0x22: "get_port_state",
    0x23: "get_udp_port_state",
    0x24: "scanner_add_port",
    0x25: "security_message",
    0x26: "security_warning",
    0x27: "security_note",
    0x28: "security_hole",
    0x29: "log_message",
    0x2a: "display",
    0x2b: "string",
    0x2c: "strcat",
    0x2d: "strlen",
    0x2e: "substr",
    0x2f: "chomp",
    0x30: "ereg",
    0x31: "ereg_replace",
    0x32: "eregmatch",
    0x33: "split",
    0x34: "int",
    0x35: "hex",
    0x36: "hexstr",
    0x37: "ord",
    0x38: "chr",
    0x39: "strtoul",
    0x3a: "tolower",
    0x3b: "toupper",
    0x3c: "str_replace",
    0x3d: "crap",
    0x3e: "raw_string",
    0x3f: "insstr",
    0x40: "max_index",
    0x41: "sort",
    0x42: "keys",
    0x43: "values",
    0x44: "typeof",
    0x45: "isnull",
    0x46: "defined_func",
    0x47: "make_array",
    0x48: "make_list",
    0x49: "list_uniq",
    0x4a: "collib::new",
    0x4b: "tcp_ping",
    0x4c: "forge_ip_packet",
    0x4d: "dump_ip_packet",
    0x4e: "get_ip_element",
    0x4f: "set_ip_elements",
    0x50: "get_tcp_element",
    0x51: "forge_tcp_packet",
    0x52: "get_udp_element",
    0x53: "forge_udp_packet",
    0x54: "send_packet",
    0x55: "pcap_next",
    0x56: "dump_tcp_packet",
    0x57: "display",
    0x58: "exit",
    0x59: "max_index",
    0x5a: "keys",
    0x5b: "chomp",
    0x5c: "split",
    0x5d: "ereg",
    0x5e: "substr",
    0x5f: "strlen",
    0x60: "int",
    0x61: "sort",
    0x62: "tolower",
    0x63: "toupper",
    0x64: "str_replace",
    0x65: "string",
    0x66: "strcat",
    0x67: "hexstr",
    0x68: "hex",
    0x69: "ord",
    0x6a: "exit",                      # confirmed: called with 0 at end of description block
    0x6b: "get_kb_list",
    0x6c: "replace_kb_item",
    0x6d: "rm_kb_item",
    0x6e: "set_kb_item",               # single-arg form (uncertain; 0x19 is named-arg form)
    0x6f: "defined_func",              # confirmed: gets function names like 'zlib_compress', 'SHA256'
    0x70: "security_warning",
    0x71: "security_note",
    0x72: "security_hole",
    0x73: "log_message",
    0xa2: "ereg_replace",
    0xee: "script_tag",
    0xef: "script_end_attributes",     # confirmed: no-arg call after all script_tag calls
    0x121: "ereg",
    0x10a: "ereg_replace",
}

# CMP opcode → comparison operator string (from nasl_vm.py OPCODES)
CMP_OPS = {
    0x03: "==",   # CMP_EQ
    0x0b: "<",    # CMP_LT
    0x0c: "<=",   # CMP_LE
    0x0d: ">",    # CMP_GT
    0x0e: ">=",   # CMP_GE
    0x2b: "!=",   # CMP_NE
}

# Negation of each CMP operator (for simplifying !(A op B))
_NEGATE_OP = {"==": "!=", "!=": "==", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}


def _simplify_condition(cond: str) -> str:
    """Simplify !(A op B) → A negop B."""
    import re
    m = re.fullmatch(r'!\((.+)\s(==|!=|<|<=|>|>=)\s(.+)\)', cond)
    if m:
        lhs, op, rhs = m.group(1), m.group(2), m.group(3)
        return f"{lhs} {_NEGATE_OP[op]} {rhs}"
    return cond

# Arithmetic opcode → operator string (from nasl_vm.py OPCODES)
ARITH_OPS = {
    0x02: "+",    # ADD
    0x0f: "&",    # AND (bitwise)
    0x10: "|",    # OR  (bitwise)
    0x11: "^",    # XOR
    0x12: "~",    # NOT (bitwise, unary)
    0x13: "-",    # SUB
    0x14: "*",    # MUL
    0x15: "/",    # DIV
    0x16: "%",    # MOD
    0x17: "**",   # POW
    0x18: "<<",   # SHL
    0x19: ">>",   # SHR
    0x1a: ">>",   # SAR (arithmetic shift right)
    0x29: "-",    # NEG (unary negation)
}


def fmt_builtin(func_id: int) -> str:
    """Return readable name for a builtin function ID."""
    idx = func_id & 0x0fffffff
    name = BUILTIN_NAMES.get(idx)
    if name:
        return name
    if (func_id & 0xf0000000) == 0xf0000000:
        return f"builtin_{idx:#x}"
    return f"fn_{func_id:#x}"


class NaslDecompiler:
    """
    Decompiles NASL nbin bytecode to readable pseudocode.

    Strategy:
    1. Parse all TLV sections (symbol tables, bytecode)
    2. Identify function blocks (FRAME_END positions + TLV 0x0c offsets)
    3. For each block: recover control flow, reconstruct expressions
    4. Emit NASL-like pseudocode with proper indentation
    """

    def __init__(self, path: str, verbose: bool = False):
        self.nb = NbinFile(path)
        self.nb.load()
        self.verbose = verbose
        self.sym = self.nb.symtable()
        self.insns = self.nb.instructions()
        self.n = len(self.insns)
        self._fid_to_name: dict[int, str] = {}   # fid → function name
        self._fid_to_start: dict[int, int] = {}  # fid → start insn index
        self._block_ranges: list[tuple[int, int, str]] = []  # (start, end, name)
        self._parse_func_table()
        self._identify_blocks()

    # ── Symbol resolution ──────────────────────────────────────────────────────

    def resolve_sym(self, key: int) -> str:
        """Look up a key in the symbol table."""
        return self.sym.get(key, f"sym_{key}")

    def fmt_operand(self, mode: int, operand: int) -> str:
        """Format an operand as NASL-like expression."""
        # Inline literal modes 0x00–0x0d
        if 0x00 <= mode <= 0x0d:
            if mode == 0x00: return "NULL"
            if mode == 0x01: return "TRUE" if operand else "FALSE"
            if mode == 0x02:                                    # data/immediate value
                if operand == 0: return "NULL"
                v = operand if operand < 0x80000000 else operand - 0x100000000
                return str(v)
            if mode == 0x03:                                    # signed int
                # Interpret as signed 32-bit
                v = operand if operand < 0x80000000 else operand - 0x100000000
                return str(v)
            if mode == 0x04: return f"{operand}"               # unsigned int
            if mode == 0x05: return "TRUE" if operand else "FALSE"
            if mode == 0x08:
                # INT_HASH: function ID (builtin, object method, or user function)
                if (operand & 0xf0000000) == 0xf0000000:
                    return fmt_builtin(operand)
                if (operand & 0xff800000) == 0x800000:
                    # Object method slot ID → look up in TLV 0x0c table
                    slot = operand & 0x7fffff
                    return self._fid_to_name.get(operand, f"method_{slot}")
                # User-defined function: fid → look up by function ID
                name = self._fid_to_name.get(operand)
                if name:
                    return name
                return f"func_{operand:#x}"
            if mode == 0x0c:
                # FREF: function reference (inline) — treat like ihash
                if (operand & 0xf0000000) == 0xf0000000:
                    return fmt_builtin(operand)
                if (operand & 0xff800000) == 0x800000:
                    slot = operand & 0x7fffff
                    return self._fid_to_name.get(operand, f"method_{slot}")
                name = self._fid_to_name.get(operand)
                if name:
                    return name
                return f"func_{operand:#x}"
            if mode == 0x0d:
                # AELEM: array element — usually accumulator/result reference
                return "__acc__" if operand == 0 else f"aelem_{operand}"
            if mode in (0x09, 0x0b, 0x0e, 0x0f):
                # String literal: operand is a symtable index
                name = self.sym.get(operand)
                return repr(name) if name else f"str_pool[{operand}]"
            if mode == 0x0a:
                # Runtime frame reference (usually negative offset)
                signed = operand if operand < 0x80000000 else operand - 0x100000000
                return f"__tmp{signed}__"
            return f"({ADDR_MODES.get(mode, f'm{mode:02x}')}:{operand:#x})"

        # Memory/runtime modes
        if mode == 0x14: return "__acc__"         # stack/accumulator
        if mode == 0x15: return f"arg_{operand}"  # local variable by frame index
        if mode == 0x16:                           # global register (local var in frame)
            # Map common registers to readable names
            if operand == 0x1f: return "__ret__"  # r31 = return value register
            return f"loc_{operand}"
        if mode == 0x17:
            # KEY: index into string pool (symtable)
            name = self.sym.get(operand)
            return name if name else f"key_{operand}"
        if mode == 0x18:
            # INT_KEY: integer key (also string pool index in most cases)
            name = self.sym.get(operand)
            return name if name else f"ikey_{operand}"
        if mode == 0x19:
            # DEREF: runtime variable slot — NOT a symtable lookup
            if (operand & 0xf0000000) == 0xf0000000:
                return fmt_builtin(operand)
            # Variable slot index in the current function scope
            # Use signed interpretation for negative slot offsets
            signed = operand if operand < 0x80000000 else operand - 0x100000000
            if signed < 0:
                return f"upval[{signed}]"  # negative = closure/upvalue
            return f"v{operand}"
        if mode == 0x1a: return "this"
        if mode == 0x1b: return "self"

        # String value types (runtime only, not standard ADDR_MODES)
        if mode in (0x10, 0x11):  # STRING_SHORT / STRING_HEAP
            name = self.sym.get(operand)
            return repr(name) if name else f"str_pool[{operand}]"

        # High-bit modes: modifier flags in upper bits, base type in low 5 bits.
        # Empirically confirmed per-mode semantics:
        #   0xc9 (base 0x09), 0xcb (base 0x0b), 0xce (base 0x0e), 0xcf (base 0x0f),
        #   0xd1 (base 0x11) → symtable string references
        #   0xca (base 0x0a) → signed runtime frame reference (negative offsets)
        #   0xcc (base 0x0c) → function reference (handled via base mode recurse)
        #   0xcd (base 0x0d) → null/unused operand marker
        if mode > 0x1b:
            base = mode & 0x1f
            # Null/unused marker
            if base == 0x0d:
                return "NULL"
            # String literal via symtable
            if base in (0x09, 0x0b, 0x0e, 0x0f, 0x10, 0x11):
                name = self.sym.get(operand)
                return repr(name) if name else f"str_pool[{operand}]"
            # Recurse with base mode (handles func refs, ints, DEREF, etc.)
            return self.fmt_operand(base, operand)

        return f"{ADDR_MODES.get(mode, f'm{mode:02x}')}:{operand:#x}"

    # ── Block identification ───────────────────────────────────────────────────

    def _parse_func_table(self):
        """Parse TLV 0x0c (class/method table) to map method slot IDs → names.

        TLV 0x0c structure (fixed 554-byte shared library):
          [4BE: class_count] [4BE: total_methods] [4BE: ?]
          Per class:
            [2B: name_len][name bytes][NUL]
            (header fields...)
            Per method:
              [1B: attr][1B: name_len][name][NUL]
              [3B pad][4BE: ?][4BE: start_insn?][4BE: method_slot_id=0x00800NNN][...]
        Method slot IDs 0x00800000..0x008000FF → _fid_to_name[slot_id] = name
        """
        raw_0c = self.nb._raw_sections.get(0x0c, b'')
        if not raw_0c:
            return

        # Walk the binary looking for 0x00800000-0x008000ff slot IDs
        # Each method entry has [1B attr][1B namelen][name][NUL][...20 bytes...][4BE slot_id]
        off = 0
        while off + 4 <= len(raw_0c):
            v = struct.unpack('>I', raw_0c[off:off+4])[0]
            if (v & 0xff800000) == 0x800000 and (v & 0x7fffff) < 256:
                slot_id = v
                # Look backward for the method name (null-terminated before these 4 bytes)
                # The name appears ~20 bytes before the slot_id
                name_end = off
                while name_end > 0 and raw_0c[name_end-1] == 0:
                    name_end -= 1
                name_start = name_end
                while name_start > 0 and 32 <= raw_0c[name_start-1] < 127:
                    name_start -= 1
                if name_end - name_start >= 2:
                    name = raw_0c[name_start:name_end].decode('ascii', errors='replace')
                    if name.replace('_', '').isalnum() or '::' in name:
                        self._fid_to_name[slot_id] = name
            off += 1

    def _identify_blocks(self):
        """Find function block boundaries from FRAME_END positions.

        Block structure:
          - Each block starts at: 0 (first block) or frame_end+1
          - Each block ends at: frame_end instruction (inclusive)
          - The last block may have no FRAME_END (ends at last instruction)
          - Function ID: fid = N - block_start  (same encoding as jump targets)
        """
        frame_ends = [i for i, ins in enumerate(self.insns) if ins.opcode == 0x33]

        if not frame_ends:
            # Only one block (no functions)
            fid = self.n  # main block fid = N - 0 = N
            self._fid_to_name[fid] = "main"
            self._fid_to_start[fid] = 0
            self._block_ranges.append((0, self.n - 1, "main"))
            return

        # Build block list: (start, end)
        starts = [0] + [fe + 1 for fe in frame_ends]
        ends   = frame_ends + [self.n - 1]

        for i, (start, end) in enumerate(zip(starts, ends)):
            fid = self.n - start
            # Check if this is the main block (block 0, first block)
            if i == 0:
                block_name = "main"
            else:
                # Look up name from class method table, else use fid
                block_name = self._fid_to_name.get(fid, f"func_{fid:#x}")

            self._fid_to_name[fid] = block_name
            self._fid_to_start[fid] = start
            self._block_ranges.append((start, end, block_name))

    def jump_target(self, src_op: int) -> int:
        """Compute jump target instruction index.

        VM sets PC = N - src_op, then DECREMENTS before fetching.
        Effective next instruction = (N - src_op) - 1.
        """
        return self.n - src_op - 1

    def fid_to_name(self, fid: int) -> str:
        """Resolve a user function ID to its name."""
        return self._fid_to_name.get(fid, f"func_{fid:#x}")

    # ── Instruction classification ─────────────────────────────────────────────

    def is_cmp(self, idx: int) -> bool:
        return self.insns[idx].opcode in CMP_OPS

    def is_jump(self, idx: int) -> bool:
        return self.insns[idx].opcode in (0x04, 0x05, 0x06)

    def is_call(self, idx: int) -> bool:
        return self.insns[idx].opcode == 0x07

    def is_slot(self, idx: int) -> bool:
        return self.insns[idx].opcode == 0x32

    def is_ret(self, idx: int) -> bool:
        return self.insns[idx].opcode == 0x08

    # ── Expression reconstruction ──────────────────────────────────────────────

    def fmt_call(self, call_idx: int) -> str:
        """Legacy helper — not used in main decompile_block path."""
        ins = self.insns[call_idx]
        func_name = self.fmt_operand(ins.src_mode, ins.src_op)
        return f"{func_name}()", call_idx + 1

    # ── Core decompiler ────────────────────────────────────────────────────────

    def _build_slots(self, pending_slots: list) -> list[str]:
        """Convert pending SLOT list to argument strings.

        Each entry is (val, name, is_named) where is_named is True only when the
        original SLOT instruction had dst_mode=0x17 (KEY) or 0x18 (INT_KEY) — the
        only modes that encode a genuine NASL named-argument key.  DEREF (0x19),
        INT (0x03), STACK (0x14), NULL (0x00), etc. all indicate positional / ODD-
        count slots and must NOT be treated as named-arg names even if their
        formatted string happens to look like an identifier.
        """
        args = []
        for entry in pending_slots:
            val, name, is_named = entry if len(entry) == 3 else (entry[0], entry[1], False)
            # Skip null/empty filler slots (NULL NULL padding in positional calls)
            if (val == "NULL" or val == "") and (name == "NULL" or name == ""):
                continue
            if val == "NULL":
                continue
            if is_named:
                args.append(f"{name}:{val}")
            else:
                args.append(val)
        return args

    def _has_loopback_in_range(self, lo: int, hi: int) -> bool:
        """Return True if there is a CJMP/JNZ/JZ in [lo..hi-1] targeting >= hi."""
        for idx in range(lo, hi):
            ins = self.insns[idx]
            if ins.opcode in (0x04, 0x05, 0x06) and ins.src_mode == 0x08:
                t = self.jump_target(ins.src_op)
                if t >= hi:
                    return True
        return False

    def decompile_block(self, start: int, end: int, func_name: str = "main") -> list[str]:
        """Decompile a single function block [start..end] to lines of code.

        VM executes instructions HIGH→LOW (PC decrements each cycle).
        Argument-passing convention (observed in Ghidra FUN_0026b180):
          - SLOT (0x32): pushes (value, name) pair — named argument
          - SETVAR (0x09): pushes value — positional argument
          - Both accumulate before CALL; CALL consumes all pending args
        File order [SLOT, SETVAR, CALL] at indices [i+2, i+1, i] means
        execution order is SLOT first, SETVAR second, CALL third (HIGH→LOW).
        """
        lines = []
        indent = 0

        def emit(line: str):
            lines.append("  " * indent + line)

        # Track open conditional blocks: stack of (close_at, label)
        # close_at = instruction index where we emit "}" (before processing that insn)
        open_blocks: list[tuple[int, str]] = []

        # Pending args: accumulate SLOT/SETVAR before CALL
        # Each entry: (val_expr, name_expr, is_named)
        # is_named=True only when SLOT dst_mode is KEY (0x17) or INT_KEY (0x18)
        pending_slots: list[tuple[str, str, bool]] = []

        # Pending CMP: set by CMP opcode, consumed by next JZ/JNZ/CJMP
        pending_cmp: tuple[str, int] | None = None  # (condition_text, cmp_opcode)

        def flush_pending_slots_as_comment():
            for val, name, _ in pending_slots:
                emit(f"// slot: {name}={val}")
            pending_slots.clear()

        # Iterate HIGH→LOW: execution order mirrors VM
        i = end
        while i >= start:
            ins = self.insns[i]
            op = ins.opcode

            # ── Close any blocks whose close target we've reached ───────────
            while open_blocks and open_blocks[-1][0] == i:
                open_blocks.pop()
                indent = max(0, indent - 1)
                emit("}")

            # ── FRAME_END (0x33) / FUNC_INIT (0x2c) / NOP (0x00) ───────────
            # FRAME_END is the function prologue (highest index, executes first)
            # FUNC_INIT is the function epilogue (lowest index, executes last)
            if op in (0x33, 0x2c, 0x00):
                i -= 1
                continue

            # ── SLOT (0x32): argument push ──────────────────────────────────
            # dst_mode=0x17 (KEY) or 0x18 (INT_KEY) → genuinely named arg
            # All other dst modes (DEREF 0x19, INT 0x03, NULL 0x00, etc.) are
            # either the ODD-count marker, a positional value, or a variable
            # reference — never a named-arg key.
            if op == 0x32:
                val     = self.fmt_operand(ins.src_mode, ins.src_op)
                name    = self.fmt_operand(ins.dst_mode, ins.dst_op)
                is_named = ins.dst_mode in (0x17, 0x18)
                pending_slots.append((val, name, is_named))
                i -= 1
                continue

            # ── SETVAR (0x09) ───────────────────────────────────────────────
            # When dst_mode==0x02 (discard/control) and src is a small even int:
            # this is the arg-count marker pushed by NASL VM before CALL.
            # It tells CALL how many items were pushed to the arg stack (N_slots*2).
            # Skip it — it is NOT an actual argument.
            # Otherwise treat as a positional arg.
            if op == 0x09:
                if ins.dst_mode == 0x02:
                    # arg-count marker — skip
                    i -= 1
                    continue
                val = self.fmt_operand(ins.src_mode, ins.src_op)
                pending_slots.append((val, "", False))
                i -= 1
                continue

            # ── PUSH_ARG (0x30): positional argument ───────────────────────
            if op == 0x30:
                val = self.fmt_operand(ins.src_mode, ins.src_op)
                pending_slots.append((val, "", False))
                i -= 1
                continue

            # ── SET_NAMED (0x31) ───────────────────────────────────────────
            # When dst_mode==0x02 (control/discard), this is function frame
            # setup machinery emitted at the top of each block — skip it.
            if op == 0x31:
                if ins.dst_mode == 0x02:
                    i -= 1
                    continue
                val = self.fmt_operand(ins.src_mode, ins.src_op)
                pending_slots.append((val, "__named__", False))
                i -= 1
                continue

            # ── CALL (0x07): consume all pending args ───────────────────────
            if op == 0x07:
                fn = self.fmt_operand(ins.src_mode, ins.src_op)
                args = self._build_slots(pending_slots)
                pending_slots.clear()
                pending_cmp = None
                if args:
                    emit(f"{fn}({', '.join(args)});")
                else:
                    emit(f"{fn}();")
                i -= 1
                continue

            # ── CMP opcodes: store condition, wait for JZ/JNZ/CJMP ─────────
            if op in CMP_OPS:
                flush_pending_slots_as_comment()
                cmp_sym = CMP_OPS[op]
                lhs = self.fmt_operand(ins.src_mode, ins.src_op)
                rhs = self.fmt_operand(ins.dst_mode, ins.dst_op)
                pending_cmp = (f"{lhs} {cmp_sym} {rhs}", op)
                i -= 1
                continue

            # ── NOT (0x24): invert condition flag ───────────────────────────
            if op == 0x24:
                if pending_cmp is not None:
                    cond, cop = pending_cmp
                    pending_cmp = (f"!({cond})", cop)
                i -= 1
                continue

            # ── JZ/JNZ/CJMP: consume pending CMP and open block ────────────
            if op in (0x04, 0x05, 0x06):
                flush_pending_slots_as_comment()
                target = self.jump_target(ins.src_op)  # = N - src_op - 1

                if pending_cmp is not None:
                    condition, _ = pending_cmp
                    pending_cmp = None

                    # JZ   fires when condition_reg==0 (condition FALSE)
                    #      → if-body runs when condition TRUE
                    # JNZ  fires when condition_reg!=0 (condition TRUE)
                    #      → if-body runs when condition FALSE → negate
                    # CJMP fires when condition_reg!=0 (same as JNZ, confirmed Ghidra)
                    #      → if-body runs when condition FALSE → negate
                    if op == 0x04:    # JZ
                        cond_text = condition
                    else:             # JNZ (0x05) or CJMP (0x06)
                        cond_text = f"!({condition})"

                    # Simplify !(A op B) → A negop B
                    cond_text = _simplify_condition(cond_text)

                    # In HIGH→LOW: target < i means target is at a lower index
                    # (forward in execution = "after the if-body" = normal if)
                    # target > i means loop-back (while loop)
                    if start <= target < i:
                        # Check if there's a loop-back jump inside the body [target+1..i-1]
                        is_while = self._has_loopback_in_range(target + 1, i)
                        if is_while:
                            emit(f"while ({cond_text}) {{")
                        else:
                            emit(f"if ({cond_text}) {{")
                        open_blocks.append((target, "while" if is_while else "if"))
                        indent += 1
                    elif target > i:
                        # Loop-back jump (end of while body jumping up)
                        emit(f"// loop-back: {['JZ','JNZ','CJMP'][op-4]} → [{target}]")
                    else:
                        emit(f"// branch out of block: {['JZ','JNZ','CJMP'][op-4]} → [{target}]")
                else:
                    # Standalone jump without preceding CMP
                    j_name = {0x04: "JZ", 0x05: "JNZ", 0x06: "CJMP"}[op]
                    target = self.jump_target(ins.src_op)
                    if start <= target < i:
                        emit(f"if (__flag__) {{  // {j_name} → [{target}]")
                        open_blocks.append((target, j_name))
                        indent += 1
                    else:
                        emit(f"// {j_name} → [{target}]")
                i -= 1
                continue

            # ── MOV (0x01): assignment ──────────────────────────────────────
            # GDB-confirmed operand semantics (HIGH→LOW VM):
            #   src_mode/src_op = DESTINATION (LHS variable to write to)
            #   dst_mode/dst_op = SOURCE value (RHS — integer literal, string pool, etc.)
            # This is counter-intuitive but matches the wire format.
            if op == 0x01:
                flush_pending_slots_as_comment()
                pending_cmp = None
                lhs = self.fmt_operand(ins.src_mode, ins.src_op)  # destination var
                rhs = self.fmt_operand(ins.dst_mode, ins.dst_op)  # source value
                # src_mode 0x02 = discard (write to nowhere) — skip
                if ins.src_mode == 0x02:
                    i -= 1
                    continue
                # Skip if LHS is the accumulator (internal VM temp)
                if ins.src_mode == 0x14:
                    i -= 1
                    continue
                # dst_mode 0x02 = discard/null source → skip (no-op assignment)
                if ins.dst_mode == 0x02:
                    i -= 1
                    continue
                emit(f"{lhs} = {rhs};")
                i -= 1
                continue

            # ── RET (0x08) ─────────────────────────────────────────────────
            if op == 0x08:
                flush_pending_slots_as_comment()
                pending_cmp = None
                if ins.src_mode == 0x00:
                    emit("return;")
                else:
                    val = self.fmt_operand(ins.src_mode, ins.src_op)
                    emit(f"return {val};")
                i -= 1
                continue

            # ── Arithmetic / bitwise ─────────────────────────────────────────
            # GDB-confirmed: src_mode/src_op = LHS (modified variable, destination)
            #                dst_mode/dst_op = RHS (operand value, source)
            if op in ARITH_OPS:
                flush_pending_slots_as_comment()
                pending_cmp = None
                lhs = self.fmt_operand(ins.src_mode, ins.src_op)  # modified var
                rhs = self.fmt_operand(ins.dst_mode, ins.dst_op)  # operand value
                op_str = ARITH_OPS[op]
                # src_mode 0x02 = discard → skip
                if ins.src_mode == 0x02:
                    i -= 1
                    continue
                # dst_mode 0x02 = discard/null → skip
                if ins.dst_mode == 0x02:
                    i -= 1
                    continue
                if op == 0x29:
                    emit(f"{lhs} = -{rhs};")
                elif op == 0x12:
                    emit(f"{lhs} = ~{rhs};")
                else:
                    emit(f"{lhs} {op_str}= {rhs};")
                i -= 1
                continue

            # ── CONCAT (0x22, 0x23) ─────────────────────────────────────────
            # GDB-confirmed: op=0x22 sm=DEREF[loop_var] dm=data(0) = loop post-increment
            # When dm=data(0), emit lhs++ (for-loop/while-loop increment pattern).
            # Otherwise emit lhs += rhs (string/value concatenation).
            if op in (0x22, 0x23):
                flush_pending_slots_as_comment()
                pending_cmp = None
                lhs = self.fmt_operand(ins.src_mode, ins.src_op)
                if ins.dst_mode == 0x02:  # data(0) → post-increment pattern
                    emit(f"{lhs}++;")
                else:
                    rhs = self.fmt_operand(ins.dst_mode, ins.dst_op)
                    emit(f"{lhs} += {rhs};")
                i -= 1
                continue

            # ── INCR (0x2f) / DECR (0x37) ───────────────────────────────────
            if op == 0x2f:
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst}++;")
                i -= 1
                continue
            if op == 0x37:
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst}--;")
                i -= 1
                continue

            # ── FOREACH (0x2d) ───────────────────────────────────────────────
            if op == 0x2d:
                flush_pending_slots_as_comment()
                pending_cmp = None
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"foreach {dst} ({src}) {{")
                open_blocks.append((start, "foreach"))
                indent += 1
                i -= 1
                continue

            # ── ITER_NEXT (0x34) ────────────────────────────────────────────
            if op == 0x34:
                i -= 1
                continue

            # ── THROW (0x26) / TRY (0x27) / CATCH (0x28) ───────────────────
            if op == 0x26:
                flush_pending_slots_as_comment()
                val = self.fmt_operand(ins.src_mode, ins.src_op)
                emit(f"throw {val};")
                i -= 1
                continue
            if op == 0x27:
                flush_pending_slots_as_comment()
                emit("try {")
                indent += 1
                i -= 1
                continue
            if op == 0x28:
                emit("} catch {")
                i -= 1
                continue

            # ── TYPECHECK (0x2a) ─────────────────────────────────────────────
            if op == 0x2a:
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"// typeof({src}) check → {dst}")
                i -= 1
                continue

            # ── INCLUDE (0x25) ──────────────────────────────────────────────
            if op == 0x25:
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                emit(f'include("{src}");')
                i -= 1
                continue

            # ── LOAD_KEY (0x1b) / STORE_KEY (0x1c) ──────────────────────────
            if op == 0x1b:
                flush_pending_slots_as_comment()
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst} = {src}[key];")
                i -= 1
                continue
            if op == 0x1c:
                flush_pending_slots_as_comment()
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst}[key] = {src};")
                i -= 1
                continue

            # ── LOAD_IDX (0x1d) / STORE_IDX (0x1e) ──────────────────────────
            if op == 0x1d:
                flush_pending_slots_as_comment()
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst} = {src}[idx];")
                i -= 1
                continue
            if op == 0x1e:
                flush_pending_slots_as_comment()
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst}[idx] = {src};")
                i -= 1
                continue

            # ── PUSH_SCOPE (0x20) / NEW_OBJ (0x21) ──────────────────────────
            # PUSH_SCOPE is stack-frame setup machinery; skip silently.
            if op == 0x20:
                i -= 1
                continue
            if op == 0x21:
                flush_pending_slots_as_comment()
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst} = new {src}();")
                i -= 1
                continue

            # ── LOAD_ACC (0x1f) ─────────────────────────────────────────────
            if op == 0x1f:
                i -= 1
                continue

            # ── POP (0x0a) ──────────────────────────────────────────────────
            if op == 0x0a:
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                if dst != "__acc__":
                    emit(f"{dst} = __acc__;")
                i -= 1
                continue

            # ── GETVAR (0x2e) ────────────────────────────────────────────────
            if op == 0x2e:
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"{dst} = getvar({src});")
                i -= 1
                continue

            # ── CMP_REG (0x35) / CMP_REG2 (0x36) ────────────────────────────
            if op in (0x35, 0x36):
                src = self.fmt_operand(ins.src_mode, ins.src_op)
                dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
                emit(f"// cmp_reg({src}, {dst})")
                i -= 1
                continue

            # ── Fallback ─────────────────────────────────────────────────────
            flush_pending_slots_as_comment()
            pending_cmp = None
            mnem = OPCODES.get(op, (f"op{op:02x}", f"op{op:02x}", 0))[0]
            src = self.fmt_operand(ins.src_mode, ins.src_op)
            dst = self.fmt_operand(ins.dst_mode, ins.dst_op)
            emit(f"// {mnem}  {src}  →  {dst}")
            i -= 1

        # Flush any remaining state
        flush_pending_slots_as_comment()

        # Close any remaining open blocks
        while open_blocks:
            open_blocks.pop()
            indent = max(0, indent - 1)
            lines.append("  " * indent + "}")

        return lines

    def decompile(self) -> str:
        """Decompile all function blocks and return complete NASL pseudocode."""
        output = []
        output.append(f"// Decompiled from: {Path(self.nb.path).name}")
        output.append(f"// Total instructions: {self.n}")
        output.append(f"// Symbol table entries: {len(self.sym)}")
        output.append("")

        for start, end, name in self._block_ranges:
            if start >= end:
                continue
            if name == "main" or name.startswith("block_"):
                header = "// === MAIN CODE ==="
            else:
                header = f"function {name}() {{"
            output.append(header)

            block_lines = self.decompile_block(start, end, name)
            for line in block_lines:
                output.append(line)

            if not (name == "main" or name.startswith("block_")):
                output.append("}")
            output.append("")

        return "\n".join(output)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    import argparse
    p = argparse.ArgumentParser(description="NASL nbin decompiler")
    p.add_argument("file", help=".nbin file to decompile")
    p.add_argument("--raw", action="store_true", help="Show raw disassembly alongside")
    p.add_argument("--verbose", action="store_true", help="Extra annotation comments")
    p.add_argument("--functions", action="store_true", help="List function blocks")
    p.add_argument("--symtable", action="store_true", help="Dump symbol table")
    args = p.parse_args()

    path = args.file
    if not Path(path).exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)

    dc = NaslDecompiler(path, verbose=args.verbose)

    if args.symtable:
        print("=== SYMBOL TABLE ===")
        for k, v in sorted(dc.sym.items()):
            print(f"  [{k:5d}] {v!r}")
        print()

    if args.functions:
        print("=== FUNCTION BLOCKS ===")
        for start, end, name in dc._block_ranges:
            print(f"  {name:<30} insns [{start}..{end}] ({end-start+1} insns)")
        print()

    if args.raw:
        print("=== RAW DISASSEMBLY ===")
        for line in dc.nb.disassemble():
            print(" ", line)
        print()

    print("=== DECOMPILED OUTPUT ===")
    print(dc.decompile())


if __name__ == "__main__":
    main()
