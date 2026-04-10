#!/usr/bin/env python3
"""
Empirical opcode analysis of NASL nbin files.

nbin format:
  [4 bytes BE: uncompressed_size][zlib compressed payload]

Inner TLV stream (after decompress):
  [type: 4 bytes BE][length: 4 bytes BE][data: length bytes] ...

Code sections: type 0x06 (function bodies) and type 0x0c (main code)

Instruction format (12 bytes fixed):
  byte[0]   = opcode
  byte[1]   = src_mode
  byte[2]   = dst_mode
  byte[3]   = flags
  bytes[4-7]  = src_operand (32-bit BE)
  bytes[8-11] = dst_operand (32-bit BE)
"""

import struct
import zlib
import sys
import os
import json
from collections import Counter, defaultdict
from pathlib import Path

# ── Known opcode names from Ghidra analysis ──────────────────────────────────
OPCODE_NAMES = {
    0x01: "MOV",
    0x02: "CALL",
    0x03: "CMP_EQ",
    0x04: "JZ",
    0x05: "JNZ",
    0x06: "CJMP",
    0x07: "OP07",
    0x08: "RET",
    0x09: "OP09",
    0x0a: "OP0A",
    0x0b: "CMP_NE",
    0x0c: "CMP_LT",
    0x0d: "CMP_GT",
    0x0e: "CMP_LE",   # or GE
    0x0f: "ADD",
    0x10: "SUB",
    0x11: "MUL",
    0x12: "DIV",
    0x13: "MOD",
    0x14: "AND",
    0x15: "OR",
    0x16: "XOR",
    0x17: "SHL",
    0x18: "SHR",
    0x19: "NEG",
    0x1a: "NOT_BIT",
    0x1b: "OP1B",
    0x1c: "OP1C",
    0x1d: "OP1D",
    0x1e: "OP1E",
    0x1f: "STORE",
    0x20: "OP20",
    0x21: "OP21",
    0x22: "ADD_CAT",
    0x23: "ADD_CAT2",
    0x24: "NOT",
    0x25: "OP25",
    0x26: "THROW",
    0x27: "OP27",
    0x28: "JMPABS",
    0x29: "ARITH29",
    0x2a: "TYPECHECK",
    0x2b: "CMP_GE",
    0x2d: "SPECIAL",
}

ADDR_MODE_NAMES = {
    0x00: "d0", 0x01: "d1", 0x02: "d2", 0x03: "d3",
    0x04: "d4", 0x05: "d5", 0x06: "d6", 0x07: "d7",
    0x08: "d8", 0x09: "d9", 0x0a: "dA", 0x0b: "dB",
    0x0c: "dC", 0x0d: "dD",
    0x14: "STACK",
    0x15: "LOCAL",
    0x16: "REG",
    0x17: "KEY",
    0x18: "INT",
    0x19: "DEREF",
    0x1a: "THIS",
    0x1b: "SELF",
}


def decompress_nbin(path):
    """Decompress a nbin file, return raw TLV bytes."""
    with open(path, "rb") as f:
        data = f.read()
    # Find zlib magic (78 xx) — skip leading garbage/non-TLV header
    # nbin format: first 4 bytes = uncompressed size (BE), then zlib data
    if len(data) < 8:
        return None
    uncompressed_size = struct.unpack(">I", data[:4])[0]
    # Try to decompress from offset 4
    try:
        raw = zlib.decompress(data[4:])
        if len(raw) != uncompressed_size:
            # size mismatch — try wbits=-15 (raw deflate)
            raw2 = zlib.decompress(data[4:], wbits=-15)
            if raw2:
                raw = raw2
        return raw
    except Exception:
        # Try finding zlib magic manually
        for off in range(0, min(64, len(data)-2)):
            b0, b1 = data[off], data[off+1]
            if b0 == 0x78 and b1 in (0x01, 0x9c, 0xda, 0x5e):
                try:
                    return zlib.decompress(data[off:])
                except Exception:
                    continue
    return None


def parse_tlv_records(raw):
    """Parse TLV records from decompressed nbin payload."""
    records = []
    offset = 0
    while offset + 8 <= len(raw):
        rtype = struct.unpack(">I", raw[offset:offset+4])[0]
        rlen  = struct.unpack(">I", raw[offset+4:offset+8])[0]
        offset += 8
        if rlen > len(raw) - offset:
            break
        data = raw[offset:offset+rlen]
        records.append((rtype, rlen, data))
        offset += rlen
    return records


def parse_instructions(code_bytes):
    """Parse 12-byte fixed-length instructions from code section."""
    instructions = []
    n = len(code_bytes) // 12
    for i in range(n):
        chunk = code_bytes[i*12:(i+1)*12]
        if len(chunk) < 12:
            break
        opcode   = chunk[0]
        src_mode = chunk[1]
        dst_mode = chunk[2]
        flags    = chunk[3]
        src_op   = struct.unpack(">I", chunk[4:8])[0]
        dst_op   = struct.unpack(">I", chunk[8:12])[0]
        instructions.append({
            "opcode":   opcode,
            "src_mode": src_mode,
            "dst_mode": dst_mode,
            "flags":    flags,
            "src_op":   src_op,
            "dst_op":   dst_op,
        })
    return instructions


def analyze_file(path):
    """Return list of instructions from all code sections in nbin."""
    raw = decompress_nbin(path)
    if raw is None:
        return None, "decompress_failed"

    records = parse_tlv_records(raw)
    all_instructions = []
    string_pool = []

    for rtype, rlen, data in records:
        # Extract string pool (type 0x03)
        if rtype == 0x03:
            # Null-terminated strings
            parts = data.split(b'\x00')
            string_pool = [p.decode('utf-8', errors='replace') for p in parts if p]

        # Code sections: type 0x06 (function body) and type 0x0c (main code)
        if rtype in (0x06, 0x0c):
            instructions = parse_instructions(data)
            all_instructions.extend(instructions)

    return all_instructions, string_pool


def opcode_name(op):
    return OPCODE_NAMES.get(op, f"OP{op:02X}")


def addr_mode_name(m):
    return ADDR_MODE_NAMES.get(m, f"M{m:02X}")


def disassemble(instructions, string_pool=None):
    """Format instructions as readable disassembly."""
    lines = []
    for i, ins in enumerate(instructions):
        op   = opcode_name(ins["opcode"])
        sm   = addr_mode_name(ins["src_mode"])
        dm   = addr_mode_name(ins["dst_mode"])
        fl   = ins["flags"]
        so   = ins["src_op"]
        do_  = ins["dst_op"]

        # Annotate string references
        src_ann = ""
        dst_ann = ""
        if string_pool and ins["src_mode"] in (0x03, 0x17) and so < len(string_pool):
            src_ann = f' ; "{string_pool[so][:40]}"'

        lines.append(
            f"{i:5d}  {op:<12} {sm}:{so:#010x}  {dm}:{do_:#010x}  fl={fl:02x}{src_ann}"
        )
    return lines


# ── Main analysis ─────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Analyse opcode frequency across a set of .nbin files."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dir",  metavar="DIR",
                       help="Directory to scan recursively for .nbin files")
    group.add_argument("--list", metavar="FILE",
                       help="Text file with one .nbin path per line")
    parser.add_argument("--out", metavar="FILE", default="opcode_analysis.json",
                        help="Output JSON path (default: opcode_analysis.json)")
    args = parser.parse_args()

    if args.dir:
        paths = [str(p) for p in Path(args.dir).rglob("*.nbin")]
    else:
        sample_file = Path(args.list)
        paths = [p.strip() for p in sample_file.read_text().splitlines() if p.strip()]

    print(f"Analyzing {len(paths)} nbin files...\n")

    opcode_freq    = Counter()
    src_mode_freq  = Counter()
    dst_mode_freq  = Counter()
    flags_freq     = Counter()
    opcode_pairs   = Counter()   # (opcode, src_mode, dst_mode) tuples
    unknown_ops    = Counter()

    total_insts = 0
    ok_files = 0
    fail_files = 0

    sample_disasm = {}   # path -> first 30 instructions (for a few files)

    for idx, path in enumerate(paths):
        instructions, extra = analyze_file(path)
        if instructions is None:
            fail_files += 1
            continue
        string_pool = extra if isinstance(extra, list) else []
        ok_files += 1
        total_insts += len(instructions)

        for ins in instructions:
            op = ins["opcode"]
            sm = ins["src_mode"]
            dm = ins["dst_mode"]
            fl = ins["flags"]

            opcode_freq[op]   += 1
            src_mode_freq[sm] += 1
            dst_mode_freq[dm] += 1
            flags_freq[fl]    += 1
            opcode_pairs[(op, sm, dm)] += 1

            if op not in OPCODE_NAMES:
                unknown_ops[op] += 1

        # Save disassembly sample for first 5 files
        if idx < 5:
            sample_disasm[path] = disassemble(instructions[:50], string_pool)

        if (idx+1) % 10 == 0:
            print(f"  Processed {idx+1}/{len(paths)} files...")

    print(f"\nDone: {ok_files} OK, {fail_files} failed")
    print(f"Total instructions analyzed: {total_insts:,}")
    print(f"\n{'='*70}")
    print("OPCODE FREQUENCY (top 40):")
    print(f"{'='*70}")
    print(f"{'Opcode':>8}  {'Name':<14} {'Count':>10}  {'%':>6}")
    print(f"{'-'*70}")
    for op, cnt in opcode_freq.most_common(40):
        name = OPCODE_NAMES.get(op, f"UNKNOWN_{op:02X}")
        pct = cnt / total_insts * 100
        flag = " *** UNKNOWN ***" if op not in OPCODE_NAMES else ""
        print(f"  0x{op:02x}    {name:<14} {cnt:>10,}  {pct:>5.1f}%{flag}")

    print(f"\n{'='*70}")
    print("UNKNOWN OPCODES:")
    print(f"{'='*70}")
    if unknown_ops:
        for op, cnt in sorted(unknown_ops.items()):
            print(f"  0x{op:02x}  count={cnt:,}")
    else:
        print("  None! All opcodes in known set.")

    print(f"\n{'='*70}")
    print("ADDRESSING MODE FREQUENCY (src):")
    print(f"{'='*70}")
    for m, cnt in src_mode_freq.most_common(20):
        name = ADDR_MODE_NAMES.get(m, f"UNK_{m:02x}")
        print(f"  0x{m:02x} {name:<8}  {cnt:>10,}")

    print(f"\n{'='*70}")
    print("ADDRESSING MODE FREQUENCY (dst):")
    print(f"{'='*70}")
    for m, cnt in dst_mode_freq.most_common(20):
        name = ADDR_MODE_NAMES.get(m, f"UNK_{m:02x}")
        print(f"  0x{m:02x} {name:<8}  {cnt:>10,}")

    print(f"\n{'='*70}")
    print("FLAGS DISTRIBUTION:")
    print(f"{'='*70}")
    for fl, cnt in sorted(flags_freq.items())[:20]:
        print(f"  0x{fl:02x}  {cnt:>10,}")

    print(f"\n{'='*70}")
    print("TOP 30 OPCODE PATTERNS (opcode, src_mode, dst_mode):")
    print(f"{'='*70}")
    for (op, sm, dm), cnt in opcode_pairs.most_common(30):
        op_n = OPCODE_NAMES.get(op, f"OP{op:02X}")
        sm_n = ADDR_MODE_NAMES.get(sm, f"M{sm:02X}")
        dm_n = ADDR_MODE_NAMES.get(dm, f"M{dm:02X}")
        print(f"  {op_n:<12} {sm_n:<8} {dm_n:<8}  {cnt:>8,}")

    print(f"\n{'='*70}")
    print("SAMPLE DISASSEMBLY (first file, first 50 instructions):")
    print(f"{'='*70}")
    for path, lines in list(sample_disasm.items())[:1]:
        print(f"\n  File: {path}")
        for line in lines:
            print(f"    {line}")

    # Save full results to JSON
    results = {
        "total_files": ok_files,
        "total_instructions": total_insts,
        "opcode_freq": {f"0x{k:02x}": v for k, v in sorted(opcode_freq.items())},
        "unknown_opcodes": {f"0x{k:02x}": v for k, v in sorted(unknown_ops.items())},
        "src_mode_freq": {f"0x{k:02x}": v for k, v in sorted(src_mode_freq.items())},
        "dst_mode_freq": {f"0x{k:02x}": v for k, v in sorted(dst_mode_freq.items())},
        "flags_freq": {f"0x{k:02x}": v for k, v in sorted(flags_freq.items())},
    }
    out_path = args.out
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n\nFull results saved to {out_path}")


if __name__ == "__main__":
    main()
