# nbin-tools

Decompiler for Nessus `.nbin` compiled plugin files — converts binary NASL
bytecode back to readable pseudocode and high-level NASL source.

## Install

```bash
pip install nbin-tools
```

Or from a GitHub Release wheel:

```bash
pip install https://github.com/mikekei/nessus-security-re-tools/releases/latest/download/nbin_tools-<version>-py3-none-any.whl
```

## CLI

```bash
# Full raw disassembly + logic pseudocode
nbin-disasm   /opt/nessus/lib/nessus/plugins/plugin.nbin

# Logic pseudocode only (quieter, closer to NASL source)
nbin-decompile /opt/nessus/lib/nessus/plugins/plugin.nbin

# Low-level VM parser: symbol table, opcode stats, raw disasm
nbin-vm        /opt/nessus/lib/nessus/plugins/plugin.nbin --disasm --stats

# Show symbol table
nbin-disasm plugin.nbin --symtable

# Show function block boundaries
nbin-disasm plugin.nbin --functions
```

## Python API

```python
from nbin_tools import NbinFile, NaslDecompiler

# Parse the binary format
nb = NbinFile("plugin.nbin")
nb.load()
print(nb.summary())              # symbol count, instruction count, TLV types
for line in nb.disassemble():    # raw instruction listing
    print(line)

# Decompile to NASL pseudocode
dc = NaslDecompiler("plugin.nbin")
print(dc.decompile())
```

## Claude Code skill

Install the companion skill for Claude Code to get `/nbin-disasm` and
`/nbin-decompile` slash commands that run the decompiler then rewrite the
output into clean NASL:

```bash
cp skills/nbin.md ~/.claude/commands/nbin.md
```

Then in Claude Code:
```
/nbin-disasm /opt/nessus/lib/nessus/plugins/some_plugin.nbin
/nbin-decompile /opt/nessus/lib/nessus/plugins/some_plugin.nbin
```

## What it understands

| Feature | Status |
|---------|--------|
| nbin TLV container format | ✅ |
| Symbol / string table | ✅ |
| All 56 VM opcodes (0x00–0x37) | ✅ |
| All addressing modes (NULL/INT/KEY/DEREF/STACK/REG) | ✅ |
| Named-arg SLOT encoding (KEY vs DEREF) | ✅ |
| User-defined function boundaries | ✅ |
| Control flow (if/while/for/foreach/try/catch) | ✅ |
| ~60 builtin function names | ✅ |
| Remaining `builtin_0xNNN` names | ⚠ partial |

## Documentation

- [`docs/NBIN_DECOMPILER_FLOW.md`](docs/NBIN_DECOMPILER_FLOW.md) — complete flow from binary to NASL
- [`docs/NASL_INSTRUCTION_SET.md`](docs/NASL_INSTRUCTION_SET.md) — full instruction set reference
- [`docs/notes.md`](docs/notes.md) — raw reverse engineering notes (Ghidra addresses, VM state layout)

## Release

Tag a commit to trigger the publish workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions builds the wheel + sdist, runs smoke tests on Python 3.9–3.12,
then creates a GitHub Release with the artifacts attached.
