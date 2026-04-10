# nbin-tools

> **Decompiler for Nessus `.nbin` compiled plugin files** — converts binary NASL
> bytecode back to readable pseudocode and high-level NASL source.

---

## Legal Notice & Disclaimer

**Read this section before using this software.**

### Purpose

This project is an **educational security research tool** created to:

- Understand the internal structure of the NASL (Nessus Attack Scripting Language)
  bytecode format for academic and professional development purposes.
- Enable security researchers and Nessus licensees to audit, inspect, and understand
  the plugins running on their own licensed Nessus installations.
- Advance public knowledge of proprietary bytecode VM design — a well-established
  domain of legitimate security research (comparable to work published on JVM, Lua,
  Python, and other VMs).
- Support defensive security use cases: understanding what a plugin does before
  deploying it on production infrastructure.

### Intended Audience

This tool is intended **only** for:

- Security researchers conducting legitimate, authorized research.
- Licensed Nessus users who want to understand the behavior of plugins running
  on systems they own or administer.
- Students and educators studying compiler theory, VM design, or binary formats
  in an academic context.
- Penetration testers with written authorization to test the environment in question.
- CTF (Capture the Flag) participants working within competition boundaries.

### Restrictions & Responsible Use

**You are solely responsible for ensuring your use complies with all applicable laws
and agreements.** In particular:

1. **Tenable License Agreement** — Nessus is proprietary software. Your Nessus
   license agreement (EULA) with Tenable, Inc. governs what you may and may not
   do with the software and its components. Review it before using this tool.
   Using this tool to circumvent license restrictions or copy-protection mechanisms
   may violate that agreement and applicable law.

2. **Computer Fraud and Abuse Act (CFAA) / equivalent national laws** — Only
   analyze plugins on systems you own or have explicit written authorization to
   test. Unauthorized access to computer systems is a criminal offense in the
   United States and most jurisdictions.

3. **DMCA Section 1201 (and equivalent)** — The Digital Millennium Copyright Act
   prohibits circumventing technological protection measures. This tool is designed
   for legitimate interoperability and research; it must not be used to circumvent
   access controls in violation of 17 U.S.C. § 1201. Security research exemptions
   (17 C.F.R. § 201.40) may apply to your use case — consult a qualified attorney
   if in doubt.

4. **Do not redistribute** decompiled plugin output as if it were your own work.
   Nessus plugins are Tenable's intellectual property. Decompiled output retains
   that copyright.

5. **No offensive use** — This tool must not be used to develop attack tools,
   assist unauthorized access, or facilitate harm to systems you do not own.

### No Warranty

This software is provided **"as is"**, without warranty of any kind, express or
implied. The authors accept no liability for damages arising from its use,
misuse, or inability to use. See the [MIT License](LICENSE) for full terms.

### DMCA / Takedown Contact

If you are Tenable, Inc. or a rights holder and believe this project infringes
your intellectual property, please open an issue or contact the repository owner
directly. We will respond promptly and in good faith.

---

## Overview

`nbin-tools` reverse-engineers the `.nbin` binary format that Nessus uses to
distribute compiled NASL plugins. It reconstructs the original plugin logic as
readable pseudocode so that licensed users can inspect what code is running on
their own infrastructure.

**What this tool does NOT do:**

- It does not bypass Nessus authentication or licensing.
- It does not extract or expose Tenable's network communications.
- It does not enable running Nessus without a valid license.
- It does not provide any exploit code or attack capability.

---

## Install

```bash
pip install nbin-tools
```

Or from a GitHub Release wheel:

```bash
pip install https://github.com/mikekei/nessus-security-re-tools/releases/latest/download/nbin_tools-<version>-py3-none-any.whl
```

---

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

---

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

---

## Claude Code Skill

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

---

## What It Understands

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

---

## Documentation

- [`docs/NBIN_DECOMPILER_FLOW.md`](docs/NBIN_DECOMPILER_FLOW.md) — complete flow from binary to NASL
- [`docs/NASL_INSTRUCTION_SET.md`](docs/NASL_INSTRUCTION_SET.md) — full instruction set reference
- [`docs/notes.md`](docs/notes.md) — raw reverse engineering notes (Ghidra addresses, VM state layout)

---

## Release

Tag a commit to trigger the publish workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions builds the wheel + sdist, runs smoke tests on Python 3.9–3.12,
then creates a GitHub Release with the artifacts attached.

---

## License

[MIT License](LICENSE) — Copyright (c) 2024 Micheal Keines.

This license covers the **tooling source code only**. Decompiled output of
Nessus plugins remains subject to Tenable's copyright. See [Legal Notice](#legal-notice--disclaimer) above.
