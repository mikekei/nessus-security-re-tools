"""
nbin_tools — Nessus .nbin plugin decompiler
============================================
Converts compiled Nessus NASL bytecode (.nbin) back to readable pseudocode
and high-level NASL source.

Quick start::

    from nbin_tools import NbinFile, NaslDecompiler

    nb = NbinFile("plugin.nbin")
    nb.load()
    print(nb.summary())

    dc = NaslDecompiler("plugin.nbin")
    print(dc.decompile())

CLI::

    nbin-disasm   plugin.nbin [--raw] [--functions] [--symtable]
    nbin-decompile plugin.nbin [--verbose]
    nbin-vm        plugin.nbin [--disasm] [--stats] [--summary]
"""

from .nasl_vm import NbinFile, NaslVM, Instruction, NaslValue, OPCODES, ADDR_MODES
from .nasl_decompiler import NaslDecompiler, BUILTIN_NAMES

__version__ = "0.1.0"
__all__ = [
    "NbinFile",
    "NaslVM",
    "Instruction",
    "NaslValue",
    "NaslDecompiler",
    "OPCODES",
    "ADDR_MODES",
    "BUILTIN_NAMES",
]
