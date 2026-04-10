"""
CLI entry points for nbin_tools.
Installed as console_scripts by pyproject.toml.
"""

import sys


def disasm():
    """nbin-disasm: raw disassembly + logic pseudocode."""
    from .nasl_decompiler import main as _main
    # Inject --raw --functions if no conflicting flags already present
    extra = []
    if "--raw" not in sys.argv:
        extra.append("--raw")
    if "--functions" not in sys.argv:
        extra.append("--functions")
    sys.argv = [sys.argv[0]] + extra + sys.argv[1:]
    _main()


def decompile():
    """nbin-decompile: full pseudocode output."""
    from .nasl_decompiler import main as _main
    _main()


def vm():
    """nbin-vm: low-level VM parser / disassembler."""
    from .nasl_vm import main as _main
    _main()
