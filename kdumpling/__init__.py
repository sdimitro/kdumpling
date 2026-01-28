"""
kdumpling - A Python library for creating Linux kdump crash dump files.

This library allows you to synthesize valid ELF64 vmcore files from
raw memory data and vmcoreinfo values.
"""

from .builder import KdumpBuilder
from .cpu_context import AArch64Reg, CpuContext, X86_64Reg

__version__ = "0.1.0"
__all__ = ["KdumpBuilder", "CpuContext", "X86_64Reg", "AArch64Reg"]
