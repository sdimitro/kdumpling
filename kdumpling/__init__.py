"""
kdumpling - A Python library for creating Linux kdump crash dump files.

This library allows you to synthesize valid ELF64 vmcore files from
raw memory data and vmcoreinfo values.
"""

from .builder import (
    CompressionType,
    CustomNote,
    CustomNoteType,
    DumpStats,
    KdumpBuilder,
    OutputFormat,
)
from .cpu_context import AArch64Reg, CpuContext, X86_64Reg

__version__ = "0.1.0"
__all__ = [
    "KdumpBuilder",
    "DumpStats",
    "CpuContext",
    "X86_64Reg",
    "AArch64Reg",
    "OutputFormat",
    "CompressionType",
    "CustomNote",
    "CustomNoteType",
]
