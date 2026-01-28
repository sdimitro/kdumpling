"""
CPU context structures for different architectures.

This module defines the register layouts for NT_PRSTATUS notes
which contain CPU state at the time of the crash.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum

from .elf import ElfData


class NoteType(IntEnum):
    """ELF note types for core dumps."""

    NT_PRSTATUS = 1
    NT_PRFPREG = 2
    NT_PRPSINFO = 3
    NT_TASKSTRUCT = 4
    NT_AUXV = 6
    NT_SIGINFO = 0x53494749
    NT_FILE = 0x46494C45
    NT_PRXFPREG = 0x46E62B7F


# x86_64 register indices in pr_reg array
class X86_64Reg(IntEnum):
    """x86_64 register indices in the prstatus pr_reg array."""

    R15 = 0
    R14 = 1
    R13 = 2
    R12 = 3
    RBP = 4
    RBX = 5
    R11 = 6
    R10 = 7
    R9 = 8
    R8 = 9
    RAX = 10
    RCX = 11
    RDX = 12
    RSI = 13
    RDI = 14
    ORIG_RAX = 15
    RIP = 16
    CS = 17
    EFLAGS = 18
    RSP = 19
    SS = 20
    FS_BASE = 21
    GS_BASE = 22
    DS = 23
    ES = 24
    FS = 25
    GS = 26


# AArch64 register indices
class AArch64Reg(IntEnum):
    """AArch64 register indices."""

    X0 = 0
    X1 = 1
    X2 = 2
    X3 = 3
    X4 = 4
    X5 = 5
    X6 = 6
    X7 = 7
    X8 = 8
    X9 = 9
    X10 = 10
    X11 = 11
    X12 = 12
    X13 = 13
    X14 = 14
    X15 = 15
    X16 = 16
    X17 = 17
    X18 = 18
    X19 = 19
    X20 = 20
    X21 = 21
    X22 = 22
    X23 = 23
    X24 = 24
    X25 = 25
    X26 = 26
    X27 = 27
    X28 = 28
    X29 = 29  # FP
    X30 = 30  # LR
    SP = 31
    PC = 32
    PSTATE = 33


@dataclass
class ArchRegisterInfo:
    """Architecture-specific register information."""

    num_registers: int
    register_size: int  # in bytes
    reg_enum: type[IntEnum] | None = None

    @property
    def pr_reg_size(self) -> int:
        """Size of the pr_reg array in bytes."""
        return self.num_registers * self.register_size


# Architecture register configurations
ARCH_REGISTER_INFO: dict[str, ArchRegisterInfo] = {
    "x86_64": ArchRegisterInfo(27, 8, X86_64Reg),
    "aarch64": ArchRegisterInfo(34, 8, AArch64Reg),
    "arm64": ArchRegisterInfo(34, 8, AArch64Reg),
    # s390x has 16 GPRs + PSW (2 * 8 bytes) + 16 access regs + 16 control regs
    "s390x": ArchRegisterInfo(32, 8, None),
    # ppc64 has 32 GPRs + special registers
    "ppc64le": ArchRegisterInfo(48, 8, None),
    "ppc64": ArchRegisterInfo(48, 8, None),
    # RISC-V has 32 GPRs + PC
    "riscv64": ArchRegisterInfo(33, 8, None),
}


@dataclass
class CpuContext:
    """
    CPU context for a single processor.

    This represents the register state at the time of the crash.
    """

    cpu_id: int = 0
    pid: int = 0
    registers: dict[str, int] = field(default_factory=dict)

    # Signal information
    si_signo: int = 0
    si_code: int = 0
    si_errno: int = 0

    # Process IDs
    pr_pid: int = 0
    pr_ppid: int = 0
    pr_pgrp: int = 0
    pr_sid: int = 0

    # Times (in jiffies/clock ticks)
    pr_utime_sec: int = 0
    pr_utime_usec: int = 0
    pr_stime_sec: int = 0
    pr_stime_usec: int = 0
    pr_cutime_sec: int = 0
    pr_cutime_usec: int = 0
    pr_cstime_sec: int = 0
    pr_cstime_usec: int = 0


def pack_prstatus(ctx: CpuContext, arch: str, endianness: ElfData) -> bytes:
    """
    Pack a prstatus structure for the given architecture.

    The prstatus structure format (for 64-bit):
        struct elf_prstatus {
            struct elf_siginfo pr_info;      // 12 bytes
            short pr_cursig;                 // 2 bytes
            unsigned long pr_sigpend;        // 8 bytes
            unsigned long pr_sighold;        // 8 bytes
            pid_t pr_pid;                    // 4 bytes
            pid_t pr_ppid;                   // 4 bytes
            pid_t pr_pgrp;                   // 4 bytes
            pid_t pr_sid;                    // 4 bytes
            struct timeval pr_utime;         // 16 bytes
            struct timeval pr_stime;         // 16 bytes
            struct timeval pr_cutime;        // 16 bytes
            struct timeval pr_cstime;        // 16 bytes
            elf_gregset_t pr_reg;            // varies by arch
            int pr_fpvalid;                  // 4 bytes
        };

    Args:
        ctx: CPU context with register values
        arch: Architecture name
        endianness: Little or big endian

    Returns:
        Packed prstatus structure as bytes
    """
    if arch not in ARCH_REGISTER_INFO:
        raise ValueError(f"Unsupported architecture for CPU context: {arch}")

    reg_info = ARCH_REGISTER_INFO[arch]
    fmt_prefix = "<" if endianness == ElfData.ELFDATA2LSB else ">"

    parts = []

    # pr_info (elf_siginfo) - 12 bytes: si_signo, si_code, si_errno
    parts.append(
        struct.pack(f"{fmt_prefix}iii", ctx.si_signo, ctx.si_code, ctx.si_errno)
    )

    # pr_cursig - 2 bytes + 2 bytes padding (to align pr_sigpend)
    parts.append(struct.pack(f"{fmt_prefix}hxx", ctx.si_signo))

    # pr_sigpend, pr_sighold - 8 bytes each
    parts.append(struct.pack(f"{fmt_prefix}QQ", 0, 0))

    # pr_pid, pr_ppid, pr_pgrp, pr_sid - 4 bytes each
    pr_pid = ctx.pr_pid if ctx.pr_pid else ctx.pid
    parts.append(
        struct.pack(f"{fmt_prefix}iiii", pr_pid, ctx.pr_ppid, ctx.pr_pgrp, ctx.pr_sid)
    )

    # pr_utime, pr_stime, pr_cutime, pr_cstime - struct timeval (16 bytes each on 64-bit)
    parts.append(struct.pack(f"{fmt_prefix}qq", ctx.pr_utime_sec, ctx.pr_utime_usec))
    parts.append(struct.pack(f"{fmt_prefix}qq", ctx.pr_stime_sec, ctx.pr_stime_usec))
    parts.append(struct.pack(f"{fmt_prefix}qq", ctx.pr_cutime_sec, ctx.pr_cutime_usec))
    parts.append(struct.pack(f"{fmt_prefix}qq", ctx.pr_cstime_sec, ctx.pr_cstime_usec))

    # pr_reg - register array
    reg_array = [0] * reg_info.num_registers

    # Fill in registers from the context
    if reg_info.reg_enum:
        for name, value in ctx.registers.items():
            name_upper = name.upper()
            # Try to find the register in the enum
            try:
                reg_idx = reg_info.reg_enum[name_upper]
                reg_array[reg_idx] = value
            except KeyError:
                # Register name not found, try without prefix
                pass
    else:
        # For architectures without detailed enum, just use numeric indices
        for name, value in ctx.registers.items():
            if name.isdigit():
                idx = int(name)
                if idx < reg_info.num_registers:
                    reg_array[idx] = value

    # Pack registers
    reg_format = f"{fmt_prefix}{reg_info.num_registers}Q"
    parts.append(struct.pack(reg_format, *reg_array))

    # pr_fpvalid - 4 bytes
    parts.append(struct.pack(f"{fmt_prefix}i", 0))

    return b"".join(parts)


def get_prstatus_size(arch: str) -> int:
    """
    Get the size of the prstatus structure for an architecture.

    Args:
        arch: Architecture name

    Returns:
        Size in bytes
    """
    if arch not in ARCH_REGISTER_INFO:
        raise ValueError(f"Unsupported architecture: {arch}")

    reg_info = ARCH_REGISTER_INFO[arch]

    # Fixed parts:
    # pr_info: 12 bytes
    # pr_cursig + padding: 4 bytes
    # pr_sigpend + pr_sighold: 16 bytes
    # pr_pid + pr_ppid + pr_pgrp + pr_sid: 16 bytes
    # pr_utime + pr_stime + pr_cutime + pr_cstime: 64 bytes
    # pr_fpvalid: 4 bytes
    fixed_size = 12 + 4 + 16 + 16 + 64 + 4

    return fixed_size + reg_info.pr_reg_size
