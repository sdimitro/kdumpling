"""
ELF64 constants and structures for building vmcore files.
"""

import struct
from enum import IntEnum
from typing import NamedTuple

# ELF Magic
ELF_MAGIC = b"\x7fELF"


# ELF Class (32-bit vs 64-bit)
class ElfClass(IntEnum):
    ELFCLASS32 = 1
    ELFCLASS64 = 2


# ELF Data Encoding (Endianness)
class ElfData(IntEnum):
    ELFDATA2LSB = 1  # Little endian
    ELFDATA2MSB = 2  # Big endian


# ELF Version
EV_CURRENT = 1

# ELF OS/ABI
ELFOSABI_NONE = 0


# ELF Type
class ElfType(IntEnum):
    ET_NONE = 0
    ET_REL = 1
    ET_EXEC = 2
    ET_DYN = 3
    ET_CORE = 4  # Core dump - this is what we need


# ELF Machine Types
class ElfMachine(IntEnum):
    EM_NONE = 0
    EM_386 = 3
    EM_X86_64 = 62
    EM_ARM = 40
    EM_AARCH64 = 183
    EM_S390 = 22
    EM_PPC64 = 21
    EM_RISCV = 243


# Program Header Types
class PhdrType(IntEnum):
    PT_NULL = 0
    PT_LOAD = 1
    PT_NOTE = 4


# Program Header Flags
class PhdrFlags(IntEnum):
    PF_X = 0x1  # Execute
    PF_W = 0x2  # Write
    PF_R = 0x4  # Read


# Note Types
class NoteType(IntEnum):
    NT_PRSTATUS = 1
    NT_PRFPREG = 2
    NT_PRPSINFO = 3


# ELF64 Header size: 64 bytes
ELF64_EHDR_SIZE = 64

# ELF64 Program Header size: 56 bytes
ELF64_PHDR_SIZE = 56


class ArchInfo(NamedTuple):
    """Architecture-specific information."""

    machine: ElfMachine
    endianness: ElfData
    page_size: int = 4096


# Supported architectures
ARCHITECTURES = {
    "x86_64": ArchInfo(ElfMachine.EM_X86_64, ElfData.ELFDATA2LSB),
    "aarch64": ArchInfo(ElfMachine.EM_AARCH64, ElfData.ELFDATA2LSB),
    "arm64": ArchInfo(ElfMachine.EM_AARCH64, ElfData.ELFDATA2LSB),  # alias
    "s390x": ArchInfo(ElfMachine.EM_S390, ElfData.ELFDATA2MSB),
    "ppc64le": ArchInfo(ElfMachine.EM_PPC64, ElfData.ELFDATA2LSB),
    "ppc64": ArchInfo(ElfMachine.EM_PPC64, ElfData.ELFDATA2MSB),
    "riscv64": ArchInfo(ElfMachine.EM_RISCV, ElfData.ELFDATA2LSB),
}


def pack_elf64_ehdr(
    machine: ElfMachine, endianness: ElfData, phdr_count: int, phdr_offset: int
) -> bytes:
    """
    Pack an ELF64 header for a core dump.

    Args:
        machine: Target architecture (e.g., EM_X86_64)
        endianness: Little or big endian
        phdr_count: Number of program headers
        phdr_offset: File offset to program headers

    Returns:
        64 bytes representing the ELF64 header
    """
    # Determine struct format based on endianness
    fmt_prefix = "<" if endianness == ElfData.ELFDATA2LSB else ">"

    # e_ident (16 bytes)
    e_ident = bytearray(16)
    e_ident[0:4] = ELF_MAGIC
    e_ident[4] = ElfClass.ELFCLASS64
    e_ident[5] = endianness
    e_ident[6] = EV_CURRENT
    e_ident[7] = ELFOSABI_NONE
    # Rest is padding (already zeros)

    # Pack the rest of the header
    # Format: HHIQQQIHHHHHH
    # H = uint16, I = uint32, Q = uint64
    header_data = struct.pack(
        f"{fmt_prefix}HHIQQQIHHHHHH",
        ElfType.ET_CORE,  # e_type (2 bytes)
        machine,  # e_machine (2 bytes)
        EV_CURRENT,  # e_version (4 bytes)
        0,  # e_entry (8 bytes) - not used for core dumps
        phdr_offset,  # e_phoff (8 bytes) - program header offset
        0,  # e_shoff (8 bytes) - no section headers
        0,  # e_flags (4 bytes)
        ELF64_EHDR_SIZE,  # e_ehsize (2 bytes)
        ELF64_PHDR_SIZE,  # e_phentsize (2 bytes)
        phdr_count,  # e_phnum (2 bytes)
        0,  # e_shentsize (2 bytes) - no sections
        0,  # e_shnum (2 bytes) - no sections
        0,  # e_shstrndx (2 bytes) - no section string table
    )

    return bytes(e_ident) + header_data


def pack_elf64_phdr(
    endianness: ElfData,
    p_type: PhdrType,
    p_flags: int,
    p_offset: int,
    p_vaddr: int,
    p_paddr: int,
    p_filesz: int,
    p_memsz: int,
    p_align: int = 0,
) -> bytes:
    """
    Pack an ELF64 program header.

    Args:
        endianness: Little or big endian
        p_type: Segment type (PT_LOAD, PT_NOTE, etc.)
        p_flags: Segment flags (read/write/execute)
        p_offset: File offset of segment data
        p_vaddr: Virtual address
        p_paddr: Physical address
        p_filesz: Size in file
        p_memsz: Size in memory
        p_align: Alignment

    Returns:
        56 bytes representing the program header
    """
    fmt_prefix = "<" if endianness == ElfData.ELFDATA2LSB else ">"

    # ELF64 Phdr format: IIQQQQQQ
    return struct.pack(
        f"{fmt_prefix}IIQQQQQQ",
        p_type,  # p_type (4 bytes)
        p_flags,  # p_flags (4 bytes)
        p_offset,  # p_offset (8 bytes)
        p_vaddr,  # p_vaddr (8 bytes)
        p_paddr,  # p_paddr (8 bytes)
        p_filesz,  # p_filesz (8 bytes)
        p_memsz,  # p_memsz (8 bytes)
        p_align,  # p_align (8 bytes)
    )


def pack_elf_note(
    endianness: ElfData, name: bytes, note_type: int, desc: bytes
) -> bytes:
    """
    Pack an ELF note entry.

    Notes have the format:
    - namesz (4 bytes): length of name including null terminator
    - descsz (4 bytes): length of descriptor
    - type (4 bytes): note type
    - name (namesz bytes, padded to 4-byte boundary)
    - desc (descsz bytes, padded to 4-byte boundary)

    Args:
        endianness: Little or big endian
        name: Note name (without null terminator)
        note_type: Note type identifier
        desc: Note descriptor data

    Returns:
        The packed note entry
    """
    fmt_prefix = "<" if endianness == ElfData.ELFDATA2LSB else ">"

    # Add null terminator to name
    name_with_null = name + b"\x00"
    namesz = len(name_with_null)
    descsz = len(desc)

    # Calculate padding to 4-byte alignment
    def align4(size: int) -> int:
        return (size + 3) & ~3

    name_padded = name_with_null.ljust(align4(namesz), b"\x00")
    desc_padded = desc.ljust(align4(descsz), b"\x00")

    header = struct.pack(f"{fmt_prefix}III", namesz, descsz, note_type)

    return header + name_padded + desc_padded
