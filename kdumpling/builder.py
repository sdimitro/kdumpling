"""
KdumpBuilder - Main class for building Linux kdump vmcore files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import BinaryIO

from .elf import (
    ARCHITECTURES,
    ELF64_EHDR_SIZE,
    ELF64_PHDR_SIZE,
    ArchInfo,
    PhdrFlags,
    PhdrType,
    pack_elf64_ehdr,
    pack_elf64_phdr,
    pack_elf_note,
)

# VMCOREINFO note type used by Linux kernel
# This is a custom note type (not standard ELF)
VMCOREINFO_NOTE_NAME = b"VMCOREINFO"
VMCOREINFO_NOTE_TYPE = 0


@dataclass
class MemorySegment:
    """Represents a memory segment to be included in the dump."""

    phys_addr: int
    data: bytes | str | BinaryIO
    size: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.data, bytes):
            self.size = len(self.data)
        elif isinstance(self.data, str):
            # It's a file path
            self.size = os.path.getsize(self.data)
        elif hasattr(self.data, "seek") and hasattr(self.data, "tell"):
            # It's a file-like object, get size
            current_pos = self.data.tell()
            self.data.seek(0, 2)  # Seek to end
            self.size = self.data.tell()
            self.data.seek(current_pos)  # Restore position

    def get_data(self) -> bytes:
        """Read and return the segment data as bytes."""
        if isinstance(self.data, bytes):
            return self.data
        elif isinstance(self.data, str):
            with open(self.data, "rb") as f:
                return f.read()
        else:
            # File-like object
            current_pos = self.data.tell()
            self.data.seek(0)
            data = self.data.read()
            self.data.seek(current_pos)
            return data

    def write_to(self, output: BinaryIO) -> None:
        """Stream the segment data to an output file."""
        if isinstance(self.data, bytes):
            output.write(self.data)
        elif isinstance(self.data, str):
            with open(self.data, "rb") as f:
                # Stream in chunks to handle large files
                while True:
                    chunk = f.read(1024 * 1024)  # 1MB chunks
                    if not chunk:
                        break
                    output.write(chunk)
        else:
            # File-like object
            current_pos = self.data.tell()
            self.data.seek(0)
            while True:
                chunk = self.data.read(1024 * 1024)
                if not chunk:
                    break
                output.write(chunk)
            self.data.seek(current_pos)


@dataclass
class KdumpBuilder:
    """
    Builder for creating Linux kdump vmcore files.

    A vmcore is an ELF64 core dump file containing:
    - ELF header identifying it as a core dump
    - Program headers describing memory segments
    - A PT_NOTE segment with VMCOREINFO metadata
    - PT_LOAD segments with the actual memory data

    Example usage:
        builder = KdumpBuilder(arch='x86_64')
        builder.set_vmcoreinfo("OSRELEASE=5.14.0\\nPAGE_SIZE=4096\\n")
        builder.add_memory_segment(phys_addr=0x100000, data=memory_bytes)
        builder.write("output.vmcore")
    """

    arch: str = "x86_64"
    _vmcoreinfo: bytes = field(default=b"", init=False)
    _segments: list[MemorySegment] = field(default_factory=list, init=False)
    _arch_info: ArchInfo = field(init=False)

    def __post_init__(self) -> None:
        if self.arch not in ARCHITECTURES:
            supported = ", ".join(sorted(ARCHITECTURES.keys()))
            raise ValueError(
                f"Unsupported architecture: {self.arch}. Supported: {supported}"
            )
        self._arch_info = ARCHITECTURES[self.arch]

    def set_vmcoreinfo(self, data: str | bytes) -> KdumpBuilder:
        """
        Set the VMCOREINFO metadata string.

        This is typically the content from /sys/kernel/vmcoreinfo or
        /proc/vmcore-info on a running Linux system.

        Args:
            data: The vmcoreinfo string (e.g., "OSRELEASE=5.14.0\\nPAGE_SIZE=4096\\n")

        Returns:
            self for method chaining
        """
        if isinstance(data, str):
            self._vmcoreinfo = data.encode("utf-8")
        else:
            self._vmcoreinfo = data
        return self

    def add_memory_segment(
        self, phys_addr: int, data: bytes | str | BinaryIO
    ) -> KdumpBuilder:
        """
        Add a memory segment to the dump.

        Args:
            phys_addr: The physical address where this memory resides
            data: The memory data. Can be:
                  - bytes: Raw memory content
                  - str: Path to a file containing the data
                  - BinaryIO: File-like object to read from

        Returns:
            self for method chaining
        """
        segment = MemorySegment(phys_addr=phys_addr, data=data)
        self._segments.append(segment)
        return self

    def _build_notes_section(self) -> bytes:
        """Build the PT_NOTE section containing VMCOREINFO."""
        notes = bytearray()

        # Add VMCOREINFO note
        if self._vmcoreinfo:
            note = pack_elf_note(
                self._arch_info.endianness,
                VMCOREINFO_NOTE_NAME,
                VMCOREINFO_NOTE_TYPE,
                self._vmcoreinfo,
            )
            notes.extend(note)

        return bytes(notes)

    def write(self, output_path: str) -> None:
        """
        Write the vmcore file to disk.

        Args:
            output_path: Path where the vmcore file will be written
        """
        endianness = self._arch_info.endianness
        machine = self._arch_info.machine

        # Build the notes section first to know its size
        notes_data = self._build_notes_section()

        # Calculate number of program headers:
        # - 1 for PT_NOTE (if we have vmcoreinfo)
        # - N for PT_LOAD (one per memory segment)
        has_notes = len(notes_data) > 0
        phdr_count = (1 if has_notes else 0) + len(self._segments)

        # Calculate offsets
        ehdr_size = ELF64_EHDR_SIZE
        phdr_offset = ehdr_size
        phdr_table_size = phdr_count * ELF64_PHDR_SIZE

        # Notes come right after program headers
        notes_offset = phdr_offset + phdr_table_size

        # Memory segments come after notes
        data_offset = notes_offset + len(notes_data)

        # Build ELF header
        ehdr = pack_elf64_ehdr(
            machine=machine,
            endianness=endianness,
            phdr_count=phdr_count,
            phdr_offset=phdr_offset,
        )

        # Build program headers
        phdrs = bytearray()

        # PT_NOTE header (if we have notes)
        if has_notes:
            note_phdr = pack_elf64_phdr(
                endianness=endianness,
                p_type=PhdrType.PT_NOTE,
                p_flags=PhdrFlags.PF_R,
                p_offset=notes_offset,
                p_vaddr=0,
                p_paddr=0,
                p_filesz=len(notes_data),
                p_memsz=len(notes_data),
                p_align=4,
            )
            phdrs.extend(note_phdr)

        # PT_LOAD headers for each memory segment
        current_offset = data_offset
        for segment in self._segments:
            load_phdr = pack_elf64_phdr(
                endianness=endianness,
                p_type=PhdrType.PT_LOAD,
                p_flags=PhdrFlags.PF_R | PhdrFlags.PF_W,
                p_offset=current_offset,
                p_vaddr=0,  # Not used for physical memory dumps
                p_paddr=segment.phys_addr,
                p_filesz=segment.size,
                p_memsz=segment.size,
                p_align=self._arch_info.page_size,
            )
            phdrs.extend(load_phdr)
            current_offset += segment.size

        # Write everything to file
        with open(output_path, "wb") as f:
            # 1. ELF header
            f.write(ehdr)

            # 2. Program headers
            f.write(phdrs)

            # 3. Notes section
            f.write(notes_data)

            # 4. Memory segment data
            for segment in self._segments:
                segment.write_to(f)
