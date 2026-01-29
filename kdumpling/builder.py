"""
KdumpBuilder - Main class for building Linux kdump vmcore files.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import IntEnum
from typing import BinaryIO

from .cpu_context import CpuContext, NoteType, get_prstatus_size, pack_prstatus
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

# Note name for CPU core dumps
CORE_NOTE_NAME = b"CORE"

# Default vendor name for custom notes
DEFAULT_NOTE_VENDOR = b"KDUMPLING"


class OutputFormat(IntEnum):
    """Output format for vmcore files."""

    ELF = 0  # Standard ELF64 vmcore (default)
    KDUMP_COMPRESSED = 1  # Kdump compressed format (makedumpfile compatible)


class CompressionType(IntEnum):
    """Compression algorithms for kdump compressed format."""

    NONE = 0  # No compression (dump level filtering only)
    ZLIB = 1  # zlib/gzip compression
    LZO = 2  # LZO compression
    SNAPPY = 4  # Snappy compression
    ZSTD = 8  # Zstandard compression


class CustomNoteType(IntEnum):
    """Predefined custom note types for kdumpling metadata.

    Users can also use any integer value for custom types.
    """

    METADATA = 1  # Hash/signature information
    ANNOTATIONS = 2  # Custom key-value annotations
    FILE_INFO = 3  # File description information
    USER_DEFINED = 256  # Start of user-defined range


@dataclass
class CustomNote:
    """
    A custom ELF note to be included in the vmcore.

    Custom notes allow users to embed additional metadata in their
    vmcore files, such as hashes, timestamps, annotations, or any
    other application-specific data.

    The note is identified by a (name, type) tuple. Using a unique
    vendor name (like "KDUMPLING" or your company name) prevents
    conflicts with other tools.

    Example:
        note = CustomNote(
            name=b"KDUMPLING",
            note_type=CustomNoteType.METADATA,
            data=b"sha256=abc123..."
        )
    """

    name: bytes  # Vendor/namespace identifier (e.g., b"KDUMPLING")
    note_type: int  # Note type (see CustomNoteType for predefined values)
    data: bytes  # Note descriptor data


def _format_size(size_bytes: int) -> str:
    """Format a size in bytes to a human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


@dataclass
class DumpStats:
    """
    Statistics about a vmcore dump being built.

    Provides information about the dump's contents and estimated size.
    """

    architecture: str
    num_memory_segments: int
    num_cpu_contexts: int
    total_memory_size: int
    vmcoreinfo_size: int
    estimated_file_size: int
    memory_segments: list[tuple[int, int, int]]  # List of (phys_addr, virt_addr, size)

    @property
    def total_memory_size_human(self) -> str:
        """Total memory size in human-readable format."""
        return _format_size(self.total_memory_size)

    @property
    def estimated_file_size_human(self) -> str:
        """Estimated file size in human-readable format."""
        return _format_size(self.estimated_file_size)

    def __str__(self) -> str:
        """Return a formatted string representation of the stats."""
        lines = [
            "Dump Statistics:",
            f"  Architecture: {self.architecture}",
            f"  Memory Segments: {self.num_memory_segments}",
            f"  CPU Contexts: {self.num_cpu_contexts}",
            f"  Total Memory: {self.total_memory_size_human} ({self.total_memory_size} bytes)",
            f"  VMCOREINFO Size: {self.vmcoreinfo_size} bytes",
            f"  Estimated File Size: {self.estimated_file_size_human}",
        ]
        if self.memory_segments:
            lines.append("  Segments:")
            for phys_addr, virt_addr, size in self.memory_segments:
                if phys_addr == virt_addr:
                    lines.append(f"    0x{phys_addr:016x}: {_format_size(size)}")
                else:
                    lines.append(
                        f"    phys=0x{phys_addr:016x} virt=0x{virt_addr:016x}: "
                        f"{_format_size(size)}"
                    )
        return "\n".join(lines)


@dataclass
class MemorySegment:
    """Represents a memory segment to be included in the dump.

    Attributes:
        phys_addr: Physical memory address where this segment resides
        data: The memory data (bytes, file path, or file-like object)
        virt_addr: Virtual memory address (optional, defaults to phys_addr if None)
        size: Size of the segment in bytes (computed automatically)
    """

    phys_addr: int
    data: bytes | str | BinaryIO
    virt_addr: int | None = None
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

    @property
    def effective_virt_addr(self) -> int:
        """Return the virtual address to use (virt_addr if set, otherwise phys_addr)."""
        return self.virt_addr if self.virt_addr is not None else self.phys_addr

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

    The builder also supports the kdump compressed format (makedumpfile
    compatible), which provides per-page compression and filtering.

    Example usage:
        builder = KdumpBuilder(arch='x86_64')
        builder.set_vmcoreinfo("OSRELEASE=5.14.0\\nPAGE_SIZE=4096\\n")
        builder.add_memory_segment(phys_addr=0x100000, data=memory_bytes)
        builder.write("output.vmcore")

    For custom metadata:
        builder.add_custom_note(
            name=b"MYAPP",
            note_type=1,
            data=b"version=1.0"
        )
    """

    arch: str = "x86_64"
    _vmcoreinfo: bytes = field(default=b"", init=False)
    _segments: list[MemorySegment] = field(default_factory=list, init=False)
    _cpu_contexts: list[CpuContext] = field(default_factory=list, init=False)
    _custom_notes: list[CustomNote] = field(default_factory=list, init=False)
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
        self,
        phys_addr: int,
        data: bytes | str | BinaryIO,
        virt_addr: int | None = None,
    ) -> KdumpBuilder:
        """
        Add a memory segment to the dump.

        Args:
            phys_addr: The physical address where this memory resides
            data: The memory data. Can be:
                  - bytes: Raw memory content
                  - str: Path to a file containing the data
                  - BinaryIO: File-like object to read from
            virt_addr: Optional virtual address for this segment. If not specified,
                       defaults to the physical address. This is useful for tools
                       like drgn that need to read memory by virtual address.

        Returns:
            self for method chaining

        Example:
            # Physical address only (virt_addr defaults to phys_addr)
            builder.add_memory_segment(phys_addr=0x100000, data=memory_bytes)

            # With explicit virtual address (for kernel memory mappings)
            builder.add_memory_segment(
                phys_addr=0x100000,
                data=memory_bytes,
                virt_addr=0xffff888000100000
            )
        """
        segment = MemorySegment(phys_addr=phys_addr, data=data, virt_addr=virt_addr)
        self._segments.append(segment)
        return self

    def add_cpu_context(
        self,
        cpu_id: int = 0,
        registers: dict[str, int] | None = None,
        pid: int = 0,
        **kwargs: int,
    ) -> KdumpBuilder:
        """
        Add CPU register state for a processor.

        This creates an NT_PRSTATUS note containing the CPU's register
        state at the time of the crash. This is useful for tools like
        crash and gdb to show backtraces.

        Args:
            cpu_id: CPU identifier (0-indexed)
            registers: Dictionary mapping register names to values.
                       For x86_64: RIP, RSP, RBP, RAX, RBX, etc.
                       For aarch64: X0-X30, SP, PC, PSTATE
            pid: Process ID associated with this CPU
            **kwargs: Additional prstatus fields (pr_ppid, pr_pgrp, etc.)

        Returns:
            self for method chaining

        Example:
            builder.add_cpu_context(
                cpu_id=0,
                registers={'RIP': 0xffffffff81000000, 'RSP': 0xffff888000000000},
                pid=1
            )
        """
        ctx = CpuContext(
            cpu_id=cpu_id,
            pid=pid,
            registers=registers or {},
            pr_pid=kwargs.get("pr_pid", pid),
            pr_ppid=kwargs.get("pr_ppid", 0),
            pr_pgrp=kwargs.get("pr_pgrp", 0),
            pr_sid=kwargs.get("pr_sid", 0),
            si_signo=kwargs.get("si_signo", 0),
            si_code=kwargs.get("si_code", 0),
            si_errno=kwargs.get("si_errno", 0),
        )
        self._cpu_contexts.append(ctx)
        return self

    def add_custom_note(
        self,
        name: bytes | str,
        note_type: int,
        data: bytes | str,
    ) -> KdumpBuilder:
        """
        Add a custom ELF note to the vmcore.

        Custom notes are stored in the PT_NOTE segment alongside
        standard notes like VMCOREINFO and NT_PRSTATUS. Tools that
        don't recognize the note type will safely ignore it.

        Args:
            name: Vendor/namespace identifier (e.g., b"KDUMPLING" or "MYAPP").
                  Using a unique name prevents conflicts with other tools.
            note_type: Numeric type identifier. See CustomNoteType for
                       predefined values, or use any integer.
            data: The note data. Can be bytes or a string (will be UTF-8 encoded).

        Returns:
            self for method chaining

        Example:
            builder.add_custom_note(
                name=b"KDUMPLING",
                note_type=CustomNoteType.METADATA,
                data=b"sha256=abc123..."
            )
        """
        if isinstance(name, str):
            name = name.encode("utf-8")
        if isinstance(data, str):
            data = data.encode("utf-8")

        note = CustomNote(name=name, note_type=note_type, data=data)
        self._custom_notes.append(note)
        return self

    def add_metadata(
        self,
        data: dict[str, str] | bytes | str,
        vendor: bytes | str = DEFAULT_NOTE_VENDOR,
    ) -> KdumpBuilder:
        """
        Add metadata to the vmcore.

        This is a convenience method for adding key-value metadata
        using the METADATA note type.

        Args:
            data: Metadata to add. Can be:
                  - dict: Key-value pairs (converted to "key=value\\n" format)
                  - bytes/str: Raw metadata content
            vendor: Vendor name for the note (default: "KDUMPLING")

        Returns:
            self for method chaining

        Example:
            builder.add_metadata({
                "sha256": "abc123...",
                "created_at": "2024-01-28T10:30:00Z",
                "source": "memory_forensics_tool"
            })
        """
        if isinstance(data, dict):
            lines = [f"{k}={v}" for k, v in data.items()]
            data_bytes = "\n".join(lines).encode("utf-8")
        elif isinstance(data, str):
            data_bytes = data.encode("utf-8")
        else:
            data_bytes = data

        return self.add_custom_note(
            name=vendor,
            note_type=CustomNoteType.METADATA,
            data=data_bytes,
        )

    def add_annotations(
        self,
        annotations: dict[str, str],
        vendor: bytes | str = DEFAULT_NOTE_VENDOR,
    ) -> KdumpBuilder:
        """
        Add custom annotations to the vmcore.

        Annotations are free-form key-value pairs that can be used
        to attach contextual information to the dump.

        Args:
            annotations: Dictionary of annotation key-value pairs
            vendor: Vendor name for the note (default: "KDUMPLING")

        Returns:
            self for method chaining

        Example:
            builder.add_annotations({
                "hostname": "prod-server-01",
                "kernel_panic_reason": "out of memory",
                "captured_by": "crash_collector v2.1"
            })
        """
        lines = [f"{k}={v}" for k, v in annotations.items()]
        data = "\n".join(lines).encode("utf-8")

        return self.add_custom_note(
            name=vendor,
            note_type=CustomNoteType.ANNOTATIONS,
            data=data,
        )

    @property
    def stats(self) -> DumpStats:
        """
        Get statistics about the dump being built.

        Returns:
            DumpStats object with information about segments, size, etc.

        Example:
            builder = KdumpBuilder()
            builder.add_memory_segment(0x1000, b"\\x00" * 4096)
            print(builder.stats)
            # Dump Statistics:
            #   Architecture: x86_64
            #   Memory Segments: 1
            #   ...
        """
        # Calculate total memory size
        total_memory = sum(seg.size for seg in self._segments)

        # Calculate notes section size
        notes_size = 0
        if self._vmcoreinfo:
            # VMCOREINFO note: header (12 bytes) + name (aligned) + data (aligned)
            name_size = len(VMCOREINFO_NOTE_NAME) + 1  # +1 for null terminator
            name_padded = (name_size + 3) & ~3
            data_padded = (len(self._vmcoreinfo) + 3) & ~3
            notes_size += 12 + name_padded + data_padded

        # NT_PRSTATUS notes
        for _ in self._cpu_contexts:
            prstatus_size = get_prstatus_size(self.arch)
            name_size = len(CORE_NOTE_NAME) + 1
            name_padded = (name_size + 3) & ~3
            data_padded = (prstatus_size + 3) & ~3
            notes_size += 12 + name_padded + data_padded

        # Custom notes
        for note in self._custom_notes:
            name_size = len(note.name) + 1
            name_padded = (name_size + 3) & ~3
            data_padded = (len(note.data) + 3) & ~3
            notes_size += 12 + name_padded + data_padded

        # Calculate estimated file size
        has_notes = notes_size > 0 or len(self._cpu_contexts) > 0
        phdr_count = (1 if has_notes else 0) + len(self._segments)

        estimated_size = (
            ELF64_EHDR_SIZE  # ELF header
            + phdr_count * ELF64_PHDR_SIZE  # Program headers
            + notes_size  # Notes section
            + total_memory  # Memory data
        )

        # Build segment list with (phys_addr, virt_addr, size)
        segment_list = [
            (seg.phys_addr, seg.effective_virt_addr, seg.size) for seg in self._segments
        ]

        return DumpStats(
            architecture=self.arch,
            num_memory_segments=len(self._segments),
            num_cpu_contexts=len(self._cpu_contexts),
            total_memory_size=total_memory,
            vmcoreinfo_size=len(self._vmcoreinfo),
            estimated_file_size=estimated_size,
            memory_segments=segment_list,
        )

    def _build_notes_section(self) -> bytes:
        """Build the PT_NOTE section containing VMCOREINFO and CPU contexts."""
        notes = bytearray()

        # Add NT_PRSTATUS notes for each CPU
        for ctx in self._cpu_contexts:
            prstatus_data = pack_prstatus(ctx, self.arch, self._arch_info.endianness)
            note = pack_elf_note(
                self._arch_info.endianness,
                CORE_NOTE_NAME,
                NoteType.NT_PRSTATUS,
                prstatus_data,
            )
            notes.extend(note)

        # Add VMCOREINFO note
        if self._vmcoreinfo:
            note = pack_elf_note(
                self._arch_info.endianness,
                VMCOREINFO_NOTE_NAME,
                VMCOREINFO_NOTE_TYPE,
                self._vmcoreinfo,
            )
            notes.extend(note)

        # Add custom notes
        for custom_note in self._custom_notes:
            note = pack_elf_note(
                self._arch_info.endianness,
                custom_note.name,
                custom_note.note_type,
                custom_note.data,
            )
            notes.extend(note)

        return bytes(notes)

    def write(
        self,
        output_path: str,
        format: OutputFormat = OutputFormat.ELF,
        compression: CompressionType = CompressionType.ZLIB,
        compression_level: int = 6,
    ) -> None:
        """
        Write the vmcore file to disk.

        Args:
            output_path: Path where the vmcore file will be written
            format: Output format (ELF or KDUMP_COMPRESSED). Default is ELF.
            compression: Compression type for KDUMP_COMPRESSED format.
                         Default is ZLIB. Ignored for ELF format.
            compression_level: Compression level 1-9. Default is 6.
                               Ignored for ELF format.

        Example:
            # Write standard ELF vmcore (default)
            builder.write("output.vmcore")

            # Write kdump compressed format with zlib
            builder.write(
                "output.vmcore",
                format=OutputFormat.KDUMP_COMPRESSED,
                compression=CompressionType.ZLIB
            )
        """
        if format == OutputFormat.KDUMP_COMPRESSED:
            self._write_compressed(output_path, compression, compression_level)
            return

        self._write_elf(output_path)

    def _write_elf(self, output_path: str) -> None:
        """Write the vmcore in standard ELF format."""
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
                p_vaddr=segment.effective_virt_addr,
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

    def _write_compressed(
        self,
        output_path: str,
        compression: CompressionType,
        compression_level: int,
    ) -> None:
        """Write the vmcore in kdump compressed format."""
        from .kdump_compressed import CompressionMethod, write_kdump_compressed

        # Map CompressionType to CompressionMethod
        compression_map = {
            CompressionType.NONE: CompressionMethod.COMPRESS_NONE,
            CompressionType.ZLIB: CompressionMethod.COMPRESS_ZLIB,
            CompressionType.LZO: CompressionMethod.COMPRESS_LZO,
            CompressionType.SNAPPY: CompressionMethod.COMPRESS_SNAPPY,
            CompressionType.ZSTD: CompressionMethod.COMPRESS_ZSTD,
        }
        comp_method = compression_map.get(compression, CompressionMethod.COMPRESS_ZLIB)

        # Build notes section
        notes_data = self._build_notes_section()

        # Extract OSRELEASE from vmcoreinfo if available
        osrelease = ""
        if self._vmcoreinfo:
            for line in self._vmcoreinfo.decode("utf-8", errors="ignore").split("\n"):
                if line.startswith("OSRELEASE="):
                    osrelease = line.split("=", 1)[1].strip()
                    break

        write_kdump_compressed(
            output_path=output_path,
            segments=self._segments,
            vmcoreinfo=self._vmcoreinfo,
            notes_data=notes_data,
            arch_info=self._arch_info,
            compression=comp_method,
            compression_level=compression_level,
            osrelease=osrelease,
        )
