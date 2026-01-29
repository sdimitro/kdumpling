"""
Kdump compressed format (makedumpfile compatible) structures and utilities.

This module implements the kdump compressed dump format used by makedumpfile
and supported by tools like crash, libkdumpfile, and drgn.

The format provides:
- Per-page compression (zlib, lzo, snappy, zstd)
- Page filtering (exclude zero pages, cache, user pages, etc.)
- Efficient storage with bitmap-based indexing

File structure (per makedumpfile specification):
    Offset 0x0000: disk_dump_header (with "KDUMP   " signature)
    Offset 0x1000: kdump_sub_header
    Offset 0x2000: 1st bitmap (valid memory pages)
    Offset varies: 2nd bitmap (dumped pages)
    Offset varies: Page descriptors
    Offset varies: Compressed page data
    Offset varies: vmcoreinfo (offset stored in sub_header)
    Offset varies: notes data (offset stored in sub_header)
"""

from __future__ import annotations

import struct
import time
import zlib
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .builder import MemorySegment
    from .elf import ArchInfo, ElfData


# =============================================================================
# Constants
# =============================================================================

# Signatures
KDUMP_SIGNATURE = b"KDUMP   "  # 8 bytes, space-padded
MAKEDUMPFILE_SIGNATURE = b"makedumpfile"

# Block size (4KB aligned)
BLOCK_SIZE = 4096

# Header sizes
DISK_DUMP_HEADER_SIZE = 4096  # Padded to block boundary
KDUMP_SUB_HEADER_SIZE = 4096  # Padded to block boundary

# Page descriptor size
PAGE_DESCRIPTOR_SIZE = 24  # sizeof(page_desc)


class DumpLevel(IntFlag):
    """Dump levels for page filtering (compatible with makedumpfile).

    These can be combined with | operator.
    """

    DL_NONE = 0  # Dump all pages
    DL_EXCLUDE_ZERO = 1  # Exclude zero-filled pages
    DL_EXCLUDE_CACHE = 2  # Exclude cache pages
    DL_EXCLUDE_CACHE_PRIVATE = 4  # Exclude private cache pages
    DL_EXCLUDE_USER = 8  # Exclude user pages
    DL_EXCLUDE_FREE = 16  # Exclude free pages


class DumpHeaderVersion(IntEnum):
    """Dump header version numbers."""

    VERSION_1 = 1  # Original version
    VERSION_2 = 2  # Added split support
    VERSION_3 = 3  # Added offset_vmcoreinfo, size_vmcoreinfo
    VERSION_4 = 4  # Added offset_note, size_note
    VERSION_5 = 5  # Added offset_eraseinfo, size_eraseinfo
    VERSION_6 = 6  # Added start_pfn_64, end_pfn_64, max_mapnr_64


class CompressionMethod(IntEnum):
    """Compression method flags stored in status field."""

    COMPRESS_NONE = 0
    COMPRESS_ZLIB = 1
    COMPRESS_LZO = 2
    COMPRESS_SNAPPY = 4
    COMPRESS_ZSTD = 8


# Architecture identifiers used in disk_dump_header
# These match the values in makedumpfile
ARCH_X86_64 = 62  # EM_X86_64
ARCH_AARCH64 = 183  # EM_AARCH64
ARCH_S390X = 22  # EM_S390
ARCH_PPC64 = 21  # EM_PPC64
ARCH_RISCV64 = 243  # EM_RISCV


# =============================================================================
# Data structures
# =============================================================================


@dataclass
class DiskDumpHeader:
    """
    disk_dump_header structure.

    This is the primary header at offset 0x1000 in the file.

    struct disk_dump_header {
        char    signature[8];       // "KDUMP   "
        int     header_version;     // Version number
        struct  new_utsname utsname; // System info (65 * 6 = 390 bytes)
        char    _pad1[2];           // Padding
        struct  timeval timestamp;  // Time of dump
        unsigned int status;        // Compression flags
        int     block_size;         // Block size (usually 4096)
        int     sub_hdr_size;       // Size of sub-header in blocks
        unsigned int bitmap_blocks; // Size of bitmap in blocks
        unsigned int max_mapnr;     // Max page frame number (32-bit)
        unsigned int total_ram_blocks; // Total RAM in blocks
        unsigned int device_blocks; // Device blocks (split dumps)
        unsigned int written_blocks; // Blocks written
        unsigned int current_cpu;   // CPU that made the dump
        int     nr_cpus;            // Number of CPUs
        struct  task_struct *tasks[0]; // Per-CPU task pointers
    };
    """

    signature: bytes = KDUMP_SIGNATURE
    header_version: int = DumpHeaderVersion.VERSION_6
    # utsname fields (each 65 bytes)
    sysname: bytes = b"Linux"
    nodename: bytes = b""
    release: bytes = b""
    version: bytes = b""
    machine: bytes = b""
    domainname: bytes = b""
    timestamp_sec: int = 0
    timestamp_usec: int = 0
    status: int = 0  # Compression flags
    block_size: int = BLOCK_SIZE
    sub_hdr_size: int = 1  # In blocks
    bitmap_blocks: int = 0
    max_mapnr: int = 0  # 32-bit max page frame number
    total_ram_blocks: int = 0
    device_blocks: int = 0
    written_blocks: int = 0
    current_cpu: int = 0
    nr_cpus: int = 1

    def pack(self, endianness: ElfData) -> bytes:
        """Pack the header into bytes."""
        from .elf import ElfData

        fmt_prefix = "<" if endianness == ElfData.ELFDATA2LSB else ">"

        # Start building the header
        data = bytearray(DISK_DUMP_HEADER_SIZE)

        offset = 0

        # signature (8 bytes)
        data[offset : offset + 8] = self.signature.ljust(8, b"\x00")[:8]
        offset += 8

        # header_version (4 bytes)
        struct.pack_into(f"{fmt_prefix}i", data, offset, self.header_version)
        offset += 4

        # utsname structure (6 fields * 65 bytes = 390 bytes)
        utsname_fields = [
            self.sysname,
            self.nodename,
            self.release,
            self.version,
            self.machine,
            self.domainname,
        ]
        for field in utsname_fields:
            field_bytes = field if isinstance(field, bytes) else field.encode("utf-8")
            data[offset : offset + 65] = field_bytes.ljust(65, b"\x00")[:65]
            offset += 65

        # _pad1[6] - 6 bytes of padding for 64-bit alignment
        # (libkdumpfile disk_dump_header_64 requires this)
        offset += 6

        # timestamp (2 * 8 bytes = 16 bytes for 64-bit timeval)
        # libkdumpfile's disk_dump_header_64 uses struct timeval_64
        struct.pack_into(
            f"{fmt_prefix}qq", data, offset, self.timestamp_sec, self.timestamp_usec
        )
        offset += 16

        # status (4 bytes)
        struct.pack_into(f"{fmt_prefix}I", data, offset, self.status)
        offset += 4

        # block_size (4 bytes)
        struct.pack_into(f"{fmt_prefix}i", data, offset, self.block_size)
        offset += 4

        # sub_hdr_size (4 bytes)
        struct.pack_into(f"{fmt_prefix}i", data, offset, self.sub_hdr_size)
        offset += 4

        # bitmap_blocks (4 bytes)
        struct.pack_into(f"{fmt_prefix}I", data, offset, self.bitmap_blocks)
        offset += 4

        # max_mapnr (4 bytes)
        struct.pack_into(f"{fmt_prefix}I", data, offset, self.max_mapnr)
        offset += 4

        # total_ram_blocks (4 bytes)
        struct.pack_into(f"{fmt_prefix}I", data, offset, self.total_ram_blocks)
        offset += 4

        # device_blocks (4 bytes)
        struct.pack_into(f"{fmt_prefix}I", data, offset, self.device_blocks)
        offset += 4

        # written_blocks (4 bytes)
        struct.pack_into(f"{fmt_prefix}I", data, offset, self.written_blocks)
        offset += 4

        # current_cpu (4 bytes)
        struct.pack_into(f"{fmt_prefix}I", data, offset, self.current_cpu)
        offset += 4

        # nr_cpus (4 bytes)
        struct.pack_into(f"{fmt_prefix}i", data, offset, self.nr_cpus)
        offset += 4

        return bytes(data)


@dataclass
class KdumpSubHeader:
    """
    kdump_sub_header structure.

    This is at offset 0x2000 in the file.

    struct kdump_sub_header {
        unsigned long   phys_base;
        int             dump_level;
        int             split;
        unsigned long   start_pfn;
        unsigned long   end_pfn;
        off_t           offset_vmcoreinfo;
        unsigned long   size_vmcoreinfo;
        off_t           offset_note;
        unsigned long   size_note;
        off_t           offset_eraseinfo;
        unsigned long   size_eraseinfo;
        unsigned long long  start_pfn_64;
        unsigned long long  end_pfn_64;
        unsigned long long  max_mapnr_64;
    };
    """

    phys_base: int = 0
    dump_level: int = 0
    split: int = 0
    start_pfn: int = 0
    end_pfn: int = 0
    offset_vmcoreinfo: int = 0
    size_vmcoreinfo: int = 0
    offset_note: int = 0
    size_note: int = 0
    offset_eraseinfo: int = 0
    size_eraseinfo: int = 0
    start_pfn_64: int = 0
    end_pfn_64: int = 0
    max_mapnr_64: int = 0

    def pack(self, endianness: ElfData) -> bytes:
        """Pack the sub-header into bytes."""
        from .elf import ElfData

        fmt_prefix = "<" if endianness == ElfData.ELFDATA2LSB else ">"

        data = bytearray(KDUMP_SUB_HEADER_SIZE)

        offset = 0

        # phys_base (8 bytes)
        struct.pack_into(f"{fmt_prefix}Q", data, offset, self.phys_base)
        offset += 8

        # dump_level (4 bytes)
        struct.pack_into(f"{fmt_prefix}i", data, offset, self.dump_level)
        offset += 4

        # split (4 bytes)
        struct.pack_into(f"{fmt_prefix}i", data, offset, self.split)
        offset += 4

        # start_pfn (8 bytes)
        struct.pack_into(f"{fmt_prefix}Q", data, offset, self.start_pfn)
        offset += 8

        # end_pfn (8 bytes)
        struct.pack_into(f"{fmt_prefix}Q", data, offset, self.end_pfn)
        offset += 8

        # offset_vmcoreinfo (8 bytes)
        struct.pack_into(f"{fmt_prefix}q", data, offset, self.offset_vmcoreinfo)
        offset += 8

        # size_vmcoreinfo (8 bytes)
        struct.pack_into(f"{fmt_prefix}Q", data, offset, self.size_vmcoreinfo)
        offset += 8

        # offset_note (8 bytes)
        struct.pack_into(f"{fmt_prefix}q", data, offset, self.offset_note)
        offset += 8

        # size_note (8 bytes)
        struct.pack_into(f"{fmt_prefix}Q", data, offset, self.size_note)
        offset += 8

        # offset_eraseinfo (8 bytes)
        struct.pack_into(f"{fmt_prefix}q", data, offset, self.offset_eraseinfo)
        offset += 8

        # size_eraseinfo (8 bytes)
        struct.pack_into(f"{fmt_prefix}Q", data, offset, self.size_eraseinfo)
        offset += 8

        # start_pfn_64 (8 bytes)
        struct.pack_into(f"{fmt_prefix}Q", data, offset, self.start_pfn_64)
        offset += 8

        # end_pfn_64 (8 bytes)
        struct.pack_into(f"{fmt_prefix}Q", data, offset, self.end_pfn_64)
        offset += 8

        # max_mapnr_64 (8 bytes)
        struct.pack_into(f"{fmt_prefix}Q", data, offset, self.max_mapnr_64)
        offset += 8

        return bytes(data)


@dataclass
class PageDescriptor:
    """
    page_desc structure describing a single page.

    struct page_desc {
        off_t   offset;         // File offset of page data
        unsigned int    size;   // Size of compressed data (or page_size if not compressed)
        unsigned int    flags;  // Page flags (compression type, etc.)
        unsigned long long  page_flags; // Kernel page flags
    };
    """

    offset: int = 0
    size: int = 0
    flags: int = 0
    page_flags: int = 0

    def pack(self, endianness: ElfData) -> bytes:
        """Pack the page descriptor into bytes."""
        from .elf import ElfData

        fmt_prefix = "<" if endianness == ElfData.ELFDATA2LSB else ">"

        return struct.pack(
            f"{fmt_prefix}qIIQ",  # off_t, uint, uint, uint64
            self.offset,
            self.size,
            self.flags,
            self.page_flags,
        )


# Page descriptor flags
PD_COMPRESSED = 0x01  # Page is compressed
PD_ZERO = 0x02  # Page is all zeros (not stored)
PD_DUMPABLE = 0x04  # Page is dumpable


# =============================================================================
# Compression utilities
# =============================================================================


def compress_page(
    data: bytes, method: CompressionMethod, level: int = 6
) -> tuple[bytes, bool]:
    """
    Compress a page of data.

    Args:
        data: Page data to compress
        method: Compression method to use
        level: Compression level (1-9 for zlib/zstd)

    Returns:
        Tuple of (compressed_data, was_compressed)
        If compression doesn't reduce size, returns original data with False.
    """
    if method == CompressionMethod.COMPRESS_NONE:
        return data, False

    if method == CompressionMethod.COMPRESS_ZLIB:
        compressed = zlib.compress(data, level)
        if len(compressed) < len(data):
            return compressed, True
        return data, False

    if method == CompressionMethod.COMPRESS_LZO:
        try:
            import lzo  # type: ignore[import-not-found]

            compressed = lzo.compress(data)
            if len(compressed) < len(data):
                return compressed, True
            return data, False
        except ImportError:
            # LZO not available, fall back to no compression
            return data, False

    if method == CompressionMethod.COMPRESS_SNAPPY:
        try:
            import snappy  # type: ignore[import-not-found]

            compressed = snappy.compress(data)
            if len(compressed) < len(data):
                return compressed, True
            return data, False
        except ImportError:
            return data, False

    if method == CompressionMethod.COMPRESS_ZSTD:
        try:
            import zstandard as zstd  # type: ignore[import-not-found]

            cctx = zstd.ZstdCompressor(level=level)
            compressed = cctx.compress(data)
            if len(compressed) < len(data):
                return compressed, True
            return data, False
        except ImportError:
            return data, False

    return data, False


def is_zero_page(data: bytes) -> bool:
    """Check if a page is all zeros."""
    return all(b == 0 for b in data)


# =============================================================================
# Writer
# =============================================================================


def write_kdump_compressed(
    output_path: str,
    segments: list[MemorySegment],
    vmcoreinfo: bytes,
    notes_data: bytes,
    arch_info: ArchInfo,
    compression: CompressionMethod = CompressionMethod.COMPRESS_ZLIB,
    dump_level: int = DumpLevel.DL_EXCLUDE_ZERO,
    compression_level: int = 6,
    osrelease: str = "",
) -> None:
    """
    Write a kdump compressed format file.

    Args:
        output_path: Path to write the dump file
        segments: List of memory segments to include
        vmcoreinfo: VMCOREINFO data
        notes_data: Pre-built notes section (NT_PRSTATUS, etc.)
        arch_info: Architecture information
        compression: Compression method to use
        dump_level: Page filtering level
        compression_level: Compression level (1-9)
        osrelease: Kernel release string for header
    """
    page_size = arch_info.page_size
    endianness = arch_info.endianness

    # Calculate max PFN across all segments
    max_pfn = 0
    min_pfn = 0xFFFFFFFFFFFFFFFF
    total_pages = 0

    for seg in segments:
        start_pfn = seg.phys_addr // page_size
        end_pfn = (seg.phys_addr + seg.size + page_size - 1) // page_size
        max_pfn = max(max_pfn, end_pfn)
        min_pfn = min(min_pfn, start_pfn)
        total_pages += (seg.size + page_size - 1) // page_size

    if not segments:
        max_pfn = 0
        min_pfn = 0

    # Calculate bitmap size (1 bit per page, rounded to block boundary)
    bitmap_bits = max_pfn
    bitmap_bytes = (bitmap_bits + 7) // 8
    bitmap_blocks = (bitmap_bytes + BLOCK_SIZE - 1) // BLOCK_SIZE

    # File layout (per makedumpfile specification):
    # Block 0 (0x0000): disk_dump_header (with "KDUMP   " signature)
    # Block 1 (0x1000): kdump_sub_header
    # Block 2 (0x2000): 1st-bitmap (valid pages)
    # Block 2 + X: 2nd-bitmap (dumped pages)
    # After bitmaps (aligned): page descriptors
    # After page descriptors: page data
    # After page data: vmcoreinfo (offset in sub_header)
    # After vmcoreinfo: notes (offset in sub_header)

    # Bitmaps start at block 2
    bitmap_offset = 2 * BLOCK_SIZE

    # We use two bitmaps:
    # 1st bitmap: which pages have valid memory (from segments)
    # 2nd bitmap: which pages are actually dumped (after filtering)
    total_bitmap_blocks = bitmap_blocks * 2

    # Page descriptors come after bitmaps
    pd_offset = bitmap_offset + total_bitmap_blocks * BLOCK_SIZE

    # Build bitmaps
    bitmap1 = bytearray(bitmap_blocks * BLOCK_SIZE)  # Valid pages
    bitmap2 = bytearray(bitmap_blocks * BLOCK_SIZE)  # Dumped pages

    # Mark valid pages in bitmap1
    for seg in segments:
        start_pfn = seg.phys_addr // page_size
        num_pages = (seg.size + page_size - 1) // page_size
        for i in range(num_pages):
            pfn = start_pfn + i
            byte_idx = pfn // 8
            bit_idx = pfn % 8
            if byte_idx < len(bitmap1):
                bitmap1[byte_idx] |= 1 << bit_idx

    # Build page descriptors and data
    page_descriptors: list[PageDescriptor] = []
    page_data_list: list[bytes] = []

    # Current offset for page data (after descriptors - we'll calculate exact offset later)
    # First pass: collect all page data and descriptors
    dumped_page_count = 0

    for seg in segments:
        seg_data = seg.get_data()
        start_pfn = seg.phys_addr // page_size
        num_pages = (seg.size + page_size - 1) // page_size

        for i in range(num_pages):
            pfn = start_pfn + i
            page_offset = i * page_size
            page_end = min(page_offset + page_size, len(seg_data))
            page_bytes = seg_data[page_offset:page_end]

            # Pad to page size if necessary
            if len(page_bytes) < page_size:
                page_bytes = page_bytes + b"\x00" * (page_size - len(page_bytes))

            # Check for zero page
            if (dump_level & DumpLevel.DL_EXCLUDE_ZERO) and is_zero_page(page_bytes):
                # Mark as not dumped in bitmap2
                continue

            # Mark as dumped in bitmap2
            byte_idx = pfn // 8
            bit_idx = pfn % 8
            if byte_idx < len(bitmap2):
                bitmap2[byte_idx] |= 1 << bit_idx

            # Compress the page
            compressed_data, was_compressed = compress_page(
                page_bytes, compression, compression_level
            )

            flags = PD_DUMPABLE
            if was_compressed:
                flags |= PD_COMPRESSED

            pd = PageDescriptor(
                offset=0,  # Will be filled in second pass
                size=len(compressed_data),
                flags=flags,
                page_flags=0,
            )
            page_descriptors.append(pd)
            page_data_list.append(compressed_data)
            dumped_page_count += 1

    # Calculate page data offset (after all descriptors)
    total_descriptors = len(page_descriptors)
    pd_total_size = total_descriptors * PAGE_DESCRIPTOR_SIZE
    pd_blocks = (pd_total_size + BLOCK_SIZE - 1) // BLOCK_SIZE
    if pd_blocks == 0 and total_descriptors > 0:
        pd_blocks = 1

    page_data_offset = pd_offset + pd_blocks * BLOCK_SIZE

    # Second pass: fill in actual offsets
    current_data_offset = page_data_offset
    for pd in page_descriptors:
        pd.offset = current_data_offset
        current_data_offset += pd.size

    # Calculate total page data size
    total_page_data_size = sum(len(d) for d in page_data_list)

    # vmcoreinfo comes after page data (aligned to block boundary)
    vmcoreinfo_size = len(vmcoreinfo)
    vmcoreinfo_offset = page_data_offset + total_page_data_size
    # Align to block boundary
    if vmcoreinfo_offset % BLOCK_SIZE != 0:
        vmcoreinfo_offset = ((vmcoreinfo_offset // BLOCK_SIZE) + 1) * BLOCK_SIZE

    # notes come after vmcoreinfo
    notes_size = len(notes_data)
    if vmcoreinfo_size > 0:
        vmcoreinfo_blocks = (vmcoreinfo_size + BLOCK_SIZE - 1) // BLOCK_SIZE
        notes_offset = vmcoreinfo_offset + vmcoreinfo_blocks * BLOCK_SIZE
    else:
        notes_offset = vmcoreinfo_offset

    # Create headers
    timestamp = int(time.time())

    # Get machine name from arch_info
    machine_name = {
        62: b"x86_64",
        183: b"aarch64",
        22: b"s390x",
        21: b"ppc64",
        243: b"riscv64",
    }.get(arch_info.machine, b"unknown")

    disk_header = DiskDumpHeader(
        signature=KDUMP_SIGNATURE,
        header_version=DumpHeaderVersion.VERSION_6,
        sysname=b"Linux",
        nodename=b"synthetic",
        release=osrelease.encode("utf-8") if osrelease else b"5.14.0-synthetic",
        version=b"#1 SMP",
        machine=machine_name,
        domainname=b"",
        timestamp_sec=timestamp,
        timestamp_usec=0,
        status=compression,
        block_size=page_size,
        sub_hdr_size=1,
        bitmap_blocks=bitmap_blocks,  # Size of ONE bitmap in blocks (not both)
        max_mapnr=min(max_pfn, 0xFFFFFFFF),  # 32-bit field
        total_ram_blocks=dumped_page_count,
        device_blocks=0,
        written_blocks=dumped_page_count,
        current_cpu=0,
        nr_cpus=1,
    )

    sub_header = KdumpSubHeader(
        phys_base=0,
        dump_level=dump_level,
        split=0,
        start_pfn=min_pfn if segments else 0,
        end_pfn=max_pfn,
        offset_vmcoreinfo=vmcoreinfo_offset,
        size_vmcoreinfo=vmcoreinfo_size,
        offset_note=notes_offset if notes_size > 0 else 0,
        size_note=notes_size,
        offset_eraseinfo=0,
        size_eraseinfo=0,
        start_pfn_64=min_pfn if segments else 0,
        end_pfn_64=max_pfn,
        max_mapnr_64=max_pfn,
    )

    # Write the file
    with open(output_path, "wb") as f:
        # Block 0: disk_dump_header (contains "KDUMP   " signature at offset 0)
        f.write(disk_header.pack(endianness))

        # Block 1: kdump_sub_header
        f.write(sub_header.pack(endianness))

        # Block 2+: Bitmaps (must be at block 2 per makedumpfile spec)
        f.seek(bitmap_offset)
        f.write(bitmap1)
        f.write(bitmap2)

        # Page descriptors (aligned to block boundary after bitmaps)
        f.seek(pd_offset)
        for pd in page_descriptors:
            f.write(pd.pack(endianness))

        # Pad descriptors to block boundary
        pd_written = total_descriptors * PAGE_DESCRIPTOR_SIZE
        pd_padding = pd_blocks * BLOCK_SIZE - pd_written
        if pd_padding > 0:
            f.write(b"\x00" * pd_padding)

        # Page data (immediately after descriptors, not aligned)
        f.seek(page_data_offset)
        for page_data in page_data_list:
            f.write(page_data)

        # VMCOREINFO (after page data, aligned to block boundary)
        if vmcoreinfo_size > 0:
            f.seek(vmcoreinfo_offset)
            f.write(vmcoreinfo)

        # Notes (after vmcoreinfo)
        if notes_size > 0:
            f.seek(notes_offset)
            f.write(notes_data)
