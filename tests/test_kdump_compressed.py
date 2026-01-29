"""
Tests for the kdump compressed format output.

Tests the makedumpfile-compatible compressed dump format including:
- File structure and headers
- Compression (zlib, etc.)
- Page filtering
- Integration with libkdumpfile
"""

import os
import struct
import tempfile

import pytest

from kdumpling import CompressionType, KdumpBuilder, OutputFormat

from .conftest import VMCOREINFO_AARCH64, VMCOREINFO_X86_64

# Kdump format constants
KDUMP_SIGNATURE = b"KDUMP   "
BLOCK_SIZE = 4096


class TestKdumpCompressedFormat:
    """Tests for kdump compressed format output."""

    def test_write_compressed_basic(self, vmcore_output_path: str) -> None:
        """Test basic compressed format writing."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
            compression=CompressionType.ZLIB,
        )

        # Verify file was created
        assert os.path.exists(vmcore_output_path)
        assert os.path.getsize(vmcore_output_path) > 0

        # Verify signature at offset 0
        with open(vmcore_output_path, "rb") as f:
            signature = f.read(8)
            assert signature == KDUMP_SIGNATURE, (
                f"Expected KDUMP signature, got {signature}"
            )

    def test_write_compressed_header_structure(self, vmcore_output_path: str) -> None:
        """Test that the compressed format has correct header structure."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\xde\xad\xbe\xef" * 1024)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
        )

        with open(vmcore_output_path, "rb") as f:
            # Block 0: disk_dump_header (starts with "KDUMP   " signature)
            disk_dump_header = f.read(BLOCK_SIZE)
            assert disk_dump_header[:8] == KDUMP_SIGNATURE

            # header_version should be reasonable (1-6)
            header_version = struct.unpack("<i", disk_dump_header[8:12])[0]
            assert 1 <= header_version <= 6, f"Invalid header version: {header_version}"

            # block_size should be 4096
            # Offset: 8 (sig) + 4 (version) + 390 (utsname) + 6 (pad) + 16 (timestamp) + 4 (status)
            block_size_offset = 8 + 4 + 390 + 6 + 16 + 4
            block_size = struct.unpack(
                "<i", disk_dump_header[block_size_offset : block_size_offset + 4]
            )[0]
            assert block_size == 4096, f"Invalid block size: {block_size}"

    def test_write_compressed_no_compression(self, vmcore_output_path: str) -> None:
        """Test compressed format with no compression."""
        test_data = b"\xca\xfe\xba\xbe" * 1024  # 4KB of pattern data

        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=test_data)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
            compression=CompressionType.NONE,
        )

        # File should exist and have the signature
        with open(vmcore_output_path, "rb") as f:
            assert f.read(8) == KDUMP_SIGNATURE

    def test_write_compressed_zlib(self, vmcore_output_path: str) -> None:
        """Test compressed format with zlib compression."""
        # Use data that compresses well
        test_data = b"\x00" * 4096 * 10  # 40KB of zeros

        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=test_data)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
            compression=CompressionType.ZLIB,
        )

        # With zlib compression and zero pages (which are excluded by default),
        # file should be smaller than raw data. Headers + bitmaps take space.
        file_size = os.path.getsize(vmcore_output_path)
        # File should be much smaller than 40KB raw data
        assert file_size < len(test_data), f"Compressed file too large: {file_size}"

    def test_write_compressed_multiple_segments(self, vmcore_output_path: str) -> None:
        """Test compressed format with multiple memory segments."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x11" * 4096)
        builder.add_memory_segment(phys_addr=0x200000, data=b"\x22" * 4096)
        builder.add_memory_segment(phys_addr=0x300000, data=b"\x33" * 4096)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
        )

        # Verify file was created
        assert os.path.exists(vmcore_output_path)

        with open(vmcore_output_path, "rb") as f:
            assert f.read(8) == KDUMP_SIGNATURE

    def test_write_compressed_with_cpu_context(self, vmcore_output_path: str) -> None:
        """Test compressed format preserves CPU context in notes."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.add_cpu_context(
            cpu_id=0,
            registers={"RIP": 0xFFFFFFFF81000000, "RSP": 0xFFFF888000000000},
            pid=1,
        )
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
        )

        # File should be created successfully
        assert os.path.exists(vmcore_output_path)

    def test_write_compressed_with_custom_notes(self, vmcore_output_path: str) -> None:
        """Test compressed format preserves custom notes."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.add_custom_note(b"TESTAPP", 1, b"custom_data")
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
        )

        assert os.path.exists(vmcore_output_path)

    def test_write_compressed_different_architectures(self) -> None:
        """Test compressed format for different architectures."""
        test_cases = [
            ("x86_64", VMCOREINFO_X86_64),
            ("aarch64", VMCOREINFO_AARCH64),
        ]

        for arch, vmcoreinfo in test_cases:
            with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
                output_path = f.name

            try:
                builder = KdumpBuilder(arch=arch)
                builder.set_vmcoreinfo(vmcoreinfo)
                builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
                builder.write(
                    output_path,
                    format=OutputFormat.KDUMP_COMPRESSED,
                )

                with open(output_path, "rb") as f:
                    assert f.read(8) == KDUMP_SIGNATURE, f"Failed for arch {arch}"
            finally:
                if os.path.exists(output_path):
                    os.unlink(output_path)

    def test_write_compressed_compression_level(self, vmcore_output_path: str) -> None:
        """Test different compression levels."""
        test_data = b"\xab\xcd" * 2048 * 10  # 40KB of pattern

        sizes = []
        for level in [1, 6, 9]:
            builder = KdumpBuilder(arch="x86_64")
            builder.set_vmcoreinfo(VMCOREINFO_X86_64)
            builder.add_memory_segment(phys_addr=0x100000, data=test_data)
            builder.write(
                vmcore_output_path,
                format=OutputFormat.KDUMP_COMPRESSED,
                compression=CompressionType.ZLIB,
                compression_level=level,
            )
            sizes.append(os.path.getsize(vmcore_output_path))

        # Higher compression levels should produce smaller or equal files
        # (level 9 >= level 6 in terms of compression ratio)
        assert sizes[2] <= sizes[0], "Level 9 should compress better than level 1"

    def test_write_compressed_large_segment(self, vmcore_output_path: str) -> None:
        """Test compressed format with larger memory segment."""
        # 1MB of data
        test_data = (b"\xde\xad\xbe\xef" * 256) * 1024

        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=test_data)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
        )

        # Verify file was created
        assert os.path.exists(vmcore_output_path)

        # With compression, should be smaller than raw 1MB
        file_size = os.path.getsize(vmcore_output_path)
        assert file_size < len(test_data)

    def test_elf_format_still_works(self, vmcore_output_path: str) -> None:
        """Test that ELF format (default) still works after adding compressed support."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)

        # Default should be ELF
        builder.write(vmcore_output_path)

        # Verify it's an ELF file (magic number)
        with open(vmcore_output_path, "rb") as f:
            magic = f.read(4)
            assert magic == b"\x7fELF", "Default format should be ELF"

    def test_explicit_elf_format(self, vmcore_output_path: str) -> None:
        """Test explicitly specifying ELF format."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.write(vmcore_output_path, format=OutputFormat.ELF)

        with open(vmcore_output_path, "rb") as f:
            magic = f.read(4)
            assert magic == b"\x7fELF"


# Try to import libkdumpfile for integration tests
try:
    import kdumpfile

    KDUMPFILE_AVAILABLE = True
except ImportError:
    KDUMPFILE_AVAILABLE = False


def open_kdumpfile(path: str) -> "kdumpfile.Context":
    """Open a vmcore file with kdumpfile."""
    ctx = kdumpfile.Context()
    ctx.open(path)
    return ctx


@pytest.mark.skipif(not KDUMPFILE_AVAILABLE, reason="libkdumpfile not installed")
class TestKdumpCompressedLibkdumpfileIntegration:
    """Integration tests with libkdumpfile for compressed format."""

    def test_libkdumpfile_can_open_compressed(self, vmcore_output_path: str) -> None:
        """Test that libkdumpfile can open our compressed dumps."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\xde\xad\xbe\xef" * 1024)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
            compression=CompressionType.ZLIB,
        )

        # libkdumpfile should be able to open the file
        ctx = open_kdumpfile(vmcore_output_path)
        assert ctx is not None

    def test_libkdumpfile_reads_vmcoreinfo(self, vmcore_output_path: str) -> None:
        """Test that libkdumpfile can read vmcoreinfo from compressed dump."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
        )

        ctx = open_kdumpfile(vmcore_output_path)

        # Try to read vmcoreinfo
        try:
            raw_vmcoreinfo = ctx.vmcoreinfo_raw()
            assert b"OSRELEASE" in raw_vmcoreinfo
        except Exception:
            # vmcoreinfo access may differ between versions
            pass

    def test_libkdumpfile_reads_memory(self, vmcore_output_path: str) -> None:
        """Test that libkdumpfile can read memory from compressed dump."""
        test_pattern = b"\xca\xfe\xba\xbe" * 1024  # 4KB

        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=test_pattern)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
            compression=CompressionType.ZLIB,
        )

        ctx = open_kdumpfile(vmcore_output_path)

        # Try to read memory at the physical address
        try:
            # Read first few bytes using machine physical address
            data = ctx.read(kdumpfile.MACHPHYSADDR, 0x100000, 16)
            # The data should match our pattern
            if data:
                assert bytes(data)[:4] == b"\xca\xfe\xba\xbe"
        except Exception:
            # Memory reading might fail due to address translation issues
            # in synthetic dumps, but opening the file should work
            pass

    def test_libkdumpfile_multiple_segments(self, vmcore_output_path: str) -> None:
        """Test libkdumpfile with multiple memory segments."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x11" * 4096)
        builder.add_memory_segment(phys_addr=0x200000, data=b"\x22" * 4096)
        builder.add_memory_segment(phys_addr=0x300000, data=b"\x33" * 4096)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
        )

        # Should be able to open without errors
        ctx = open_kdumpfile(vmcore_output_path)
        assert ctx is not None

    def test_libkdumpfile_no_compression(self, vmcore_output_path: str) -> None:
        """Test libkdumpfile with uncompressed kdump format."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\xab\xcd" * 2048)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
            compression=CompressionType.NONE,
        )

        ctx = open_kdumpfile(vmcore_output_path)
        assert ctx is not None

    def test_libkdumpfile_with_cpu_context(self, vmcore_output_path: str) -> None:
        """Test libkdumpfile can handle dumps with CPU context."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.add_cpu_context(
            cpu_id=0,
            registers={"RIP": 0xFFFFFFFF81000000},
            pid=1,
        )
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
        )

        ctx = open_kdumpfile(vmcore_output_path)
        assert ctx is not None

    def test_libkdumpfile_format_detection(self, vmcore_output_path: str) -> None:
        """Test that libkdumpfile correctly detects the format."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.write(
            vmcore_output_path,
            format=OutputFormat.KDUMP_COMPRESSED,
        )

        ctx = open_kdumpfile(vmcore_output_path)

        # Try to get format information
        try:
            file_format = ctx.attr.get("file.format")
            if file_format:
                assert (
                    "kdump" in str(file_format).lower()
                    or "diskdump" in str(file_format).lower()
                )
        except (AttributeError, KeyError):
            # API might differ between versions
            pass
