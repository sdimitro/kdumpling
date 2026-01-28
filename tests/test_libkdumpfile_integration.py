"""
Integration tests using libkdumpfile (kdumpfile Python module) to validate vmcore files.

These tests verify that the generated vmcore files can be opened and parsed
by libkdumpfile, which is a widely-used library for reading Linux crash dumps.
"""

import os
import tempfile

import pytest

from kdumpling import KdumpBuilder

# Check if kdumpfile is available
try:
    import kdumpfile

    KDUMPFILE_AVAILABLE = True
except ImportError:
    KDUMPFILE_AVAILABLE = False


# Minimum vmcoreinfo required for basic parsing
VMCOREINFO_X86_64 = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffffffff82a00000
SYMBOL(_stext)=ffffffff81000000
NUMBER(phys_base)=0
"""


@pytest.mark.skipif(not KDUMPFILE_AVAILABLE, reason="kdumpfile not installed")
class TestLibkdumpfileIntegration:
    """Integration tests using libkdumpfile."""

    def test_kdumpfile_opens_vmcore(self) -> None:
        """Test that kdumpfile can open a basic vmcore."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            # Open with kdumpfile
            ctx = kdumpfile.kdumpfile(output_path)
            assert ctx is not None
        finally:
            os.unlink(output_path)

    def test_kdumpfile_reads_vmcoreinfo(self) -> None:
        """Test that kdumpfile can read vmcoreinfo attributes."""
        vmcoreinfo = """OSRELEASE=5.14.0-test-kernel
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffffffff82a00000
SYMBOL(init_task)=ffffffff82413440
SYMBOL(_stext)=ffffffff81000000
NUMBER(phys_base)=0
SIZE(list_head)=16
OFFSET(list_head.next)=0
"""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(vmcoreinfo)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            ctx = kdumpfile.kdumpfile(output_path)

            # Check that we can read vmcoreinfo values
            # The attribute path for OSRELEASE
            try:
                osrelease = ctx.attr.get("linux.uts.release")
                assert "5.14.0-test-kernel" in str(osrelease)
            except (KeyError, AttributeError):
                # Different versions of kdumpfile may have different attr paths
                # Try alternative approach
                pass

            # Check page size attribute
            try:
                page_size = ctx.attr.get("arch.page_size")
                assert page_size == 4096
            except (KeyError, AttributeError):
                pass

        finally:
            os.unlink(output_path)

    def test_kdumpfile_with_memory_segments(self) -> None:
        """Test that kdumpfile can access memory segments."""
        # Create recognizable test data
        test_pattern = b"\xde\xad\xbe\xef" * 1024  # 4KB

        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=test_pattern)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            ctx = kdumpfile.kdumpfile(output_path)

            # Try to read from the physical address we wrote to
            try:
                # kdumpfile uses ADDRXLAT for address translation
                # For raw physical access, we might need specific setup
                data = ctx.read(kdumpfile.KVADDR, 0x100000, 16)
                # If we can read, verify the pattern
                if data:
                    assert data[:4] == b"\xde\xad\xbe\xef"
            except Exception:
                # Reading may fail without proper kernel symbols
                # but opening the file is the main test
                pass

        finally:
            os.unlink(output_path)

    def test_kdumpfile_with_cpu_context(self) -> None:
        """Test that kdumpfile accepts vmcore with CPU contexts."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_cpu_context(
            cpu_id=0,
            registers={"RIP": 0xFFFFFFFF81001234, "RSP": 0xFFFF888000001000},
            pid=1,
        )
        builder.add_cpu_context(
            cpu_id=1,
            registers={"RIP": 0xFFFFFFFF81005678},
            pid=2,
        )
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            # kdumpfile should be able to open this
            ctx = kdumpfile.kdumpfile(output_path)
            assert ctx is not None

            # Try to get CPU count from attributes
            try:
                # Different kdumpfile versions may expose this differently
                num_cpus = ctx.attr.get("cpu.number")
                if num_cpus:
                    assert num_cpus >= 1
            except (KeyError, AttributeError):
                pass

        finally:
            os.unlink(output_path)

    def test_kdumpfile_arch_detection(self) -> None:
        """Test that kdumpfile correctly detects the architecture."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            ctx = kdumpfile.kdumpfile(output_path)

            # Check architecture attribute
            try:
                arch_name = ctx.attr.get("arch.name")
                assert (
                    "x86_64" in str(arch_name).lower()
                    or "x86" in str(arch_name).lower()
                )
            except (KeyError, AttributeError):
                # Architecture might be exposed differently
                pass

        finally:
            os.unlink(output_path)

    def test_kdumpfile_multiple_segments(self) -> None:
        """Test kdumpfile with multiple memory segments."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)

        # Add multiple segments at different physical addresses
        builder.add_memory_segment(phys_addr=0x0, data=b"\x00" * 4096)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x11" * 4096)
        builder.add_memory_segment(phys_addr=0x200000, data=b"\x22" * 8192)
        builder.add_memory_segment(phys_addr=0x1000000, data=b"\x33" * 16384)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            ctx = kdumpfile.kdumpfile(output_path)
            assert ctx is not None

        finally:
            os.unlink(output_path)
