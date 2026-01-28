"""
Integration tests using drgn to validate vmcore files.

These tests verify that the generated vmcore files can be opened
and parsed by drgn, a real-world kernel debugging tool.
"""

import os
import tempfile

import pytest

from kdumpling import KdumpBuilder

# Check if drgn is available
try:
    import drgn

    DRGN_AVAILABLE = True
except ImportError:
    DRGN_AVAILABLE = False


# Minimum vmcoreinfo required by drgn
MINIMAL_VMCOREINFO_X86_64 = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffffffff82a00000
"""

MINIMAL_VMCOREINFO_AARCH64 = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffff800000000000
"""

MINIMAL_VMCOREINFO_S390X = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=0000000000000000
"""


@pytest.mark.skipif(not DRGN_AVAILABLE, reason="drgn not installed")
class TestDrgnIntegration:
    """Integration tests using drgn."""

    def test_drgn_opens_vmcore(self) -> None:
        """Test that drgn can open a basic vmcore."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(MINIMAL_VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            prog = drgn.Program()
            prog.set_core_dump(output_path)

            # Verify basic properties
            assert prog.platform is not None
            assert prog.platform.arch == drgn.Architecture.X86_64
        finally:
            os.unlink(output_path)

    def test_drgn_detects_linux_kernel(self) -> None:
        """Test that drgn recognizes the vmcore as a Linux kernel dump."""
        vmcoreinfo = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffffffff82a00000
"""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(vmcoreinfo)
        builder.add_memory_segment(phys_addr=0x0, data=b"\x00" * 4096)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            prog = drgn.Program()
            prog.set_core_dump(output_path)

            # Check that drgn recognizes this as a Linux kernel dump
            assert drgn.ProgramFlags.IS_LINUX_KERNEL in prog.flags
        finally:
            os.unlink(output_path)

    def test_drgn_platform_detection(self) -> None:
        """Test that drgn correctly detects the platform for different architectures."""
        test_cases = [
            ("x86_64", drgn.Architecture.X86_64, MINIMAL_VMCOREINFO_X86_64),
            ("aarch64", drgn.Architecture.AARCH64, MINIMAL_VMCOREINFO_AARCH64),
        ]

        for arch, expected_drgn_arch, vmcoreinfo in test_cases:
            builder = KdumpBuilder(arch=arch)
            builder.set_vmcoreinfo(vmcoreinfo)
            builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)

            with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
                output_path = f.name

            try:
                builder.write(output_path)

                prog = drgn.Program()
                prog.set_core_dump(output_path)

                assert prog.platform.arch == expected_drgn_arch, (
                    f"Expected {expected_drgn_arch} for {arch}, "
                    f"got {prog.platform.arch}"
                )
            finally:
                os.unlink(output_path)

    def test_drgn_with_cpu_context(self) -> None:
        """Test that drgn can open vmcore with CPU context notes."""
        vmcoreinfo = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffffffff82a00000
"""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(vmcoreinfo)
        builder.add_cpu_context(
            cpu_id=0,
            registers={
                "RIP": 0xFFFFFFFF81001234,
                "RSP": 0xFFFF888000001000,
                "RBP": 0xFFFF888000002000,
            },
            pid=1,
        )
        builder.add_cpu_context(
            cpu_id=1,
            registers={"RIP": 0xFFFFFFFF81005678},
            pid=2,
        )
        builder.add_memory_segment(phys_addr=0x0, data=b"\x00" * 4096)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            prog = drgn.Program()
            prog.set_core_dump(output_path)

            # drgn should still open successfully with CPU context
            assert prog.platform.arch == drgn.Architecture.X86_64
            assert drgn.ProgramFlags.IS_LINUX_KERNEL in prog.flags
        finally:
            os.unlink(output_path)

    def test_drgn_with_complete_vmcoreinfo(self) -> None:
        """Test drgn with a more complete vmcoreinfo that includes common fields."""
        vmcoreinfo = """OSRELEASE=5.14.0-362.el9.x86_64
PAGESIZE=4096
SYMBOL(init_task)=ffffffff82413440
SYMBOL(swapper_pg_dir)=ffffffff82a00000
SYMBOL(_stext)=ffffffff81000000
SYMBOL(vmemmap_base)=ffffea0000000000
SYMBOL(page_offset_base)=ffff888000000000
LENGTH(mem_section)=8192
SIZE(mem_section)=16
SIZE(page)=64
SIZE(list_head)=16
SIZE(pt_regs)=168
OFFSET(list_head.next)=0
OFFSET(list_head.prev)=8
NUMBER(KERNELOFFSET)=0
NUMBER(phys_base)=0
NUMBER(MAX_PHYSMEM_BITS)=52
NUMBER(kimage_voffset)=0xffffffff80000000
NUMBER(KERNEL_IMAGE_SIZE)=0x40000000
"""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(vmcoreinfo)
        builder.add_cpu_context(cpu_id=0, registers={"RIP": 0xFFFFFFFF81000000}, pid=0)
        builder.add_memory_segment(phys_addr=0x0, data=b"\x00" * 4096)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            prog = drgn.Program()
            prog.set_core_dump(output_path)

            # Verify the vmcore is recognized correctly
            assert prog.platform.arch == drgn.Architecture.X86_64
            assert drgn.ProgramFlags.IS_LINUX_KERNEL in prog.flags

            # Verify platform flags
            platform_flags = prog.platform.flags
            assert drgn.PlatformFlags.IS_64_BIT in platform_flags
            assert drgn.PlatformFlags.IS_LITTLE_ENDIAN in platform_flags
        finally:
            os.unlink(output_path)

    def test_drgn_endianness_detection(self) -> None:
        """Test that drgn correctly detects endianness for little-endian architectures."""
        # Little endian (x86_64)
        builder_le = KdumpBuilder(arch="x86_64")
        builder_le.set_vmcoreinfo(MINIMAL_VMCOREINFO_X86_64)
        builder_le.add_memory_segment(phys_addr=0x1000, data=b"\x00" * 64)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path_le = f.name

        try:
            builder_le.write(output_path_le)

            prog_le = drgn.Program()
            prog_le.set_core_dump(output_path_le)

            assert drgn.PlatformFlags.IS_LITTLE_ENDIAN in prog_le.platform.flags
            assert drgn.PlatformFlags.IS_64_BIT in prog_le.platform.flags
        finally:
            os.unlink(output_path_le)

        # Also test aarch64 (little endian)
        builder_arm = KdumpBuilder(arch="aarch64")
        builder_arm.set_vmcoreinfo(MINIMAL_VMCOREINFO_AARCH64)
        builder_arm.add_memory_segment(phys_addr=0x1000, data=b"\x00" * 64)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path_arm = f.name

        try:
            builder_arm.write(output_path_arm)

            prog_arm = drgn.Program()
            prog_arm.set_core_dump(output_path_arm)

            assert drgn.PlatformFlags.IS_LITTLE_ENDIAN in prog_arm.platform.flags
            assert drgn.PlatformFlags.IS_64_BIT in prog_arm.platform.flags
        finally:
            os.unlink(output_path_arm)
