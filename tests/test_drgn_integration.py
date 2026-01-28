"""
Integration tests using drgn to validate vmcore files.

These tests verify that the generated vmcore files can be opened
and parsed by drgn, a real-world kernel debugging tool.
"""

import pytest

from kdumpling import KdumpBuilder

from .conftest import (
    VMCOREINFO_AARCH64,
    VMCOREINFO_FULL_X86_64,
    VMCOREINFO_X86_64,
)

# Check if drgn is available
try:
    import drgn

    DRGN_AVAILABLE = True
except ImportError:
    DRGN_AVAILABLE = False


@pytest.mark.skipif(not DRGN_AVAILABLE, reason="drgn not installed")
class TestDrgnIntegration:
    """Integration tests using drgn."""

    def test_drgn_opens_vmcore(self, vmcore_output_path: str) -> None:
        """Test that drgn can open a basic vmcore."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.write(vmcore_output_path)

        prog = drgn.Program()
        prog.set_core_dump(vmcore_output_path)

        # Verify basic properties
        assert prog.platform is not None
        assert prog.platform.arch == drgn.Architecture.X86_64

    def test_drgn_detects_linux_kernel(self, vmcore_output_path: str) -> None:
        """Test that drgn recognizes the vmcore as a Linux kernel dump."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x0, data=b"\x00" * 4096)
        builder.write(vmcore_output_path)

        prog = drgn.Program()
        prog.set_core_dump(vmcore_output_path)

        # Check that drgn recognizes this as a Linux kernel dump
        assert drgn.ProgramFlags.IS_LINUX_KERNEL in prog.flags

    def test_drgn_platform_detection(self, vmcore_output_path: str) -> None:
        """Test that drgn correctly detects the platform for different architectures."""
        test_cases = [
            ("x86_64", drgn.Architecture.X86_64, VMCOREINFO_X86_64),
            ("aarch64", drgn.Architecture.AARCH64, VMCOREINFO_AARCH64),
        ]

        for arch, expected_drgn_arch, vmcoreinfo in test_cases:
            builder = KdumpBuilder(arch=arch)
            builder.set_vmcoreinfo(vmcoreinfo)
            builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
            builder.write(vmcore_output_path)

            prog = drgn.Program()
            prog.set_core_dump(vmcore_output_path)

            assert prog.platform.arch == expected_drgn_arch, (
                f"Expected {expected_drgn_arch} for {arch}, got {prog.platform.arch}"
            )

    def test_drgn_with_cpu_context(self, vmcore_output_path: str) -> None:
        """Test that drgn can open vmcore with CPU context notes."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
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
        builder.write(vmcore_output_path)

        prog = drgn.Program()
        prog.set_core_dump(vmcore_output_path)

        # drgn should still open successfully with CPU context
        assert prog.platform.arch == drgn.Architecture.X86_64
        assert drgn.ProgramFlags.IS_LINUX_KERNEL in prog.flags

    def test_drgn_with_complete_vmcoreinfo(self, vmcore_output_path: str) -> None:
        """Test drgn with a more complete vmcoreinfo that includes common fields."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_FULL_X86_64)
        builder.add_cpu_context(cpu_id=0, registers={"RIP": 0xFFFFFFFF81000000}, pid=0)
        builder.add_memory_segment(phys_addr=0x0, data=b"\x00" * 4096)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.write(vmcore_output_path)

        prog = drgn.Program()
        prog.set_core_dump(vmcore_output_path)

        # Verify the vmcore is recognized correctly
        assert prog.platform.arch == drgn.Architecture.X86_64
        assert drgn.ProgramFlags.IS_LINUX_KERNEL in prog.flags

        # Verify platform flags
        platform_flags = prog.platform.flags
        assert drgn.PlatformFlags.IS_64_BIT in platform_flags
        assert drgn.PlatformFlags.IS_LITTLE_ENDIAN in platform_flags

    def test_drgn_endianness_detection(self, vmcore_output_path: str) -> None:
        """Test that drgn correctly detects endianness for little-endian architectures."""
        # Little endian (x86_64)
        builder_le = KdumpBuilder(arch="x86_64")
        builder_le.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder_le.add_memory_segment(phys_addr=0x1000, data=b"\x00" * 64)
        builder_le.write(vmcore_output_path)

        prog_le = drgn.Program()
        prog_le.set_core_dump(vmcore_output_path)

        assert drgn.PlatformFlags.IS_LITTLE_ENDIAN in prog_le.platform.flags
        assert drgn.PlatformFlags.IS_64_BIT in prog_le.platform.flags

        # Also test aarch64 (little endian)
        builder_arm = KdumpBuilder(arch="aarch64")
        builder_arm.set_vmcoreinfo(VMCOREINFO_AARCH64)
        builder_arm.add_memory_segment(phys_addr=0x1000, data=b"\x00" * 64)
        builder_arm.write(vmcore_output_path)

        prog_arm = drgn.Program()
        prog_arm.set_core_dump(vmcore_output_path)

        assert drgn.PlatformFlags.IS_LITTLE_ENDIAN in prog_arm.platform.flags
        assert drgn.PlatformFlags.IS_64_BIT in prog_arm.platform.flags
