"""
Tests for KdumpBuilder using pyelftools for validation.
"""

import io
import os
import tempfile

import pytest
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import NoteSegment

from kdumpling import KdumpBuilder


class TestKdumpBuilder:
    """Tests for the KdumpBuilder class."""

    def test_create_empty_vmcore(self) -> None:
        """Test creating a vmcore with no segments (just header)."""
        builder = KdumpBuilder(arch="x86_64")

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)

                # Verify ELF header
                assert elf.header["e_type"] == "ET_CORE"
                assert elf.header["e_machine"] == "EM_X86_64"
                assert elf.elfclass == 64
                assert elf.little_endian is True
        finally:
            os.unlink(output_path)

    def test_create_vmcore_with_vmcoreinfo(self) -> None:
        """Test creating a vmcore with vmcoreinfo metadata."""
        vmcoreinfo = "OSRELEASE=5.14.0-test\nPAGE_SIZE=4096\nSYMBOL(init_task)=ffffffff82413440\n"

        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(vmcoreinfo)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)

                # Find PT_NOTE segment
                note_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
                ]
                assert len(note_segments) == 1

                note_segment = note_segments[0]
                assert isinstance(note_segment, NoteSegment)

                # Iterate through notes and find VMCOREINFO
                found_vmcoreinfo = False
                for note in note_segment.iter_notes():
                    if note["n_name"] == "VMCOREINFO":
                        found_vmcoreinfo = True
                        # The descriptor should contain our vmcoreinfo string
                        desc = note["n_desc"]
                        if isinstance(desc, bytes):
                            desc_str = desc.decode("utf-8", errors="ignore")
                        else:
                            desc_str = str(desc)
                        assert "OSRELEASE=5.14.0-test" in desc_str
                        assert "PAGE_SIZE=4096" in desc_str

                assert found_vmcoreinfo, "VMCOREINFO note not found"
        finally:
            os.unlink(output_path)

    def test_create_vmcore_with_memory_segment(self) -> None:
        """Test creating a vmcore with a memory segment."""
        test_data = b"\xde\xad\xbe\xef" * 1024  # 4KB of test pattern
        phys_addr = 0x100000  # 1MB physical address

        builder = KdumpBuilder(arch="x86_64")
        builder.add_memory_segment(phys_addr=phys_addr, data=test_data)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)

                # Find PT_LOAD segment
                load_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                ]
                assert len(load_segments) == 1

                load_segment = load_segments[0]
                assert load_segment["p_paddr"] == phys_addr
                assert load_segment["p_filesz"] == len(test_data)
                assert load_segment["p_memsz"] == len(test_data)

                # Verify the actual data
                segment_data = load_segment.data()
                assert segment_data == test_data
        finally:
            os.unlink(output_path)

    def test_create_vmcore_with_multiple_segments(self) -> None:
        """Test creating a vmcore with multiple memory segments."""
        segments_data = [
            (0x100000, b"\x11" * 4096),  # 1MB
            (0x200000, b"\x22" * 8192),  # 2MB
            (0x1000000, b"\x33" * 16384),  # 16MB
        ]

        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo("OSRELEASE=test\n")

        for phys_addr, data in segments_data:
            builder.add_memory_segment(phys_addr=phys_addr, data=data)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)

                # Should have 1 PT_NOTE + 3 PT_LOAD
                all_segments = list(elf.iter_segments())
                note_segments = [s for s in all_segments if s["p_type"] == "PT_NOTE"]
                load_segments = [s for s in all_segments if s["p_type"] == "PT_LOAD"]

                assert len(note_segments) == 1
                assert len(load_segments) == 3

                # Verify each load segment
                for i, load_segment in enumerate(load_segments):
                    expected_paddr, expected_data = segments_data[i]
                    assert load_segment["p_paddr"] == expected_paddr
                    assert load_segment.data() == expected_data
        finally:
            os.unlink(output_path)

    def test_fluent_api(self) -> None:
        """Test that the fluent/chained API works correctly."""
        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            # All methods should return self for chaining
            (
                KdumpBuilder(arch="x86_64")
                .set_vmcoreinfo("TEST=1\n")
                .add_memory_segment(0x1000, b"\x00" * 100)
                .add_memory_segment(0x2000, b"\xff" * 100)
                .write(output_path)
            )

            # Verify file was created
            assert os.path.exists(output_path)
            assert os.path.getsize(output_path) > 0
        finally:
            os.unlink(output_path)

    def test_memory_segment_from_file(self) -> None:
        """Test adding a memory segment from a file path."""
        test_data = b"\xca\xfe\xba\xbe" * 512

        with tempfile.NamedTemporaryFile(delete=False) as data_file:
            data_file.write(test_data)
            data_path = data_file.name

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder = KdumpBuilder(arch="x86_64")
            builder.add_memory_segment(phys_addr=0x100000, data=data_path)
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)
                load_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                ]
                assert len(load_segments) == 1
                assert load_segments[0].data() == test_data
        finally:
            os.unlink(output_path)
            os.unlink(data_path)

    def test_memory_segment_from_file_object(self) -> None:
        """Test adding a memory segment from a file-like object."""
        test_data = b"\xab\xcd\xef\x01" * 256

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            data_io = io.BytesIO(test_data)

            builder = KdumpBuilder(arch="x86_64")
            builder.add_memory_segment(phys_addr=0x100000, data=data_io)
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)
                load_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                ]
                assert len(load_segments) == 1
                assert load_segments[0].data() == test_data
        finally:
            os.unlink(output_path)


class TestArchitectureSupport:
    """Tests for multi-architecture support."""

    @pytest.mark.parametrize(
        "arch,expected_machine,little_endian",
        [
            ("x86_64", "EM_X86_64", True),
            ("aarch64", "EM_AARCH64", True),
            ("arm64", "EM_AARCH64", True),  # alias
            ("s390x", "EM_S390", False),
            ("ppc64le", "EM_PPC64", True),
            ("ppc64", "EM_PPC64", False),
            ("riscv64", "EM_RISCV", True),
        ],
    )
    def test_architecture(
        self, arch: str, expected_machine: str, little_endian: bool
    ) -> None:
        """Test that different architectures produce correct ELF headers."""
        builder = KdumpBuilder(arch=arch)
        builder.set_vmcoreinfo("TEST=1\n")
        builder.add_memory_segment(0x1000, b"\x00" * 64)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)
                assert elf.header["e_type"] == "ET_CORE"
                assert elf.header["e_machine"] == expected_machine
                assert elf.little_endian == little_endian
        finally:
            os.unlink(output_path)

    def test_unsupported_architecture(self) -> None:
        """Test that unsupported architectures raise an error."""
        with pytest.raises(ValueError, match="Unsupported architecture"):
            KdumpBuilder(arch="mips64")


class TestElfStructure:
    """Tests for ELF structure correctness."""

    def test_elf_header_size(self) -> None:
        """Test that ELF header is exactly 64 bytes."""
        builder = KdumpBuilder(arch="x86_64")

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                # Read just the e_ehsize field at offset 52
                f.seek(52)
                import struct

                e_ehsize = struct.unpack("<H", f.read(2))[0]
                assert e_ehsize == 64
        finally:
            os.unlink(output_path)

    def test_program_header_size(self) -> None:
        """Test that program headers are exactly 56 bytes."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo("TEST=1\n")

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                # Read e_phentsize field at offset 54
                f.seek(54)
                import struct

                e_phentsize = struct.unpack("<H", f.read(2))[0]
                assert e_phentsize == 56
        finally:
            os.unlink(output_path)

    def test_note_alignment(self) -> None:
        """Test that notes are properly aligned."""
        # Note entries must be 4-byte aligned
        vmcoreinfo = "A=1\n"  # Short string to test padding

        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(vmcoreinfo)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)
                note_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
                ]
                assert len(note_segments) == 1

                # pyelftools should be able to parse the notes without error
                # if alignment is correct
                notes = list(note_segments[0].iter_notes())
                assert len(notes) == 1
        finally:
            os.unlink(output_path)


class TestCpuContext:
    """Tests for CPU context (NT_PRSTATUS) support."""

    def test_add_single_cpu_context(self) -> None:
        """Test adding a single CPU context."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo("OSRELEASE=test\n")
        builder.add_cpu_context(
            cpu_id=0,
            registers={"RIP": 0xFFFFFFFF81000000, "RSP": 0xFFFF888000000000},
            pid=1,
        )

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)
                note_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
                ]
                assert len(note_segments) == 1

                notes = list(note_segments[0].iter_notes())
                # Should have NT_PRSTATUS + VMCOREINFO
                assert len(notes) == 2

                # Find NT_PRSTATUS note (pyelftools returns string "NT_PRSTATUS")
                prstatus_notes = [n for n in notes if n["n_type"] == "NT_PRSTATUS"]
                assert len(prstatus_notes) == 1
                assert prstatus_notes[0]["n_name"] == "CORE"
        finally:
            os.unlink(output_path)

    def test_add_multiple_cpu_contexts(self) -> None:
        """Test adding multiple CPU contexts (SMP system)."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo("OSRELEASE=test\n")

        # Add 4 CPUs
        for cpu_id in range(4):
            builder.add_cpu_context(
                cpu_id=cpu_id,
                registers={"RIP": 0xFFFFFFFF81000000 + cpu_id * 0x1000},
                pid=cpu_id + 1,
            )

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)
                note_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
                ]
                assert len(note_segments) == 1

                notes = list(note_segments[0].iter_notes())
                # Should have 4 NT_PRSTATUS + 1 VMCOREINFO
                assert len(notes) == 5

                prstatus_notes = [n for n in notes if n["n_type"] == "NT_PRSTATUS"]
                assert len(prstatus_notes) == 4
        finally:
            os.unlink(output_path)

    def test_cpu_context_fluent_api(self) -> None:
        """Test that add_cpu_context supports fluent API."""
        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            (
                KdumpBuilder(arch="x86_64")
                .set_vmcoreinfo("TEST=1\n")
                .add_cpu_context(cpu_id=0, registers={"RIP": 0x1000})
                .add_cpu_context(cpu_id=1, registers={"RIP": 0x2000})
                .add_memory_segment(0x1000, b"\x00" * 100)
                .write(output_path)
            )

            assert os.path.exists(output_path)
            assert os.path.getsize(output_path) > 0
        finally:
            os.unlink(output_path)

    def test_cpu_context_register_enum(self) -> None:
        """Test using register enum for register names."""
        builder = KdumpBuilder(arch="x86_64")

        # Using string names that match the enum
        builder.add_cpu_context(
            cpu_id=0,
            registers={
                "RIP": 0xFFFFFFFF81000000,
                "RSP": 0xFFFF888000000000,
                "RBP": 0xFFFF888000001000,
                "RAX": 0x1234,
                "RBX": 0x5678,
            },
        )

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)
                note_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
                ]
                notes = list(note_segments[0].iter_notes())
                prstatus_notes = [n for n in notes if n["n_type"] == "NT_PRSTATUS"]
                assert len(prstatus_notes) == 1
        finally:
            os.unlink(output_path)

    @pytest.mark.parametrize(
        "arch",
        ["x86_64", "aarch64", "s390x", "ppc64le", "riscv64"],
    )
    def test_cpu_context_architectures(self, arch: str) -> None:
        """Test CPU context for different architectures."""
        builder = KdumpBuilder(arch=arch)
        builder.add_cpu_context(cpu_id=0, registers={}, pid=1)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)
                note_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
                ]
                assert len(note_segments) == 1

                notes = list(note_segments[0].iter_notes())
                prstatus_notes = [n for n in notes if n["n_type"] == "NT_PRSTATUS"]
                assert len(prstatus_notes) == 1
        finally:
            os.unlink(output_path)


class TestDumpStats:
    """Tests for the DumpStats API."""

    def test_stats_empty_builder(self) -> None:
        """Test stats on an empty builder."""
        builder = KdumpBuilder(arch="x86_64")
        stats = builder.stats

        assert stats.architecture == "x86_64"
        assert stats.num_memory_segments == 0
        assert stats.num_cpu_contexts == 0
        assert stats.total_memory_size == 0
        assert stats.vmcoreinfo_size == 0
        assert stats.memory_segments == []

    def test_stats_with_memory_segments(self) -> None:
        """Test stats with memory segments."""
        builder = KdumpBuilder(arch="x86_64")
        builder.add_memory_segment(0x100000, b"\x00" * 4096)
        builder.add_memory_segment(0x200000, b"\x00" * 8192)

        stats = builder.stats

        assert stats.num_memory_segments == 2
        assert stats.total_memory_size == 4096 + 8192
        assert len(stats.memory_segments) == 2
        # Format: (phys_addr, virt_addr, size) - virt_addr defaults to phys_addr
        assert stats.memory_segments[0] == (0x100000, 0x100000, 4096)
        assert stats.memory_segments[1] == (0x200000, 0x200000, 8192)

    def test_stats_with_vmcoreinfo(self) -> None:
        """Test stats with vmcoreinfo."""
        vmcoreinfo = "OSRELEASE=5.14.0\nPAGESIZE=4096\n"
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(vmcoreinfo)

        stats = builder.stats

        assert stats.vmcoreinfo_size == len(vmcoreinfo)

    def test_stats_with_cpu_contexts(self) -> None:
        """Test stats with CPU contexts."""
        builder = KdumpBuilder(arch="x86_64")
        builder.add_cpu_context(cpu_id=0, registers={"RIP": 0x1000})
        builder.add_cpu_context(cpu_id=1, registers={"RIP": 0x2000})
        builder.add_cpu_context(cpu_id=2, registers={"RIP": 0x3000})

        stats = builder.stats

        assert stats.num_cpu_contexts == 3

    def test_stats_estimated_file_size(self) -> None:
        """Test that estimated file size is reasonable."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo("TEST=1\n")
        builder.add_memory_segment(0x100000, b"\x00" * 4096)

        stats = builder.stats

        # File size should be at least the memory size plus headers
        assert stats.estimated_file_size > stats.total_memory_size
        # But not absurdly large
        assert stats.estimated_file_size < stats.total_memory_size + 10000

        # Write and verify actual size is close to estimate
        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)
            actual_size = os.path.getsize(output_path)
            # Estimated size should be very close to actual
            assert abs(actual_size - stats.estimated_file_size) < 100
        finally:
            os.unlink(output_path)

    def test_stats_human_readable_sizes(self) -> None:
        """Test human-readable size formatting."""
        builder = KdumpBuilder(arch="x86_64")

        # Test bytes
        builder.add_memory_segment(0x1000, b"\x00" * 100)
        assert "100 B" in builder.stats.total_memory_size_human

        # Test KB
        builder = KdumpBuilder(arch="x86_64")
        builder.add_memory_segment(0x1000, b"\x00" * 2048)
        assert "KB" in builder.stats.total_memory_size_human

        # Test MB
        builder = KdumpBuilder(arch="x86_64")
        builder.add_memory_segment(0x1000, b"\x00" * (2 * 1024 * 1024))
        assert "MB" in builder.stats.total_memory_size_human

    def test_stats_string_representation(self) -> None:
        """Test the string representation of stats."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo("OSRELEASE=test\n")
        builder.add_memory_segment(0x100000, b"\x00" * 4096)
        builder.add_cpu_context(cpu_id=0)

        stats_str = str(builder.stats)

        assert "Dump Statistics:" in stats_str
        assert "x86_64" in stats_str
        assert "Memory Segments: 1" in stats_str
        assert "CPU Contexts: 1" in stats_str
        assert "0x0000000000100000" in stats_str

    def test_stats_different_architectures(self) -> None:
        """Test stats for different architectures."""
        for arch in ["x86_64", "aarch64", "s390x"]:
            builder = KdumpBuilder(arch=arch)
            stats = builder.stats
            assert stats.architecture == arch


class TestVirtualAddressSupport:
    """Tests for virtual address support in memory segments."""

    def test_segment_with_explicit_virt_addr(self) -> None:
        """Test creating a segment with an explicit virtual address."""
        test_data = b"\xde\xad\xbe\xef" * 1024
        phys_addr = 0x100000
        virt_addr = 0xFFFF888000100000  # Typical kernel direct mapping

        builder = KdumpBuilder(arch="x86_64")
        builder.add_memory_segment(
            phys_addr=phys_addr, data=test_data, virt_addr=virt_addr
        )

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)

                load_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                ]
                assert len(load_segments) == 1

                load_segment = load_segments[0]
                assert load_segment["p_paddr"] == phys_addr
                assert load_segment["p_vaddr"] == virt_addr
                assert load_segment.data() == test_data
        finally:
            os.unlink(output_path)

    def test_segment_without_virt_addr_defaults_to_phys(self) -> None:
        """Test that segments without virt_addr default to phys_addr."""
        test_data = b"\xca\xfe" * 512
        phys_addr = 0x200000

        builder = KdumpBuilder(arch="x86_64")
        builder.add_memory_segment(phys_addr=phys_addr, data=test_data)

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)

                load_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                ]
                assert len(load_segments) == 1

                load_segment = load_segments[0]
                # When virt_addr is not specified, it should default to phys_addr
                assert load_segment["p_paddr"] == phys_addr
                assert load_segment["p_vaddr"] == phys_addr
        finally:
            os.unlink(output_path)

    def test_multiple_segments_with_different_virt_addrs(self) -> None:
        """Test multiple segments with various virtual address configurations."""
        segments_config = [
            # (phys_addr, virt_addr, data)
            (0x100000, 0xFFFF888000100000, b"\x11" * 4096),
            (0x200000, None, b"\x22" * 4096),  # Should default to phys_addr
            (0x300000, 0xFFFFFFFF81300000, b"\x33" * 4096),  # Kernel text mapping
        ]

        builder = KdumpBuilder(arch="x86_64")
        for phys_addr, virt_addr, data in segments_config:
            builder.add_memory_segment(
                phys_addr=phys_addr, data=data, virt_addr=virt_addr
            )

        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            builder.write(output_path)

            with open(output_path, "rb") as f:
                elf = ELFFile(f)

                load_segments = [
                    s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                ]
                assert len(load_segments) == 3

                # Verify each segment
                for i, load_segment in enumerate(load_segments):
                    phys_addr, virt_addr, data = segments_config[i]
                    expected_virt = virt_addr if virt_addr is not None else phys_addr

                    assert load_segment["p_paddr"] == phys_addr
                    assert load_segment["p_vaddr"] == expected_virt
                    assert load_segment.data() == data
        finally:
            os.unlink(output_path)

    def test_stats_include_virt_addr(self) -> None:
        """Test that stats include virtual addresses for segments."""
        builder = KdumpBuilder(arch="x86_64")
        builder.add_memory_segment(
            phys_addr=0x100000, data=b"\x00" * 4096, virt_addr=0xFFFF888000100000
        )
        builder.add_memory_segment(
            phys_addr=0x200000, data=b"\x00" * 8192
        )  # No virt_addr

        stats = builder.stats

        assert len(stats.memory_segments) == 2

        # First segment: explicit virt_addr
        phys, virt, size = stats.memory_segments[0]
        assert phys == 0x100000
        assert virt == 0xFFFF888000100000
        assert size == 4096

        # Second segment: virt_addr defaults to phys_addr
        phys, virt, size = stats.memory_segments[1]
        assert phys == 0x200000
        assert virt == 0x200000  # Should default to phys_addr
        assert size == 8192

    def test_stats_string_shows_virt_addr_when_different(self) -> None:
        """Test that stats string shows virt_addr when it differs from phys_addr."""
        builder = KdumpBuilder(arch="x86_64")
        builder.add_memory_segment(
            phys_addr=0x100000, data=b"\x00" * 4096, virt_addr=0xFFFF888000100000
        )

        stats_str = str(builder.stats)

        # Should show both addresses when they differ
        assert "phys=0x" in stats_str
        assert "virt=0x" in stats_str
        assert "ffff888000100000" in stats_str.lower()

    def test_fluent_api_with_virt_addr(self) -> None:
        """Test that the fluent API works with virtual addresses."""
        with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
            output_path = f.name

        try:
            (
                KdumpBuilder(arch="x86_64")
                .set_vmcoreinfo("TEST=1\n")
                .add_memory_segment(
                    phys_addr=0x1000, data=b"\x00" * 100, virt_addr=0xFFFF888000001000
                )
                .add_memory_segment(phys_addr=0x2000, data=b"\xff" * 100)
                .write(output_path)
            )

            assert os.path.exists(output_path)
            assert os.path.getsize(output_path) > 0
        finally:
            os.unlink(output_path)

    def test_virt_addr_with_different_architectures(self) -> None:
        """Test virtual address support across different architectures."""
        for arch in ["x86_64", "aarch64", "s390x"]:
            builder = KdumpBuilder(arch=arch)
            builder.add_memory_segment(
                phys_addr=0x100000, data=b"\x00" * 64, virt_addr=0xFFFF000000100000
            )

            with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
                output_path = f.name

            try:
                builder.write(output_path)

                with open(output_path, "rb") as f:
                    elf = ELFFile(f)
                    load_segments = [
                        s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"
                    ]
                    assert len(load_segments) == 1
                    assert load_segments[0]["p_vaddr"] == 0xFFFF000000100000
                    assert load_segments[0]["p_paddr"] == 0x100000
            finally:
                os.unlink(output_path)
