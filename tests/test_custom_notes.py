"""
Tests for the custom notes API.

Tests that users can add custom metadata notes to vmcore files
and that the notes are properly serialized in the ELF format.
"""

import pytest
from elftools.elf.elffile import ELFFile

from kdumpling import CustomNoteType, KdumpBuilder

from .conftest import VMCOREINFO_X86_64


class TestCustomNotes:
    """Tests for custom note functionality."""

    def test_add_custom_note_bytes(self, vmcore_output_path: str) -> None:
        """Test adding a custom note with bytes data."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.add_custom_note(
            name=b"TESTVENDOR",
            note_type=100,  # Use a high number to avoid NT_* enum mapping
            data=b"test_data_here",
        )
        builder.write(vmcore_output_path)

        # Verify the note is in the file
        with open(vmcore_output_path, "rb") as f:
            elf = ELFFile(f)

            # Find PT_NOTE segment
            note_segment = None
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_NOTE":
                    note_segment = segment
                    break

            assert note_segment is not None

            # Find our custom note
            found_custom_note = False
            for note in note_segment.iter_notes():
                if note["n_name"] == "TESTVENDOR":
                    found_custom_note = True
                    assert note["n_type"] == 100
                    assert note["n_desc"] == b"test_data_here"
                    break

            assert found_custom_note, "Custom note not found in vmcore"

    def test_add_custom_note_string(self, vmcore_output_path: str) -> None:
        """Test adding a custom note with string data."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.add_custom_note(
            name="MYAPP",  # String name
            note_type=100,  # Use high number to avoid NT_* mapping
            data="version=1.0\nhost=test",  # String data
        )
        builder.write(vmcore_output_path)

        # Verify the note
        with open(vmcore_output_path, "rb") as f:
            elf = ELFFile(f)
            note_segment = next(
                s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
            )

            found_note = False
            for note in note_segment.iter_notes():
                if note["n_name"] == "MYAPP":
                    found_note = True
                    assert note["n_type"] == 100
                    assert b"version=1.0" in note["n_desc"]
                    break

            assert found_note

    def test_add_multiple_custom_notes(self, vmcore_output_path: str) -> None:
        """Test adding multiple custom notes."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)

        # Add multiple notes
        builder.add_custom_note(b"VENDOR1", 1, b"data1")
        builder.add_custom_note(b"VENDOR2", 2, b"data2")
        builder.add_custom_note(b"VENDOR1", 3, b"data3")  # Same vendor, different type

        builder.write(vmcore_output_path)

        # Verify all notes
        with open(vmcore_output_path, "rb") as f:
            elf = ELFFile(f)
            note_segment = next(
                s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
            )

            custom_notes = [
                n
                for n in note_segment.iter_notes()
                if n["n_name"] in ("VENDOR1", "VENDOR2")
            ]

            assert len(custom_notes) == 3

    def test_add_metadata_dict(self, vmcore_output_path: str) -> None:
        """Test add_metadata convenience method with dict."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.add_metadata(
            {
                "sha256": "abc123def456",
                "created_at": "2024-01-28T10:30:00Z",
                "source": "test",
            }
        )
        builder.write(vmcore_output_path)

        # Verify metadata note
        with open(vmcore_output_path, "rb") as f:
            elf = ELFFile(f)
            note_segment = next(
                s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
            )

            found_metadata = False
            for note in note_segment.iter_notes():
                if note["n_name"] == "KDUMPLING":
                    # Note type 1 (METADATA) may be shown as "NT_PRSTATUS" by pyelftools
                    n_type = note["n_type"]
                    if n_type == CustomNoteType.METADATA or n_type == "NT_PRSTATUS":
                        found_metadata = True
                        desc = note["n_desc"].decode("utf-8")
                        assert "sha256=abc123def456" in desc
                        assert "created_at=2024-01-28T10:30:00Z" in desc
                        break

            assert found_metadata

    def test_add_annotations(self, vmcore_output_path: str) -> None:
        """Test add_annotations convenience method."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.add_annotations(
            {
                "hostname": "prod-server-01",
                "panic_reason": "out of memory",
            }
        )
        builder.write(vmcore_output_path)

        # Verify annotations note
        with open(vmcore_output_path, "rb") as f:
            elf = ELFFile(f)
            note_segment = next(
                s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
            )

            found_annotations = False
            for note in note_segment.iter_notes():
                if note["n_name"] == "KDUMPLING":
                    # Note type 2 (ANNOTATIONS) may be shown as "NT_FPREGSET" by pyelftools
                    n_type = note["n_type"]
                    if n_type == CustomNoteType.ANNOTATIONS or n_type == "NT_FPREGSET":
                        found_annotations = True
                        desc = note["n_desc"].decode("utf-8")
                        assert "hostname=prod-server-01" in desc
                        assert "panic_reason=out of memory" in desc
                        break

            assert found_annotations

    def test_custom_vendor_name(self, vmcore_output_path: str) -> None:
        """Test using a custom vendor name with convenience methods."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.add_metadata({"key": "value"}, vendor=b"MYCOMPANY")
        builder.write(vmcore_output_path)

        # Verify note uses custom vendor
        with open(vmcore_output_path, "rb") as f:
            elf = ELFFile(f)
            note_segment = next(
                s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
            )

            found_note = False
            for note in note_segment.iter_notes():
                if note["n_name"] == "MYCOMPANY":
                    found_note = True
                    break

            assert found_note

    def test_custom_notes_with_cpu_context(self, vmcore_output_path: str) -> None:
        """Test that custom notes work alongside CPU contexts."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.add_cpu_context(cpu_id=0, registers={"RIP": 0xFFFFFFFF81000000})
        builder.add_custom_note(b"TESTAPP", 1, b"test")
        builder.write(vmcore_output_path)

        # Verify both CPU context and custom note are present
        with open(vmcore_output_path, "rb") as f:
            elf = ELFFile(f)
            note_segment = next(
                s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
            )

            notes_by_name: dict[str, list] = {}
            for note in note_segment.iter_notes():
                name = note["n_name"]
                if name not in notes_by_name:
                    notes_by_name[name] = []
                notes_by_name[name].append(note)

            # Should have CORE (prstatus), VMCOREINFO, and TESTAPP notes
            assert "CORE" in notes_by_name
            assert "VMCOREINFO" in notes_by_name
            assert "TESTAPP" in notes_by_name

    def test_fluent_api_with_custom_notes(self, vmcore_output_path: str) -> None:
        """Test that custom notes work with fluent API."""
        (
            KdumpBuilder(arch="x86_64")
            .set_vmcoreinfo(VMCOREINFO_X86_64)
            .add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
            .add_custom_note(b"NOTE1", 1, b"data1")
            .add_metadata({"key": "value"})
            .add_annotations({"info": "test"})
            .write(vmcore_output_path)
        )

        # Verify file was created and is valid
        with open(vmcore_output_path, "rb") as f:
            elf = ELFFile(f)
            note_segment = next(
                s for s in elf.iter_segments() if s["p_type"] == "PT_NOTE"
            )

            note_names = set()
            for note in note_segment.iter_notes():
                note_names.add(note["n_name"])

            assert "NOTE1" in note_names
            assert "KDUMPLING" in note_names

    def test_stats_includes_custom_notes(self, vmcore_output_path: str) -> None:
        """Test that stats calculation includes custom notes size."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)

        # Get stats without custom notes
        stats_before = builder.stats
        size_before = stats_before.estimated_file_size

        # Add custom note
        builder.add_custom_note(b"TESTNOTE", 1, b"x" * 100)

        # Get stats with custom note
        stats_after = builder.stats
        size_after = stats_after.estimated_file_size

        # Size should have increased
        assert size_after > size_before


# Try to import drgn for integration test
try:
    import drgn

    DRGN_AVAILABLE = True
except ImportError:
    DRGN_AVAILABLE = False


@pytest.mark.skipif(not DRGN_AVAILABLE, reason="drgn not installed")
class TestCustomNotesDrgnIntegration:
    """Test that custom notes don't break drgn compatibility."""

    def test_drgn_ignores_custom_notes(self, vmcore_output_path: str) -> None:
        """Test that drgn can still read vmcores with custom notes."""
        builder = KdumpBuilder(arch="x86_64")
        builder.set_vmcoreinfo(VMCOREINFO_X86_64)
        builder.add_memory_segment(phys_addr=0x100000, data=b"\x00" * 4096)
        builder.add_custom_note(b"KDUMPLING", CustomNoteType.METADATA, b"test=value")
        builder.add_custom_note(b"KDUMPLING", CustomNoteType.ANNOTATIONS, b"key=val")
        builder.write(vmcore_output_path)

        # drgn should be able to open the file without issues
        prog = drgn.Program()
        prog.set_core_dump(vmcore_output_path)

        # Verify basic functionality still works
        assert prog.platform is not None
        assert prog.platform.arch == drgn.Architecture.X86_64
