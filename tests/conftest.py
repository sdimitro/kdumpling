"""
Shared test fixtures and constants for kdumpling tests.

This module provides common vmcoreinfo data and pytest fixtures
to reduce duplication across test files.
"""

import os
import tempfile
from typing import Generator

import pytest

# =============================================================================
# VMCOREINFO Constants
# =============================================================================

# Minimal vmcoreinfo required by drgn for different architectures
VMCOREINFO_X86_64 = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffffffff82a00000
SYMBOL(_stext)=ffffffff81000000
NUMBER(phys_base)=0
"""

VMCOREINFO_AARCH64 = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffff800000000000
"""

VMCOREINFO_S390X = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=0000000000000000
"""

VMCOREINFO_PPC64 = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=c000000000000000
"""

VMCOREINFO_RISCV64 = """OSRELEASE=5.14.0-test
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffffffe000000000
"""

# Comprehensive vmcoreinfo for more thorough testing
VMCOREINFO_FULL_X86_64 = """OSRELEASE=5.14.0-362.el9.x86_64
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

# Map architecture to its vmcoreinfo
VMCOREINFO_BY_ARCH = {
    "x86_64": VMCOREINFO_X86_64,
    "aarch64": VMCOREINFO_AARCH64,
    "arm64": VMCOREINFO_AARCH64,
    "s390x": VMCOREINFO_S390X,
    "ppc64": VMCOREINFO_PPC64,
    "ppc64le": VMCOREINFO_PPC64,
    "riscv64": VMCOREINFO_RISCV64,
}


# =============================================================================
# Test Data Constants
# =============================================================================

# Common test memory patterns
TEST_PATTERN_4KB = b"\xde\xad\xbe\xef" * 1024
TEST_PATTERN_ZEROS_4KB = b"\x00" * 4096
TEST_PATTERN_ONES_4KB = b"\xff" * 4096

# Common physical addresses
PHYS_ADDR_BASE = 0x0
PHYS_ADDR_1MB = 0x100000
PHYS_ADDR_2MB = 0x200000
PHYS_ADDR_16MB = 0x1000000


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def vmcore_output_path() -> Generator[str, None, None]:
    """Fixture that provides a temporary file path for vmcore output.

    The file is automatically cleaned up after the test.
    """
    with tempfile.NamedTemporaryFile(suffix=".vmcore", delete=False) as f:
        output_path = f.name

    yield output_path

    # Cleanup
    if os.path.exists(output_path):
        os.unlink(output_path)


@pytest.fixture
def temp_data_file() -> Generator[str, None, None]:
    """Fixture that provides a temporary file with test data.

    The file contains 2KB of test pattern data.
    """
    test_data = b"\xca\xfe\xba\xbe" * 512

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(test_data)
        data_path = f.name

    yield data_path

    # Cleanup
    if os.path.exists(data_path):
        os.unlink(data_path)


def get_vmcoreinfo_for_arch(arch: str) -> str:
    """Get the appropriate vmcoreinfo for a given architecture.

    Args:
        arch: Architecture name (e.g., 'x86_64', 'aarch64')

    Returns:
        The vmcoreinfo string for that architecture.

    Raises:
        KeyError: If the architecture is not supported.
    """
    return VMCOREINFO_BY_ARCH[arch]
