<p align="center">
  <img src="https://github.com/sdimitro/kdumpling/raw/develop/assets/logo.png" alt="kdumpling logo" width="400">
</p>

<h1 align="center">kdumpling</h1>

<p align="center">
  <a href="https://github.com/sdimitro/kdumpling/actions/workflows/ci.yml"><img src="https://github.com/sdimitro/kdumpling/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/sdimitro/kdumpling"><img src="https://codecov.io/gh/sdimitro/kdumpling/graph/badge.svg" alt="Codecov"></a>
  <a href="https://kdumpling.readthedocs.io"><img src="https://readthedocs.org/projects/kdumpling/badge/?version=latest" alt="Documentation"></a>
  <a href="https://pypi.org/project/kdumpling/"><img src="https://img.shields.io/pypi/v/kdumpling.svg" alt="PyPI version"></a>
  <a href="https://pypi.org/project/kdumpling/"><img src="https://img.shields.io/pypi/pyversions/kdumpling.svg" alt="Python versions"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

<p align="center">A Python library for creating Linux kdump crash dump files.</p>

## Overview

**kdumpling** allows you to synthesize valid ELF64 vmcore files from raw memory data and vmcoreinfo values. This is useful for:

- Testing crash dump analysis tools (like [drgn](https://github.com/osandov/drgn), [crash](https://github.com/crash-utility/crash))
- Creating synthetic crash dumps for debugging
- Educational purposes for understanding Linux kernel crash dump formats

## Installation

```bash
pip install kdumpling
```

## Quick Start

```python
from kdumpling import KdumpBuilder

# Create a builder for x86_64 architecture
builder = KdumpBuilder(arch='x86_64')

# Set the vmcoreinfo metadata
builder.set_vmcoreinfo("""OSRELEASE=5.14.0
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffffffff82a00000
""")

# Add memory segments
builder.add_memory_segment(phys_addr=0x100000, data=b'\x00' * 4096)

# Add CPU register state (optional)
builder.add_cpu_context(
    cpu_id=0,
    registers={'RIP': 0xffffffff81000000, 'RSP': 0xffff888000000000},
    pid=1
)

# Check stats before writing
print(builder.stats)
# Dump Statistics:
#   Architecture: x86_64
#   Memory Segments: 1
#   CPU Contexts: 1
#   Total Memory: 4.0 KB (4096 bytes)
#   ...

# Write the vmcore file
builder.write("output.vmcore")
```

## Features

- **Multi-architecture support**: x86_64, aarch64/arm64, s390x, ppc64/ppc64le, riscv64
- **Fluent API**: Chain method calls for concise code
- **CPU context support**: Include register state for debugging tools
- **Memory from multiple sources**: bytes, file paths, or file-like objects
- **Statistics API**: Inspect dump properties before writing
- **Validated**: Tested with [pyelftools](https://github.com/eliben/pyelftools), [drgn](https://github.com/osandov/drgn), and [libkdumpfile](https://codeberg.org/ptesarik/libkdumpfile)

## Supported Architectures

| Architecture | Endianness | Description |
|-------------|------------|-------------|
| `x86_64` | Little | 64-bit x86 (AMD64/Intel 64) |
| `aarch64` / `arm64` | Little | 64-bit ARM |
| `s390x` | Big | IBM Z series |
| `ppc64le` | Little | 64-bit PowerPC (little endian) |
| `ppc64` | Big | 64-bit PowerPC (big endian) |
| `riscv64` | Little | 64-bit RISC-V |

## Validating with drgn

```python
import drgn

prog = drgn.Program()
prog.set_core_dump("output.vmcore")
print(f"Platform: {prog.platform}")  # Platform(<Architecture.X86_64: 1>, ...)
print(f"Flags: {prog.flags}")        # ProgramFlags.IS_LINUX_KERNEL
```

## API Reference

### KdumpBuilder

```python
builder = KdumpBuilder(arch='x86_64')

# Set vmcoreinfo metadata
builder.set_vmcoreinfo("OSRELEASE=5.14.0\n...")

# Add memory segments
builder.add_memory_segment(phys_addr=0x100000, data=b'...')
builder.add_memory_segment(phys_addr=0x200000, data="/path/to/file")

# Add CPU context
builder.add_cpu_context(cpu_id=0, registers={'RIP': 0x...}, pid=1)

# Get statistics
stats = builder.stats
print(stats.num_memory_segments)
print(stats.total_memory_size_human)

# Write to file
builder.write("output.vmcore")
```

### DumpStats

```python
stats = builder.stats

stats.architecture          # 'x86_64'
stats.num_memory_segments   # Number of PT_LOAD segments
stats.num_cpu_contexts      # Number of NT_PRSTATUS notes
stats.total_memory_size     # Total memory in bytes
stats.vmcoreinfo_size       # VMCOREINFO size in bytes
stats.estimated_file_size   # Estimated output file size
stats.memory_segments       # List of (phys_addr, size) tuples

# Human-readable sizes
stats.total_memory_size_human     # "4.0 MB"
stats.estimated_file_size_human   # "4.0 MB"
```

## Development

```bash
# Clone the repository
git clone https://github.com/sdimitro/kdumpling.git
cd kdumpling

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check .

# Run type checker
mypy kdumpling
```

## License

MIT License - see [LICENSE](LICENSE) for details.
