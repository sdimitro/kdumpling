# Quick Start Guide

## Basic Usage

### Creating a Simple Vmcore

The most basic usage involves creating a vmcore with some memory data:

```python
from kdumpling import KdumpBuilder

builder = KdumpBuilder(arch='x86_64')
builder.set_vmcoreinfo("OSRELEASE=5.14.0\nPAGESIZE=4096\n")
builder.add_memory_segment(phys_addr=0x100000, data=b'\x00' * 4096)
builder.write("simple.vmcore")
```

### Fluent API

All builder methods return `self`, allowing method chaining:

```python
from kdumpling import KdumpBuilder

(KdumpBuilder(arch='x86_64')
    .set_vmcoreinfo("OSRELEASE=5.14.0\n")
    .add_memory_segment(0x100000, b'\x00' * 4096)
    .add_memory_segment(0x200000, b'\x00' * 8192)
    .add_cpu_context(cpu_id=0, registers={'RIP': 0xffffffff81000000})
    .write("chained.vmcore"))
```

### Adding CPU Context

To include CPU register state for debugging tools:

```python
from kdumpling import KdumpBuilder

builder = KdumpBuilder(arch='x86_64')
builder.set_vmcoreinfo("OSRELEASE=5.14.0\n")

# Add register state for CPU 0
builder.add_cpu_context(
    cpu_id=0,
    registers={
        'RIP': 0xffffffff81000000,  # Instruction pointer
        'RSP': 0xffff888000000000,  # Stack pointer
        'RBP': 0xffff888000001000,  # Base pointer
        'RAX': 0x1234,
        'RBX': 0x5678,
    },
    pid=1
)

# Add another CPU
builder.add_cpu_context(
    cpu_id=1,
    registers={'RIP': 0xffffffff81001000},
    pid=2
)

builder.write("with_cpu.vmcore")
```

### Checking Dump Statistics

Before writing, you can inspect the dump statistics:

```python
from kdumpling import KdumpBuilder

builder = KdumpBuilder(arch='x86_64')
builder.set_vmcoreinfo("OSRELEASE=5.14.0\n")
builder.add_memory_segment(0x100000, b'\x00' * (4 * 1024 * 1024))  # 4MB
builder.add_cpu_context(cpu_id=0)

# Get statistics
stats = builder.stats
print(f"Architecture: {stats.architecture}")
print(f"Memory segments: {stats.num_memory_segments}")
print(f"Total memory: {stats.total_memory_size_human}")
print(f"Estimated file size: {stats.estimated_file_size_human}")

# Or print everything
print(stats)
```

Output:
```
Dump Statistics:
  Architecture: x86_64
  Memory Segments: 1
  CPU Contexts: 1
  Total Memory: 4.0 MB (4194304 bytes)
  VMCOREINFO Size: 20 bytes
  Estimated File Size: 4.0 MB
  Segments:
    0x0000000000100000: 4.0 MB
```

## Compressed Output

kdumpling supports the kdump compressed format, which is compatible with makedumpfile and tools like crash, libkdumpfile, and drgn. This format provides per-page compression and can significantly reduce file sizes.

### Basic Compressed Output

```python
from kdumpling import KdumpBuilder, OutputFormat, CompressionType

builder = KdumpBuilder(arch='x86_64')
builder.set_vmcoreinfo("OSRELEASE=5.14.0\nPAGESIZE=4096\n")
builder.add_memory_segment(0x100000, b'\x00' * 4096 * 100)  # 400KB

# Write in kdump compressed format with zlib compression
builder.write(
    "compressed.vmcore",
    format=OutputFormat.KDUMP_COMPRESSED,
    compression=CompressionType.ZLIB
)
```

### Compression Options

```python
from kdumpling import KdumpBuilder, OutputFormat, CompressionType

builder = KdumpBuilder(arch='x86_64')
builder.set_vmcoreinfo("OSRELEASE=5.14.0\n")
builder.add_memory_segment(0x100000, memory_data)

# No compression (still filters zero pages)
builder.write("dump.vmcore", format=OutputFormat.KDUMP_COMPRESSED,
              compression=CompressionType.NONE)

# Zlib compression (default, always available)
builder.write("dump.vmcore", format=OutputFormat.KDUMP_COMPRESSED,
              compression=CompressionType.ZLIB, compression_level=9)

# Zstandard compression (requires 'zstandard' package)
builder.write("dump.vmcore", format=OutputFormat.KDUMP_COMPRESSED,
              compression=CompressionType.ZSTD)
```

### Available Compression Types

| Type | Description | Requirement |
|------|-------------|-------------|
| `CompressionType.NONE` | No compression | None |
| `CompressionType.ZLIB` | zlib/gzip (default) | None (built-in) |
| `CompressionType.LZO` | LZO compression | `python-lzo` |
| `CompressionType.SNAPPY` | Snappy compression | `python-snappy` |
| `CompressionType.ZSTD` | Zstandard compression | `zstandard` |

The compressed format automatically excludes zero-filled pages, reducing output size even without compression.

## Supported Architectures

kdumpling supports the following architectures:

| Architecture | Endianness | Description |
|-------------|------------|-------------|
| `x86_64` | Little | 64-bit x86 (AMD64/Intel 64) |
| `aarch64` / `arm64` | Little | 64-bit ARM |
| `s390x` | Big | IBM Z series |
| `ppc64le` | Little | 64-bit PowerPC (little endian) |
| `ppc64` | Big | 64-bit PowerPC (big endian) |
| `riscv64` | Little | 64-bit RISC-V |

## Memory Segment Sources

Memory segments can be provided from different sources:

```python
from kdumpling import KdumpBuilder
import io

builder = KdumpBuilder(arch='x86_64')

# From bytes
builder.add_memory_segment(0x1000, b'\x00' * 4096)

# From a file path
builder.add_memory_segment(0x2000, "/path/to/memory.bin")

# From a file-like object
data = io.BytesIO(b'\xff' * 4096)
builder.add_memory_segment(0x3000, data)
```

## Validating with drgn

You can verify the generated vmcore using [drgn](https://github.com/osandov/drgn):

```python
import drgn
from kdumpling import KdumpBuilder

# Create vmcore
builder = KdumpBuilder(arch='x86_64')
builder.set_vmcoreinfo("""OSRELEASE=5.14.0
PAGESIZE=4096
SYMBOL(swapper_pg_dir)=ffffffff82a00000
""")
builder.add_memory_segment(0x100000, b'\x00' * 4096)
builder.write("test.vmcore")

# Verify with drgn
prog = drgn.Program()
prog.set_core_dump("test.vmcore")
print(f"Platform: {prog.platform}")
print(f"Flags: {prog.flags}")
```
