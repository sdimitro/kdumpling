# API Reference

## KdumpBuilder

The main class for building vmcore files.

```python
from kdumpling import KdumpBuilder
```

### Constructor

```python
KdumpBuilder(arch: str = 'x86_64')
```

**Parameters:**
- `arch`: Target architecture. One of: `x86_64`, `aarch64`, `arm64`, `s390x`, `ppc64le`, `ppc64`, `riscv64`

**Raises:**
- `ValueError`: If the architecture is not supported

### Methods

#### set_vmcoreinfo

```python
def set_vmcoreinfo(self, data: str | bytes) -> KdumpBuilder
```

Set the VMCOREINFO metadata string.

**Parameters:**
- `data`: The vmcoreinfo string (e.g., `"OSRELEASE=5.14.0\nPAGESIZE=4096\n"`)

**Returns:** `self` for method chaining

#### add_memory_segment

```python
def add_memory_segment(self, phys_addr: int, data: bytes | str | BinaryIO) -> KdumpBuilder
```

Add a memory segment to the dump.

**Parameters:**
- `phys_addr`: The physical address where this memory resides
- `data`: The memory data. Can be:
  - `bytes`: Raw memory content
  - `str`: Path to a file containing the data
  - `BinaryIO`: File-like object to read from

**Returns:** `self` for method chaining

#### add_cpu_context

```python
def add_cpu_context(
    self,
    cpu_id: int = 0,
    registers: dict[str, int] | None = None,
    pid: int = 0,
    **kwargs: int
) -> KdumpBuilder
```

Add CPU register state for a processor.

**Parameters:**
- `cpu_id`: CPU identifier (0-indexed)
- `registers`: Dictionary mapping register names to values
  - For x86_64: `RIP`, `RSP`, `RBP`, `RAX`, `RBX`, `RCX`, `RDX`, `RSI`, `RDI`, `R8`-`R15`, etc.
  - For aarch64: `X0`-`X30`, `SP`, `PC`, `PSTATE`
- `pid`: Process ID associated with this CPU
- `**kwargs`: Additional prstatus fields (`pr_ppid`, `pr_pgrp`, `pr_sid`, `si_signo`, etc.)

**Returns:** `self` for method chaining

#### write

```python
def write(self, output_path: str) -> None
```

Write the vmcore file to disk.

**Parameters:**
- `output_path`: Path where the vmcore file will be written

### Properties

#### stats

```python
@property
def stats(self) -> DumpStats
```

Get statistics about the dump being built.

**Returns:** `DumpStats` object with information about segments, size, etc.

---

## DumpStats

Statistics about a vmcore dump being built.

```python
from kdumpling import DumpStats
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `architecture` | `str` | Target architecture |
| `num_memory_segments` | `int` | Number of memory segments |
| `num_cpu_contexts` | `int` | Number of CPU contexts |
| `total_memory_size` | `int` | Total memory size in bytes |
| `vmcoreinfo_size` | `int` | Size of vmcoreinfo in bytes |
| `estimated_file_size` | `int` | Estimated output file size |
| `memory_segments` | `list[tuple[int, int]]` | List of (phys_addr, size) tuples |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `total_memory_size_human` | `str` | Human-readable memory size (e.g., "4.0 MB") |
| `estimated_file_size_human` | `str` | Human-readable file size |

### String Representation

`DumpStats` has a `__str__` method that provides a formatted summary:

```python
print(builder.stats)
# Dump Statistics:
#   Architecture: x86_64
#   Memory Segments: 2
#   CPU Contexts: 1
#   Total Memory: 8.0 KB (8192 bytes)
#   ...
```

---

## CpuContext

CPU context for a single processor (used internally).

```python
from kdumpling import CpuContext
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `cpu_id` | `int` | CPU identifier |
| `pid` | `int` | Process ID |
| `registers` | `dict[str, int]` | Register name to value mapping |
| `si_signo` | `int` | Signal number |
| `pr_pid` | `int` | Process ID in prstatus |
| `pr_ppid` | `int` | Parent process ID |

---

## Register Enums

### X86_64Reg

Register indices for x86_64 architecture.

```python
from kdumpling import X86_64Reg

# Available registers:
X86_64Reg.RIP  # Instruction pointer
X86_64Reg.RSP  # Stack pointer
X86_64Reg.RBP  # Base pointer
X86_64Reg.RAX, X86_64Reg.RBX, X86_64Reg.RCX, X86_64Reg.RDX
X86_64Reg.RSI, X86_64Reg.RDI
X86_64Reg.R8, X86_64Reg.R9, X86_64Reg.R10, X86_64Reg.R11
X86_64Reg.R12, X86_64Reg.R13, X86_64Reg.R14, X86_64Reg.R15
# ... and more
```

### AArch64Reg

Register indices for AArch64 (ARM64) architecture.

```python
from kdumpling import AArch64Reg

# Available registers:
AArch64Reg.X0 through AArch64Reg.X30
AArch64Reg.SP     # Stack pointer
AArch64Reg.PC     # Program counter
AArch64Reg.PSTATE # Processor state
```
