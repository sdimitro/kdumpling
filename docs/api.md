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

#### add_custom_note

```python
def add_custom_note(
    self,
    name: bytes | str,
    note_type: int,
    data: bytes | str
) -> KdumpBuilder
```

Add a custom ELF note to the vmcore.

Custom notes are stored in the PT_NOTE segment alongside standard notes like VMCOREINFO and NT_PRSTATUS. Tools that don't recognize the note type will safely ignore it.

**Parameters:**
- `name`: Vendor/namespace identifier (e.g., `b"KDUMPLING"` or `"MYAPP"`). Using a unique name prevents conflicts with other tools.
- `note_type`: Numeric type identifier. See `CustomNoteType` for predefined values, or use any integer.
- `data`: The note data. Can be bytes or a string (will be UTF-8 encoded).

**Returns:** `self` for method chaining

**Example:**
```python
builder.add_custom_note(
    name=b"KDUMPLING",
    note_type=CustomNoteType.METADATA,
    data=b"sha256=abc123..."
)
```

#### add_metadata

```python
def add_metadata(
    self,
    data: dict[str, str] | bytes | str,
    vendor: bytes | str = b"KDUMPLING"
) -> KdumpBuilder
```

Add metadata to the vmcore. This is a convenience method for adding key-value metadata using the METADATA note type.

**Parameters:**
- `data`: Metadata to add. Can be:
  - `dict`: Key-value pairs (converted to `"key=value\n"` format)
  - `bytes`/`str`: Raw metadata content
- `vendor`: Vendor name for the note (default: `"KDUMPLING"`)

**Returns:** `self` for method chaining

**Example:**
```python
builder.add_metadata({
    "sha256": "abc123...",
    "created_at": "2024-01-28T10:30:00Z",
    "source": "memory_forensics_tool"
})
```

#### add_annotations

```python
def add_annotations(
    self,
    annotations: dict[str, str],
    vendor: bytes | str = b"KDUMPLING"
) -> KdumpBuilder
```

Add custom annotations to the vmcore. Annotations are free-form key-value pairs for attaching contextual information to the dump.

**Parameters:**
- `annotations`: Dictionary of annotation key-value pairs
- `vendor`: Vendor name for the note (default: `"KDUMPLING"`)

**Returns:** `self` for method chaining

**Example:**
```python
builder.add_annotations({
    "hostname": "prod-server-01",
    "kernel_panic_reason": "out of memory",
    "captured_by": "crash_collector v2.1"
})
```

#### write

```python
def write(
    self,
    output_path: str,
    format: OutputFormat = OutputFormat.ELF,
    compression: CompressionType = CompressionType.ZLIB,
    compression_level: int = 6
) -> None
```

Write the vmcore file to disk.

**Parameters:**
- `output_path`: Path where the vmcore file will be written
- `format`: Output format (`OutputFormat.ELF` or `OutputFormat.KDUMP_COMPRESSED`). Default is ELF.
- `compression`: Compression type for KDUMP_COMPRESSED format. See `CompressionType`. Default is ZLIB. Ignored for ELF format.
- `compression_level`: Compression level 1-9. Default is 6. Higher values give better compression but are slower. Ignored for ELF format.

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

## OutputFormat

Output format options for vmcore files.

```python
from kdumpling import OutputFormat
```

| Value | Description |
|-------|-------------|
| `OutputFormat.ELF` | Standard ELF64 vmcore (default). Compatible with all tools. |
| `OutputFormat.KDUMP_COMPRESSED` | Kdump compressed format (makedumpfile compatible). Provides per-page compression and filtering. |

---

## CompressionType

Compression algorithms for the kdump compressed format.

```python
from kdumpling import CompressionType
```

| Value | Description |
|-------|-------------|
| `CompressionType.NONE` | No compression (dump level filtering only) |
| `CompressionType.ZLIB` | zlib/gzip compression (default, always available) |
| `CompressionType.LZO` | LZO compression (requires `python-lzo` package) |
| `CompressionType.SNAPPY` | Snappy compression (requires `python-snappy` package) |
| `CompressionType.ZSTD` | Zstandard compression (requires `zstandard` package) |

**Note:** If an optional compression library is not installed, the writer will fall back to storing pages uncompressed.

---

## CustomNote

A custom ELF note to be included in the vmcore.

```python
from kdumpling import CustomNote
```

Custom notes allow users to embed additional metadata in their vmcore files, such as hashes, timestamps, annotations, or any other application-specific data.

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `bytes` | Vendor/namespace identifier (e.g., `b"KDUMPLING"`) |
| `note_type` | `int` | Note type (see `CustomNoteType` for predefined values) |
| `data` | `bytes` | Note descriptor data |

### Example

```python
from kdumpling import CustomNote, CustomNoteType

note = CustomNote(
    name=b"KDUMPLING",
    note_type=CustomNoteType.METADATA,
    data=b"sha256=abc123..."
)
```

---

## CustomNoteType

Predefined custom note types for kdumpling metadata.

```python
from kdumpling import CustomNoteType
```

| Value | Description |
|-------|-------------|
| `CustomNoteType.METADATA` | Hash/signature information (value: 1) |
| `CustomNoteType.ANNOTATIONS` | Custom key-value annotations (value: 2) |
| `CustomNoteType.FILE_INFO` | File description information (value: 3) |
| `CustomNoteType.USER_DEFINED` | Start of user-defined range (value: 256) |

Users can also use any integer value for custom types beyond the predefined ones.

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
