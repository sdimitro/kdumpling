```{image} https://github.com/sdimitro/kdumpling/raw/main/assets/logo.png
:alt: kdumpling logo
:width: 400px
:align: center
```

# kdumpling

A Python library for creating Linux kdump crash dump files.

```{warning}
This library is currently a work in progress. The API may change in future releases.
```

## Overview

**kdumpling** allows you to synthesize valid ELF64 vmcore files from raw memory data and vmcoreinfo values. This is useful for:

- Testing crash dump analysis tools
- Creating synthetic crash dumps for debugging
- Educational purposes for understanding Linux kernel crash dump formats

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

# Write the vmcore file
builder.write("output.vmcore")
```

## Installation

```bash
pip install kdumpling
```

## Table of Contents

```{toctree}
:maxdepth: 2

quickstart
api
```
