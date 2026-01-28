#!/bin/bash
#
# Install libkdumpfile from source with Python bindings (pykdumpfile)
#
set -eux

# Install build dependencies
sudo apt-get update
sudo apt-get install -y \
    autoconf \
    automake \
    binutils-dev \
    liblzo2-dev \
    libsnappy-dev \
    libtool \
    pkg-config \
    python3-dev \
    zlib1g-dev \
    libzstd-dev

# Clone and build libkdumpfile (C library)
cd /tmp
git clone https://codeberg.org/ptesarik/libkdumpfile.git
cd libkdumpfile

# Build and install the C library
autoreconf -fi
./configure
make -j$(nproc)
sudo make install

# Update library cache
sudo ldconfig

# Now install the Python bindings (pykdumpfile)
# The Python bindings are in a separate repository since libkdumpfile 0.5.5
cd /tmp
git clone https://github.com/ptesarik/pykdumpfile.git
cd pykdumpfile

# Install using pip (which respects the Python set up by actions/setup-python)
pip install .

# Verify installation
python -c "import kdumpfile; print(f'kdumpfile version: {kdumpfile.__version__}')"
echo "kdumpfile module installed successfully"
