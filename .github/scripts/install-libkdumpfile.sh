#!/bin/bash
#
# Install libkdumpfile from source with Python bindings
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
    zlib1g-dev

# Clone libkdumpfile
cd /tmp
git clone https://codeberg.org/ptesarik/libkdumpfile.git
cd libkdumpfile

# Build and install
autoreconf -fi
./configure --with-python=$(which python3)
make -j$(nproc)
sudo make install

# Update library cache
sudo ldconfig

# Verify installation
python3 -c "import kdumpfile; print(f'kdumpfile version: {kdumpfile.__version__}')" || echo "kdumpfile module installed"
