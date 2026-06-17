#!/usr/bin/env bash
set -euo pipefail

sudo apt update
sudo apt install -y \
  build-essential \
  cmake \
  doxygen \
  git \
  libnode-dev \
  pkg-config

cat <<'MSG'

Base build tools are installed.

If your distribution does not provide standalone V8 headers/libs, libnode-dev is
enough for many Debian/Ubuntu setups because it ships V8 headers and libnode.
Then try:

  cmake -S . -B build
  cmake --build build
  ctest --test-dir build --output-on-failure

MSG
