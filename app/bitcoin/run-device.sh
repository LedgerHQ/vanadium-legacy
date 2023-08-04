#!/bin/sh

set -e

PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python ./client_py/bitcoin.py --app ./target/riscv32imc-unknown-none-elf/release/vnd-bitcoin "$@"
