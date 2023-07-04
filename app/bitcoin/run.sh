#!/bin/sh

set -e

speculos.py ../../vm/bin/app.elf &

sleep .5; PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python ./client_py/bitcoin.py --speculos --app ./target/riscv32i-unknown-none-elf/release/vnd-bitcoin "$@"
