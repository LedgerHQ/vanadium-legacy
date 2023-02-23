#!/bin/sh

set -e

speculos.py --sdk 1.0.3 --model nanosp ../../vm/bin/app.elf &

sleep .5; ../../host/stream.py --speculos --app ./target/riscv32i-unknown-none-elf/release/app-bitcoin
