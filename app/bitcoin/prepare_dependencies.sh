#!/bin/sh

[ ! -d "rust-bitcoin" ] && git clone https://github.com/LedgerHQ/vanadium-rust-bitcoin.git rust-bitcoin
[ ! -d "rust-secp256k1" ] && git clone https://github.com/LedgerHQ/vanadium-rust-secp256k1.git rust-secp256k1
[ ! -d "secp256kfun" ] && git clone https://github.com/LedgerHQ/vanadium-secp256kfun.git secp256kfun
