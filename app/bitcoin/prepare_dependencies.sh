#!/bin/sh

# clone rust-bitcoin and apply patches
[ ! -d "./rust-bitcoin" ] && (
git clone --depth 1 git@github.com:rust-bitcoin/rust-bitcoin.git
cd rust-bitcoin || exit
git apply ../patches/rust-bitcoin-*.patch
)

# clone rust-secp256k1 and apply patches
[ ! -d "./rust-secp256k1" ] && (
git clone --depth 1 git@github.com:rust-bitcoin/rust-secp256k1.git
cd rust-secp256k1 || exit
git apply ../patches/rust-secp256k1-*.patch
)
