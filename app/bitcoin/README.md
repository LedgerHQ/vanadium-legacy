
## Compiling the app

### TL;DR:

Compile the C SDK first (for both native and RISC-V targets).

From the root folder of the app:

```console
./lib/create-lib.sh
```

```console
$ ./prepare-depencencies.sh
```

Then, for native execution:

```console
cargo build --release
```

or, for the RISC-V target:

```console
cargo build --release --target riscv32imc-unknown-none-elf
```

### Pre-requisites (system)

Some libraries are required to build a Rust app:

- `libc.a` to build the app for the RISC-V target
- `libcrypto.a` to pass tests on the x64 target

These libraries can be retrieved from Docker images thanks to the script `lib/create-lib.sh`:

```console
./lib/create-lib.sh
```

They are also generated as artifacts by the [GitHub CI](https://github.com/LedgerHQ/vanadium/actions/workflows/apps.yml).


### Pre-requisites (bitcoin)

The app requires patched versions of the [rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) and [rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1). The `prepare_dependencies.sh` downloads the patched libraries from https://github.com/LedgerHQ/vanadium-rust-bitcoin and https://github.com/LedgerHQ/vanadium-rust-secp256k1, respectively.


## Running native unit tests

Make sure to not run tests in parallel, for example:

```
cargo test -- --test-threads=1
```