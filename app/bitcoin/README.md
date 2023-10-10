
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

* On Linux x86_64 host:

```console
cargo build --release
```

* On Apple Mac M1/M2 host

Build Rust Docker image

```console
docker build -t rust -f rust.Dockerfile .
```

then

```console
docker run --rm -ti  -v $(pwd):/usr/src/vanadium -w /usr/src/vanadium rust:latest
cd app/bitcoin
cargo build --release --target aarch64-unknown-linux-gnu
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

* On Linux x86_64 host:

```
cargo test -- --test-threads=1
```

* On Apple Mac M1/M2 host

```
cargo test --target aarch64-unknown-linux-gnu -- --test-threads=1
```