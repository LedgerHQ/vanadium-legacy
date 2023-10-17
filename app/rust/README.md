## Rust app for Linux or RISC-V targets
### Pre-requisites

1. Compile the C SDK
   * for [native](../../c-sdk/README.md#build-for-native-target) target
   * for [RISC-V](../../c-sdk/README.md#build-for-risc-v-target) target

2. Some libraries are required to build the app:
   * `libc.a` to build the app for a RISC-V target
   * `libcrypto.a` to run tests on a Linux target

   These libraries can be retrieved from Docker images thanks to the script:
   ```console
   ./lib/create-lib.sh
   ```
   They are also generated as artifacts by the [GitHub CI](https://github.com/LedgerHQ/vanadium/actions/workflows/apps.yml).
2. Build the Rust Docker image 
   ```console
   docker build -t rust -f rust.Dockerfile .
   docker run --rm -ti  -v $(pwd):/usr/src/vanadium -w /usr/src/vanadium/app/rust rust:latest
   ```

### Building
#### For RISC-V target
```console
cargo build --release
```
#### For Linux aarch64 (Mac M1/M2) target
```console
cargo build --release --target aarch64-unknown-linux-gnu
```
#### For Linux x86_64 target
```console
cargo build --release --target x86_64-unknown-linux-gnu
```

### Testing (Linux only)
Tests are ran on native thanks to `libspeculos.so`.

`--test-threads=1` is required because `libspeculos.so` isn't thread safe.
#### For Linux aarch64 target
```console
docker run --rm -ti  -v $(pwd):/usr/src/vanadium -w /usr/src/vanadium rust:latest
cd app/rust
cargo test --target aarch64-unknown-linux-gnu -- --test-threads=1
```
#### For Linux x86_64 target
```console
docker run --rm -ti  -v $(pwd):/usr/src/vanadium -w /usr/src/vanadium rust:latest
cd app/rust
cargo test --target x86_64-unknown-linux-gnu -- --test-threads=1
```
## Notes

- Find which functions take the most of space with `cargo install bloat && cargo bloat --release -n 10`
