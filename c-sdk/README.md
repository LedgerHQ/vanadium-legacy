This is Vanadium's C SDK. It can be compiled for both the RISC-V and the native targets, and contains the interface to the ecalls that are exported by the VM (in particular, the ones allowing access to Bolos syscalls).

When compiled towards the RISC-V target, direct ecalls are used. With native compilation, the corresponding implementation from speculos are used instead.

Compiling the C SDK is a pre-requisite for the [Rust sdk](../rust-sdk/), and for any app using the Rust sdk.

## Build for RISC-V target

Build the docker image to have a ready-to-use RISC-V toolchain:

```console
docker build -t riscv .
```

Build the RISC-V C sdk using the `docker.sh` script:

```console
$ ./docker.sh riscv
[root:/c-sdk] # cmake -Bbuild -H.
[root:/c-sdk] # make -C build/
```

## Build for native target

Build the docker image:

```console
docker build -t native -f native.Dockerfile .
```

Build the native C sdk using the `docker.sh` script:

From the docker image `./docker.sh native`, configure CMake to build the native binaries into `build/native/`:

```console
$ ./docker.sh native
[root:/c-sdk] # cmake -Bbuild/native/ -H. -DNATIVE=1
[root:/c-sdk] # make -C build/native/
```
