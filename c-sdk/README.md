This is Vanadium's C SDK. It can be compiled for both the RISC-V and Linux native targets, and contains the interface to the ecalls that are exported by the VM (in particular, the ones allowing access to Bolos syscalls).

- When compiled towards RISC-V target, direct ecalls are used. 
- When compiled towards NATIVE target, the corresponding implementation from speculos are used instead.

Compiling the C SDK is a pre-requisite for the [Rust sdk](../rust-sdk/), and for any app using Rust :crab: SDK.

## Build for RISC-V target

### Build the Docker image to have a ready-to-use RISC-V toolchain
#### Linux x86_64 host
```console
docker build -t riscv .
```
#### Apple M1/M2 host 
[Dockross](https://github.com/dockcross/dockcross) `linux-riscv32` image shall be rebuilt

```console
git clone git@github.com:dockcross/dockcross.git
cd dockcross
make base
make linux-riscv32
```

### Build C-sdk
```console
$ ./docker.sh riscv
[root:/c-sdk] # cmake -Bbuild -H.
[root:/c-sdk] # make -C build/
```
## Build for Native target
### Build the docker image
```console
docker build -t native -f native.Dockerfile .
```
### Build C-sdk
```console
$ ./docker.sh native
[root:/c-sdk] # cmake -Bbuild/native/ -H. -DNATIVE=1
[root:/c-sdk] # make -C build/native/
```
