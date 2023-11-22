# Dockerfile to build RISC-V rust binaries
#
# docker build -t rust -f rust.Dockerfile .

FROM rust:latest

RUN rustup default nightly
RUN rustup target add --toolchain=nightly riscv32imc-unknown-none-elf
RUN rustup component add clippy
RUN rustup component add rustfmt

# Install protoc (for Python client)
ARG PB_REL="https://github.com/protocolbuffers/protobuf/releases/download"

RUN case $(uname -m) in \
        x86_64 | amd64) \
            ARCH=x86_64;; \
        aarch64 | arm64) \
            ARCH=aarch_64;; \
        *) echo "Unkown architecture" && exit 1;; \
    esac && \
    curl -L -o protoc_installer.zip ${PB_REL}/v25.0/protoc-25.0-linux-${ARCH}.zip && \
    unzip protoc_installer.zip -d /usr/local && \
    rm protoc_installer.zip