#!/bin/bash

# Helper to run various docker images.

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ $# -eq 0 ]; then
    image='riscv'
elif [ $# -eq 1 ]; then
    image="${1}"
else
    echo "Usage: ${0} <riscv|native|rust>"
    exit 1
fi

case ${image} in
    riscv)
        docker run -w /c-sdk -v "${SCRIPT_DIR}/c-sdk/":/c-sdk/ --rm -it riscv bash -c "cmake -Bbuild/riscv/ -H. && make -C build/riscv/ clean && make -C build/riscv/"
        ;;

    native)
        [ ! -d "ledger-secure-sdk" ] && git clone git@github.com:LedgerHQ/ledger-secure-sdk.git
        docker run -w /c-sdk \
            -v "${SCRIPT_DIR}/c-sdk/":/c-sdk/ \
            --env BOLOS_SDK_DIR=/bolos_sdk/ \
            -v $(pwd)/ledger-secure-sdk:/bolos_sdk/:ro \
            --rm -it native \
            bash -c "cmake -Bbuild/native/ -H. -DNATIVE=1 && make -C build/native/ clean && make -C build/native/"
        ;;

    *)
        echo "Invalid image name"
        exit 1
        ;;
esac