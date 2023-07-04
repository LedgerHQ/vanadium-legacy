
Install protobuf v3.30.2 using the instructions below:

https://grpc.io/docs/protoc-installation/#install-pre-compiled-binaries-any-os

Then generate python modules from protobuf definitions with:

$ protoc -I=../src/message --python_out=. ../src/message/message.proto


Run the VM on speculos, or on a device, then run the client with:

$ ./bitcoin.py --speculos --app ./target/riscv32i-unknown-none-elf/release/vnd-bitcoin

(remove `--speculos` if using a real device)