
Install protobuf using the instructions below:

https://grpc.io/docs/protoc-installation/#install-pre-compiled-binaries-any-os

Then generate python modules from protobuf definitions with:

$ protoc -I=../src/message --python_out=. ../src/message/message.proto

Run the VM on speculos, or on a device, then run the client with:

$ ./client.py --speculos --app ../target/riscv32imc-unknown-none-elf/release/demo

(remove `--speculos` if using a real device)