> **Note:** This repository is archived and no longer maintained. Check out the new [vanadium](https://github.com/LedgerHQ/vanadium).


# DISCLAIMER

:warning: | THIS IS AN EXPERIMENTAL PROJECT.<br/>Please don't start depending on it, and do not use it in production. Large parts of this project are subject to change, and there might be critical vulnerabilities.<br/>This is an open source project developed by a dedicated team in Ledger, but it is not an official Ledger product. | :warning:
:---: | :--- | :---

---

## Vanadium

The *Vanadium* project allows running any app on Ledger Nano devices (X, S+, Stax) without restrictions such as memory limitations. Basically, the Ledger Nano runs a VM which can launch any app ; the (unlimited) memory is exported encrypted on the PC or the smartphone of the user.

For developers, development is now standard since there's no restriction on the stack, heap nor code size. Modern software stack can be used (which implies standard toolchains, tests, fuzzing tools and standard libraries) along usual development patterns. The code is totally independent from the firmware and the same app is compatible with Nano X, Nano S+ and Stax. An emulator such as speculos isn't required anymore and apps can be developed in Rust.

For end-users, it means that there's no restrictions on the number of apps since there's no app install anymore: all supported apps are immediately available. In a similary way, there are no no app updates anymore, app version is always the latest. Regarding the transport, there's no USB or BLE deconnection when switching from an app to another.


### Usage

(Excerpt from [docs/app-dev.md](docs/app-dev.md)).

1. Run the VM with speculos: `speculos.py --model nanox vm/bin/app.elf`
2. Launch the app: `./host/stream.py --speculos --app ./app/build/app-swap/app-swap`


### Code

A few apps are available in the [app/](app/) folder:

- [rust](app/rust/): the first demo app written in Rust; implements some features of the Exchange app.
- [bitcoin](app/bitcoin/): a clone of the Ledger bitcoin app.

The Nano RISC-V VM app is in [vm/](vm/) and Python tools to interact with the VM app are in [host/](host/).

The [Vanadium Rust SDK](rust-sdk) is used by all the Rust apps, providing an interface to the _ecalls_ that allow access to privileged calls from the emulated apps. It is linked together with the [C SDK](c-sdk).

Once the project will be adopted more broadly, it will be split into several repositories. Meanwhile, it's more convenient to work on a mono-repo.

[![Build and test apps](https://github.com/LedgerHQ/vanadium/actions/workflows/apps.yml/badge.svg)](https://github.com/LedgerHQ/vanadium/actions/workflows/apps.yml)
[![Build and test the Nano VM](https://github.com/LedgerHQ/vanadium/actions/workflows/vm.yml/badge.svg)](https://github.com/LedgerHQ/vanadium/actions/workflows/vm.yml)
[![Build container images](https://github.com/LedgerHQ/vanadium/actions/workflows/build-packages.yml/badge.svg)](https://github.com/LedgerHQ/vanadium/actions/workflows/build-packages.yml)


### Documentation

Technical and usage information can be found in the [docs/](docs/) folder, and in the various subfolders of the project.


### Licensing

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.


### Community

Feel free to join the [#streaming-project](https://discord.com/channels/885256081289379850/1052612612837355682) discord channel.
