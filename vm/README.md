This is the Vanadium VM app that is installed natively on a Ledger device (or emulated via speculos).

## Compiling the app

Compile on NanoS+ using ledger-app-builder:

```shell
docker run --rm -ti -u $(id -u):$(id -g) -v "$(realpath .):/app" -v "$(realpath .)/../c-sdk:/c-sdk" --privileged -v "/dev/bus/usb:/dev/bus/usb" ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest bash -c "make clean; BOLOS_SDK=\$NANOSP_SDK make -j"
```

Note the additional `-v` parameter for the `c-sdk` volume, which typical apps do not have.

## Tests

```shell
cmake -Bbuild -Htests/
make -C build/
make -C build/ test
```
