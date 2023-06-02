## [ISLET](https://github.com/Samsung/islet/)
An on-device confidential computing framework by leveraging ARMv9 CCA.

## ISLET SDK
An open source SDK which provides confidential computing primitives to enclaves.

## [CCA Shim](./cca_shim.cc)
A shimmed layer between `Certifier` and `CCA` that emulates the functions of the HW without any HW or emulator.

## SW Components
```
Certifier API
-------------
CCA Shim
-------------
ISLET SDK
-------------
Host (x86_64)
```

## How to build applications on x86_64
### Clone ISLET SDK & Setup Rust environment & Build the library
```sh
$ ../../third_party/islet/setup.sh
```

### Build [the sample app](./islet_test/shim_test.cc) and Run it
Check `User data` and `Measurement` parsed from the attestation report.

```sh
$ cd islet_test
$ make shim_test

What was said: User Custom data
Measurement: 6190EB90B293886C172EC644DAFB7E33EE2CEA6541ABE15300D96380DF525BF9
Attestation test succeeded.
Success sealing round trip.
Sealing test succeeded.
```
