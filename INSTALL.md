# Installing The Certifier Framework for Confidential Computing

In this description, the top level directory of this repository,
which includes this `INSTALL.md` file, is denoted $CERTIFIER.

The Ubuntu 20.04 install guide can be found in
[Ubuntu Install](./Doc/install-certifier-Ubuntu-20.04.md).

Read the [Guide](./Doc/Guide.pdf) in the `Doc/` directory to understand the
basic nomenclature and programs you will build and use.

## Hardware Requirements

Most programs can use a "simulated_enclave" for prototyping and can compile
and run on Linux or macOS.

- To run programs that use SGX, you must run on SGX capable hardware.
- We use Open Enclaves or Asylo to support SGX.
- To run programs that use AMD SEV-SNP, you must run on AMD SEV-SNP hardware
  under a compliant VMM and in a VM that supports AMD SEV-SNP primitives.
  - See [SEV-SNP Simulator](#SEV-SNP-Simulator-utility) to setup a SEV-SNP
    simulator on Linux VMs to run sample app under SEV-SNP.


# Certifier API

The Certifier API is in the `src/` directory.

## Setup steps

You will need to install the following packages:

```shell
$ sudo apt-get update -y
$ sudo apt-get install -y protobuf-compiler
$ sudo apt-get install -y libgtest-dev/jammy
$ sudo apt-get install -y libgflags-dev/jammy
$ sudo apt-get install -y protoc-gen-go
$ sudo apt-get install -y golang-go
$ sudo apt-get install -y libmbedtls-dev/jammy
$ sudo apt-get install -y libssl-dev uuid-dev python3-pip swig
```

## To compile and run the Certifier API tests

```shell
  $ cd $CERTIFIER/src
  $ make -f certifier_tests.mak clean
  $ make -f certifier_tests.mak
  $ ./certifier_tests.exe [--print_all=true]
```

### Certifier API tests with SEV-enabled

If you are compiling the Certifier tests with SEV-enabled you must first install
the simulated SEV driver and then run the tests as root.

See the [SEV-SNP Simulator utility](#SEV-SNP-Simulator-utility) section
for how-to setup and install the SEV-SNP simulator.

(Running SEV-enabled tests is indicated by `ENABLE_SEV=1` in the
[certifier_tests.mak](./src/certifier_tests.mak) file.)

```shell
$ ENABLE_SEV=1 make -f certifier_tests.mak clean
$ ENABLE_SEV=1 make -f certifier_tests.mak

$ sudo ./certifier_tests.exe --print_all=true
```

------

Once you are sure the Certifier works, compile and make the Certifier library:

```shell
 $ cd $CERTIFIER/src
 $ make -f certifier.mak clean
 $ make -f certifier.mak
```

# Utilities

There are utility programs in the `utilities/` subdirectory. Different steps
in the Certifier workflow use these programs.

To compile them:

```shell
$ cd $CERTIFIER/utilities
$ make -f cert_utility.mak clean
$ make -f policy_utilities.mak clean

$ make -f cert_utility.mak
$ make -f policy_utilities.mak
```

# Certifier Service

The Certifier Service is in the [certifier_service/](./certifier_service/) directory
and contains two subdirectories: [certlib/](./certifier_service/certlib/) and
[certprotos/](./certifier_service/certprotos/).

Certlib unit-tests require some input data in test_data/ dir. Generate it as follows:

```shell
cd $CERTIFIER/certifier_service/certlib/test_data

$CERTIFIER/utilities/cert_utility.exe                 \
   --operation=generate-policy-key-and-test-keys      \
   --policy_key_output_file=policy_key_file.bin       \
   --policy_cert_output_file=policy_cert_file.bin     \
   --platform_key_output_file=platform_key_file.bin   \
   --attest_key_output_file=attest_key_file.bin
```

Setup libraries for Certifier Service to link with:

```shell
cd $CERTIFIER/certifier_service/graminelib
make dummy

cd ../oelib
make dummy

cd ../isletlib/
make dummy

cd ../teelib/
make
```

To compile the Certlib tests:

```shell
cd $CERTIFIER/certifier_service/certprotos
protoc --go_opt=paths=source_relative --go_out=. --go_opt=Mcertifier.proto= ./certifier.proto
```

Run the Certifier library unit-tests:

```shell
$ cd ../certlib
$ go test
```
To compile and run the Certifier Service and test it, follow
the [instructions](./sample_apps/simple_app/instructions.md)
in the [sample_apps/simple_app](./sample_apps/simple_app/) example.


## Building the Policy Generator - Setup Required

If you wish to use the Policy Generator instead of manually composing the
policies, you need to build the Generator in the `utilities/` directory.
The Policy Generator requires the json-schema-validator library which in turn
depends on the JSON for Modern C++ library.

Follow these instructions to have these software packages built and installed
on your system. You may be able to use the
[setup-JSON-schema-validator-for-SEV-apps.sh](./CI/scripts/setup-JSON-schema-validator-for-SEV-apps.sh)
which automates these steps in our CI-environment.

```shell
$ cd $CERTIFIER/utilities
$ git clone https://github.com/nlohmann/json.git
$ cd json
$ mkdir build
$ cd build

$ cmake ..
$ make
$ sudo make install
$ cd ..

$ git clone https://github.com/pboettch/json-schema-validator.git
$ cd json-schema-validator
$ mkdir build
$ cd build

$ cmake .. -DBUILD_SHARED_LIBS=ON ..
$ make
$ sudo make install
$ cd ..
```

Both libraries should be installed under `/usr/local` by default. If this is
not the case, remember to update the JSON_VALIDATOR variable in the
`utilities/policy_generator.mak` makefile.
Add `/usr/local/lib` to `/etc/ld.so.conf` and run ldconfig if not already done.

## Build the Policy Generator utility

The Policy Generator utility can then be built using:

```shell
$ cd $CERTIFIER/utilities
$ make -f policy_generator.mak
```

## SEV-SNP Simulator utility

There is a Linux driver in the `sev-snp-simulator/` directory that simulates
the SEV functions.

Portions of this code are GPL licensed and the build driver is also GPL licensed.
This is the only directory that contains GPL licensed code and it is not included in
the Certifier API or Certifier Service, so all other code in the Certifier Framework
for Confidential Computing is not affected by GPL license terms.

## Compile the sample app

To compile the sample app in [sample_apps/simple_app](sample_apps/simple_app/):

```shell
$ cd $CERTIFIER/sample_apps/simple_app
$ make -f example_app.mak clean
$ make -f example_app.mak
```

Instructions on running the app are in
[instructions.md](./sample_apps/simple_app/instructions.md)
and notes on provisioning a policy key are in
[policy_key_notes.md](./sample_apps/simple_app/policy_key_notes.md).

This example illustrates very nearly all that is needed to run a "real" app.

There is also an application service that provides Confidential Computing
support for application programs on encrypted virtual machine platforms.
For instructions on building and running this service in an encrypted
virtual machine, refer to
 [application_service/instructions.md](./application_service/instructions.md).


Additional packages required
----------------------------

The Certifier Framework for Confidential Computing employs code from other open
source projects including:

Google gflags which can be obtained at https://github.com/gflags/gflags,
  gflags helps deal with command line arguments and defaults.

Google gtest which can be obtained at https://github.com/google/googletest,
  gtest is a test infrastructure used in our tests.

Google protobuf which can be obtained at https://github.com/protocolbuffers/protobuf,
  protobuf is a serialization framwork.

Openssl which contains crypto libraries and TLS support.

We use Git as the repository framework.

You must install these as well as standard C++ compilers and libraries.  The
Certifier Service is written in Go, so you also need to install that to build and use
the Certifier Service.

