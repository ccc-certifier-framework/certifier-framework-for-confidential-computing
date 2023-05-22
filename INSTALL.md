Installing The Certifier Framework for Confidential Computing 
=============================================================

In this description, the top level directory of this repository,
which includes this INSTALL.md file, is denoted $(CERTIFIER).

The Ubuntu 20.04 install guide can be found in
[Ubuntu Install](./Doc/install-certifier-Ubuntu-20.04.md).

Read the [Guide](Doc/Guide.pdf) in the Doc directory to understand the
basic nomenclature and programs you will build and use.


# Certifier API

The certifier API is in the src/ directory.

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
```

## To compile and run the certifier API tests

```shell
  $ cd $(CERTIFIER)/src
  $ make -f certifier_tests.mak clean
  $ make -f certifier_tests.mak
  $ ./certifier_tests.exe [--print_all=true]
```
If you are compiling the certifier tests win sev enabled (This is
indicated by ENABLE_SEV=1 in the [certifier_tests.mak](src/certifier_tests.mak) file),
you must run the tests as root and must install the simulated SEV driver (see
below).

```shell
$ sudo ./certifier_tests.exe --print_all=true
```

Otherwise

```shell
$ ./certifier_tests.exe --print_all=true
```

should work fine.

Once you are sure the certifier works, compile and make the certifier library:

```shell
 $ cd $(CERTIFIER)/src
 $ make -f certifier.mak clean
 $ make -f certifier.mak
```

# Certifier Service

The certifier service is in the [certifier_service](./certifier_service/) directory
and contains two subdirectories: [certlib](./certifier_service/certlib/) and
[certprotos](./certifier_service/certprotos/).

To compile the certlib tests:

  ```shell
  $ cd $(CERTIFIER)/certifier_service/certprotos
  $ protoc --go_opt=paths=source_relative --go_out=. --go_opt=Mcertifier.proto= ./certifier.proto
  $ cd ../certlib
  $ go test
```
To compile and run the Certifier Service and test it, follow
the [instructions](./sample_apps/simple_app/instructions.txt)
in the [sample_apps/simple_app](./sample_apps/simple_app/) example.


# Utilities

There are utilities in the utilities subdirectory.  To compile them:

```shell
$ cd $(CERTIFIER)/utilities
$ make -f cert_utility.mak clean
$ make -f cert_utility.mak
$ make -f policy_utilities.mak clean
$ make -f policy_utilities.mak
```

If you wish to use the Policy Generator instead of manually composing the
policies, you need to build it in utilities. The Policy Generator requires the
json-schema-validator library which in turn depends on the JSON for Modern C++
library. Follow the following instructions to have them built and installed on
your system:

```shell
$ cd $(CERTIFIER)/utilities
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

Both libraries should be installed under /usr/local by default. If this is not
the case, remember to update the JSON_VALIDATOR variable in
policy_generator.mak. Add /usr/local/lib to /etc/ld.so.conf and run ldconfig if
not already done.

The Policy Generator utility can then be built using:

```shell
$ cd $(CERTIFIER)/utilities
$ make -f policy_generator.mak
```

There is a Linux driver that simulates the SEV functions in sev-snp-simulator.
Portions of this code are GPL licensed and the build driver is also GPL licensed.
This is the only directory that contains GPL licensed code and it is not included in
the certifier API or certifier service, so all other code in the Certifier Framework
for Confidential Computing is not affected by GPL license terms.

To build this and install it on Linux: (RESOLVE: These steps did not work; got diff errors. Sort it out during review.)

```shell
$ cd $(CERTIFIER)/sev-snp-simulator
$ make sev-guest
$ sudo make insmod     # (You must be root to install the module)
$ cd $(CERTIFIER)/sev-snp-simulator/test
$ make sev-test
$ sudo sev-test        # (You must be root to run the test)
```

To compile the sample app in [sample_apps/simple_app](sample_apps/simple_app/):

```shell
$ cd $(CERTIFIER)/sample_apps/simple_app
$ make -f example_app.mak clean
$ make -f example_app.mak
```

Instructions on running the app are in
[instructions.txt](./sample_apps/simple_app/instructions.txt)
as well as notes on provisioning a policy key in
[policy_key_notes.txt](./sample_apps/simple_app/policy_key_notes.txt).

This example illustrates very nearly all that is needed to run a "real" app.

There is also an application service that provides Confidential Computing
support for application programs on encrypted virtual machine platforms.
For instructions on building and running this service in an encrypted
virtual machine, read application_service/instructions.txt.

Most programs can use a "simulated_enclave" for prototyping and can compile
and run on linux or mac os.  To run programs that use SGX, you must run on
SGX capable hardware.  We use Open Enclaves or Asylo to support SGX.
To run programs that use AMD SEV-SNP, you must run on AMD SEV-SNP hardware
under a compliant VMM and in a VM that supports AMD SEV-SNP primitives.


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

We use git as the repository framework.

You must install these as well as standard C++ compilers and libraries.  The
Certifier Service is written in Go, so you also need to install that to build and use
the Certifier Service.

