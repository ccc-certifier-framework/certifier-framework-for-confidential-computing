# Certifier API Test Sample for Open Enclave on SGX

## Introduction

This is a sample SGX application developed with the Open Enclave SDK. It tests
basic Certifier APIs and does not include the Certifier service components. It
serves the purpose of helping you setup the Open Enclave SGX development
environment for the Certifier.

The [Open Enclave SDK](https://github.com/openenclave/openenclave)
is a hardware-agnostic open source library for developing
applications that utilize Hardware-based Trusted Execution Environments, also
known as Enclaves.

## Instructions for building and running the test

$CERTIFIER_PROTOTYPE is the top level directory for the certifier repository.
It is helpful to have a shell variable for it, e.g., :

```shell
export CERTIFIER_PROTOTYPE=~/Projects/certifier-framework-for-confidential-computing
```

----

## Step 1: Setup Open Enclave SDK with SGX

Follow instructions in
[Open Enclave SDK Getting Started](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs)
to have SGX configured and the SDKs installed on your development machine.

More specifically, follow the instructions
[here](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_20.04.md)
to setup Intel SDK/Driver, before installing the Open Enclave SDK. After this
is done successfully, run the [Open Enclave SDK Attestation
Example](https://github.com/openenclave/openenclave/blob/master/samples/attestation/README.md)
to verify that everything is configured correctly.

We tested Open Enclave 0.17 and 0.18 using clang-10.

## Step 2a: Build the Certifier Utilities

```shell
cd $CERTIFIER_PROTOTYPE/utilities

make -f cert_utility.mak
make -f policy_utilities.mak
```

The bare-minimum required for this sample application work is to build the
`measurement_init` utility:

```shell
cd $CERTIFIER_PROTOTYPE/utilities

make -f cert_utility.mak measurement_init.exe
```

## Step 2(b): Build the Open Enclave protobuf

The Certifier API requires protobuf. For the SGX enclave environment, we a
statically compiled protobuf archive to be built into the enclave binary.
Additionally, the matching `protoc` command needs to be available on the
development host.

If you do not see these and the headers inside the
$CERTIFIER_PROTOTYPE/openenclave_test/protobufs-bin directory, you will need
to build and install them first. When the Open Enclave SDK integrates protobuf
in the future, we will be able to live without these.

- \$OE_SOURCE is the Open Enclave SDK source directory
- \$OE_BIN is the Open Enclave SDK installation directory
- \$PROTO_BIN is the protobuf installation directory

## Step 2(b).1: Download protobuf

Download the protobuf versions you want from
https://github.com/protocolbuffers/protobuf/releases

## Step 2(b).2: Build protobuf for the development host (e.g., Ubuntu 20.04)

```shell
git clone https://github.com/protocolbuffers/protobuf.git
cd protobuf

git submodule update --init --recursive

./autogen.sh
./configure --prefix=$(PROTO_BIN) --disable-shared CC=clang-10 CXX=clang++10

make
make check
make install
```

The protobuf libraries in the installation directory is built for the host
after this step and not ready for the enclave. We need to rebuild the libraries
for the enclave environment.

## Step 2(b).3: Rebuild protobuf libraries for the enclave

```shell
 cd protobuf

 export LIBCXX_LIBRARY_DIR=$(OE_BIN)/share/pkgconfig/../../lib/openenclave/enclave
 export LIBCXX_SOURCE_DIR=$(OE_SOURCE)/3rdparty/libcxx/libcxx

 ./configure --prefix=$(PROTO_BIN) --disable-shared CC=clang-10 CXX=clang++-10 \
 CXXFLAGS="-c -nostdinc++ -nostdlib++ -m64 -fPIE -ftls-model=local-exec -fvisibility=hidden \
 -fstack-protector-strong -fno-omit-frame-pointer -ffunction-sections -fdata-sections -mllvm \
 -x86-speculative-load-hardening \
 -I$(OE_BIN)/share/pkgconfig/../../include/openenclave/3rdparty/libcxx \
 -I$(OE_BIN)/share/pkgconfig/../../include/openenclave/3rdparty/libc \
 -I$(OE_BIN)/share/pkgconfig/../../include/openenclave/3rdparty \
 -I$(OE_BIN)/share/pkgconfig/../../include" \
 LDFLAGS="-nostdinc++ -nostdlib++ -nodefaultlibs -nostartfiles -Wl,--no-undefined -Wl,-Bstatic \
 -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -Wl,--build-id -Wl,-z,noexecstack -Wl,-z,now -Wl,\
 -gc-sections -L${LIBCXX_LIBRARY_DIR} -Wl,-rpath,${LIBCXX_LIBRARY_DIR} -loelibcxx"

 make
 ```

You will get some warnings and the protoc tool generated will not be usable on
your development host.

NOTE: You **SHOULD NOT** DO `make install` at this point. Instead
copy the generated archives to \$PROTO_BIN manually.

```shell
cp -p protobuf/src/.libs/libprotobuf.a $PROTO_BIN/lib/
cp -p protobuf/src/.libs/libprotobuf-lite.a $PROTO_BIN/lib/
```

## Step 2(b).4: Replace protobufs-bin in openenclave_test

```shell
cd $CERTIFIER_PROTOTYPE/openenclave_test
rm -rf protobufs-bin
cp -pr $PROTO_BIN ./protobufs-bin
```

## Step 3: Build the Certifier API Test Sample Application

```shell
cd $CERTIFIER_PROTOTYPE/openenclave_test
make
```

The build will produce the untrusted and trusted (enclave) part binaries along
with a signed enclave binary called `enclave.signed` in the enclave directory
ready for SGX.

Now, dump the enclave measurement (mrenclave) using the following command:

```shell
cd $CERTIFIER_PROTOTYPE/openenclave_test
make dump_mrenclave
```

The output will look something like the following:

    oesign dump --enclave-image=./enclave/enclave.signed

    === Entry point:
    name=_start
    address=0x0000000018e77c

    === SGX Enclave Properties:
    product_id=1
    security_version=1
    debug=1
    xfrm=0000000000000000
    num_heap_pages=1024
    num_stack_pages=1024
    num_tcs=2
    mrenclave=c33b590742e20c440b9d474cf64aaa2db483d3e9f5aba95122c8e03ff1dca5f1
    mrsigner=...
    signature=...

Notice the line that starts with `mrenclave=`. Copy the hex string after the =
sign and configure the expected measurement of the enclave for the Certifier by
issuing the following command:

```shell
measurement_init.exe \
     --mrenclave=c33b590742e20c440b9d474cf64aaa2db483d3e9f5aba95122c8e03ff1dca5f1 \
     --out_file=/tmp/binary_trusted_measurements_file.bin
```

`measurement_init.exe` is the utility you built in Step 2.

A file containing the trusted measurement of the enclave will be saved to the
/tmp directory on your development machine. Notice that you will need to redo this 
every time you modified and recompiled the enclave because the expected measurement 
of the enclave will change afterwards.

## Step 4: Run the Certifier API Test Sample Application

To run the application, simply do:

```shell
cd $CERTIFIER_PROTOTYPE/openenclave_test

make run
```

You should get the results similar to the following:

```shell
make run
    host/host enclave/enclave.signed
    Initializing certifier

    Calling certifier_test_sim_certify
    Test succeeded!

    Calling certifier_test_local_certify
    Test succeeded!

    Calling certifier_test_seal
    Test succeeded!
```
