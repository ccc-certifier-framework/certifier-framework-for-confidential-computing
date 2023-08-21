# Simple App under Islet SDK

This document gives detailed instructions for building and running the sample
application under the [Islet SDK](https://github.com/Samsung/islet) which
implements the [ARMv9 Confidential Computing Architecture CCA](https://www.arm.com/architecture/security-features/arm-confidential-compute-architecture)
specification.

## Overview

This app is similar to the application in
[simple_app](../simple_app/example_app.cc) but currently runs under an
Islet-shim interface.

This sample application demonstrates a simple client and server setup that
can certify with the Certifier Service to get admission certificates.
Once certified, the client and server can talk to each other through a
mutually trusted and authenticated TLS connection.


## Software Repositories

$CERTIFIER_PROTOTYPE is the top level directory for the Certifier repository.
It is helpful to have a shell variable for it, e.g.,:

```shell
export CERTIFIER_PROTOTYPE=~/Projects/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the example application.  Again, a shell variable
is useful.

```shell
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app_under_islet
```

### Setup Islet SDK

This sample app requires the Islet SDK. Follow these instructions to download
and build the Islet SDK

```shell

cd $CERTIFIER_PROTOTYPE/src/islet

$CERTIFIER_PROTOTYPE/third_party/islet/setup.sh
```

This should build the required libislet_sdk.so in $CERTIFIER_PROTOTYPE/third_party/islet/lib .
```shell
export LD_LIBRARY_PATH=$CERTIFIER_PROTOTYPE/third_party/islet/lib
```
-------

## Step 1: Build the utilities

The build process requires access to Open-SSL libraries. The default path specified in the
[utilities/policy_utilities.mak](../../utilities/policy_utilities.mak) is /usr/local/lib .
If in your installation, these libraries exist elsewhere, you can override the library
path as shown in the example below:

```shell
cd $CERTIFIER_PROTOTYPE/utilities
make -f cert_utility.mak clean
LOCAL_LIB=/usr/local/lib64 make -f cert_utility.mak
LOCAL_LIB=/usr/local/lib64 make -f policy_utilities.mak
```

Similarly, invoke the wrapper shell script as:
```shell
$ LOCAL_LIB=/usr/local/lib64 run_example.sh simple_app_under_islet [setup | run_test]
```

## Step 2:  Create a directory for the provisioning files
``` shell
mkdir $EXAMPLE_DIR/provisioning
```

## Step 3: Generate the policy key and self-signed certificate

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe       \
    --operation=generate-policy-key-and-test-keys     \
    --policy_key_output_file=policy_key_file.bin      \
    --policy_cert_output_file=policy_cert_file.bin    \
    --platform_key_output_file=platform_key_file.bin  \
    --attest_key_output_file=attest_key_file.bin
```

This will also generate the attestation key and platform key for these tests.

## Step 4: Embed the policy key in example_app.

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/embed_policy_key.exe \
      --input=policy_cert_file.bin                  \
      --output=../policy_key.cc
```

## Step 5. Build Islet-Certifier app

First, the `make` builds a binary that is run with the Islet SDK library.

```shell
cd $EXAMPLE_DIR

make -f islet_example_app.mak clean
make -f islet_example_app.mak
```
## Step 6. Obtain the measurement of the trusted application for this security domain

Currently, we offer shim-support for the Islet APIs. Use a hard-coded measurement
for the Islet enclave.

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/measurement_init.exe                              \
    --mrenclave=6190EB90B293886C172EC644DAFB7E33EE2CEA6541ABE15300D96380DF525BF9 \
    --out_file=example_app.measurement
```

## Step 7. Author the policy for the security domain and produce the signed claims the apps need

### Write the policy

This is a temporary fix for use with the Islet-shim support

```shell
cd $EXAMPLE_DIR/provisioning

cp -p policy_cert_file.bin cca_emulated_islet_key_cert.bin
```

### a. Construct policyKey says platformKey is-trusted-for-attestation
```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
    --cert-subject=cca_emulated_islet_key_cert.bin          \
    --verb="is-trusted-for-attestation"                     \
    --output=ts1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe \
    --key_subject=policy_key_file.bin                       \
    --verb="says"                                           \
    --clause=ts1.bin                                        \
    --output=vse_policy1.bin
```

### b. Produce the signed claims for each vse policy statement.

```shell
$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
    --vse_file=vse_policy1.bin                                          \
    --duration=9000                                                     \
    --private_key_file=policy_key_file.bin                              \
    --output=signed_claim_1.bin
```

### c. Construct policy key says measurement is-trusted
```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
    --key_subject=""                                        \
    --measurement_subject=example_app.measurement           \
    --verb="is-trusted"                                     \
    --output=ts2.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe     \
    --key_subject=policy_key_file.bin                           \
    --verb="says"                                               \
    --clause=ts2.bin                                            \
    --output=vse_policy2.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe \
    --vse_file=vse_policy2.bin                                       \
    --duration=9000                                                  \
    --private_key_file=policy_key_file.bin                           \
    --output=signed_claim_2.bin
```

### d. Combine signed policy statements for Certifier Service use
```shell
$CERTIFIER_PROTOTYPE/utilities/package_claims.exe   \
    --input=signed_claim_1.bin,signed_claim_2.bin   \
    --output=policy.bin
```

### step e. [optional] Print the policy
```shell
$CERTIFIER_PROTOTYPE/utilities/print_packaged_claims.exe \
    --input=policy.bin
```

## Step 8: Build SimpleServer

### a. Compile the protobuf and the C-Go interface
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/certprotos

protoc --go_opt=paths=source_relative \
       --go_out=.                     \
       --go_opt=M=certifier.proto     \
       ./certifier.proto
```

This should produce a Go file for the certifier protobufs called
certifier.pb.go in certprotos.

```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/oelib
make dummy

cd $CERTIFIER_PROTOTYPE/certifier_service/graminelib
make dummy

cd $CERTIFIER_PROTOTYPE/certifier_service/isletlib
make

cd $CERTIFIER_PROTOTYPE/certifier_service/teelib
make
```

### b. Now build simpleserver:
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service

go build simpleserver.go
```

## Step 9: Create directories for app data

```shell
cd $EXAMPLE_DIR
mkdir -p app1_data app2_data service
```

## Step 10: Provision the app files
```shell
cd $EXAMPLE_DIR/provisioning
cp -p ./* $EXAMPLE_DIR/app1_data
cp -p ./* $EXAMPLE_DIR/app2_data
```

## Step 11: Provision the service files
```shell
cd $EXAMPLE_DIR/provisioning
cp -p policy_key_file.bin policy_cert_file.bin policy.bin $EXAMPLE_DIR/service
```

## Step 12:  Start the Certifier Service

In a new terminal window:

```shell
cd $EXAMPLE_DIR/service

$CERTIFIER_PROTOTYPE/certifier_service/simpleserver \
    --policyFile=policy.bin                         \
    --readPolicy=true
```

## Step 13: Run the apps after getting admission certificates from Certifier Service

Open two new terminals (one for the app as a client and one for the app as a server):

In app-as-a-server terminal run the following:

```shell
cd $EXAMPLE_DIR

$EXAMPLE_DIR/islet_example_app.exe                       \
      --data_dir=./app2_data/                      \
      --operation=cold-init                        \
      --measurement_file="example_app.measurement" \
      --policy_store_file=policy_store
      --print_all=true

$EXAMPLE_DIR/islet_example_app.exe                       \
      --data_dir=./app2_data/                      \
      --operation=get-certified                    \
      --measurement_file="example_app.measurement" \
      --policy_store_file=policy_store             \
      --print_all=true
```

In app-as-a-client terminal run the following:

```shell
cd $EXAMPLE_DIR

$EXAMPLE_DIR/islet_example_app.exe                       \
      --data_dir=./app1_data/                      \
      --operation=cold-init                        \
      --measurement_file="example_app.measurement" \
      --policy_store_file=policy_store
      --print_all=true

$EXAMPLE_DIR/islet_example_app.exe                       \
      --data_dir=./app1_data/                      \
      --operation=get-certified                    \
      --measurement_file="example_app.measurement" \
      --policy_store_file=policy_store             \
      --print_all=true
```

At this point, both versions of the app have their admission certificates.
Output and results are printed on each of the terminals running the app and
the service.

Now all we have to do is have the apps connect to each other for the final test.
The Certifier Service is no longer needed at this point.

### a. In the app-as-a-server terminal run the following:

```shell

cd $EXAMPLE_DIR

$EXAMPLE_DIR/islet_example_app.exe           \
      --data_dir=./app2_data/          \
      --operation=run-app-as-server    \
      --policy_store_file=policy_store \
      --print_all=true
```

### b. In the app-as-a-client terminal run the following:

```shell
cd $EXAMPLE_DIR

$EXAMPLE_DIR/islet_example_app.exe           \
      --data_dir=./app1_data/          \
      --operation=run-app-as-client    \
      --policy_store_file=policy_store \
      --print_all=true
```

You should see the message "Hi from your secret server" in the client terminal window and
"Hi from your secret client".

If so, **Congratulations! Your first Confidential Computing program worked!**
