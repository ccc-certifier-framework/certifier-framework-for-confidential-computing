# Simple App under Open Enclave (OE) SDK

This document gives detailed instructions for building and running the sample application
under [Open Enclave SDK](https://github.com/openenclave/openenclave) and generating
policy for the Certifier Service using the policy utilities.

The structure of an OE application is different from other applications in sample_apps because
of the partitioning of the application into "trusted" and "untrusted" portions.  So, unlike
other applications, there is not a single "example_app.cc" that gets built. Instead, the simple
application is split into the host and enclave parts. The normal Certifier interfaces used by
other simple apps are now wrapped as ECALLs that can be called by the host application into the
enclave.

$CERTIFIER_PROTOTYPE is the top level directory for the Certifier repository.
It is helpful to have a shell variable for it, e.g.,:

```shell
export CERTIFIER_PROTOTYPE=~/Projects/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the example application.  Again, a shell variable
is useful.

```shell
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app_under_oe
```
**NOTE**: Different components of the build use different versions of the `protoc` compiler.
This will affect your build. The driving protobuf definition in `src/certifier.proto`
is used to build the utility programs using the default `protoc` compiler.
The "trusted" enclave part of the application uses a specific version of the
compiler from `openenclave_test/protobufs-bin/bin/protoc` . Protobuf-related
files generated while building the utility programs are incompatible with
this `openenclave_test` version of `protoc`.

You have to do some manual management of generated files as part of the build
process, as documented below. The [./run_example.sh](./run_example.sh) takes
care of this internally.

----
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

Similarly, invoke the wrapper shell script as: `$ LOCAL_LIB=/usr/local/lib64 run_example.sh simple_app_under_oe [setup]`

## Step 2:  Create a directory for the provisioning files
``` shell
mkdir $EXAMPLE_DIR/provisioning
```

## Step 3: Generate the policy key and self-signed certificate

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe     \
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
      --input=policy_cert_file.bin                    \
      --output=../policy_key.cc
```

## Step 5: Compile example_app with the embedded policy_key
 
To avoid incompatibilities in the format of protobuf-generated files, you
need to delete any previously generated files.

```shell
cd $CERTIFIER_PROTOTYPE/utilities
rm -rf certifier.pb.cc
cd $CERTIFIER_PROTOTYPE/include
rm -rf certifier.pb.h
```

Build the example_app as follows:

```shell
cd $EXAMPLE_DIR
make
make dump_mrenclave
```

## Step 6: Produce bin file containing the application measurement

In addition to making the binary, above `make` will provide instructions to produce
the binary_trusted_measurements_file.bin containing the application measurement.
Follow these instructions.

## Author the policy for the security domain and produce the signed claims the apps need.

The policies can be generated either manually or through the Policy Generator tool.
In the steps below, follow either step (7), below, or step (8),
 [Use Automated Policy Generator](#Step-8-Use-Automated-Policy-Generator).

```shell
cd $EXAMPLE_DIR/provisioning
```
## Step 7: Manual policy generation

### a. Construct policyKey says platformKey is-trusted-for-attestation

 ```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe          \
      --measurement_subject=binary_trusted_measurements_file.bin  \
      --verb="is-trusted"                                         \
      --output=ts1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe       \
      --key_subject=policy_key_file.bin                           \
      --verb="says"                                               \
      --clause=ts1.bin                                            \
      --output=vse_policy1.bin
```

### b. Produce the signed claims for each vse policy statement.

```shell
$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
          --vse_file=vse_policy1.bin                                    \
          --duration=9000                                               \
          --private_key_file=policy_key_file.bin                        \
          --output=signed_claim_1.bin
```

### c. Combine signed policy statements for Certifier Service use.

```shell
$CERTIFIER_PROTOTYPE/utilities/package_claims.exe     \
         --input=signed_claim_1.bin                   \
         --output=policy.bin
```

### d. [optional] Print the policy
```shell
$CERTIFIER_PROTOTYPE/utilities/print_packaged_claims.exe --input=policy.bin
```

## Step 8: Use Automated Policy Generator

### a. Edit policy file

Open `simple_app_under_oe/oe_policy.json` and replace trusted measurements
in the "measurements" property with the expected measurement from
`make dump_mrenclave`.

### b. Build the Policy Generator

```shell
cd $CERTIFIER_PROTOTYPE/utilities
LOCAL_LIB=/usr/local/lib64 make -f policy_generator.mak
```

### c. Run Policy Generator

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/policy_generator.exe                      \
         --policy_input=../oe_policy.json                                  \
         --schema_input=$CERTIFIER_PROTOTYPE/utilities/policy_schema.json  \
         --util_path=$CERTIFIER_PROTOTYPE/utilities
```

### c. [optional] Print the policy
```shell
$CERTIFIER_PROTOTYPE/utilities/print_packaged_claims.exe --input=policy.bin
```

## Step 9: Build SimpleServer
You should have gotten the protobuf compiler (protoc) for Go when you got Go.
If not, do:

```shell
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```

Compile the protobuf

```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/certprotos

protoc --go_opt=paths=source_relative --go_out=. --go_opt=M=certifier.proto ./certifier.proto
```

Compile the oelib for OE host verification
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/oelib

make
```

If you do not have OpenEnclave SDK installed or do not want to enable OpenEnclave:
```shell
make dummy
```

Compile the teelib for running the certifier service inside a TEE
```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/teelib

make
```

This should produce a go file for the certifier protobufs called certifier.pb.go in certprotos.
Now build simpeserver:

```shell
cd $CERTIFIER_PROTOTYPE/certifier_service
go build simpleserver.go
```

## Step 10: Create directories for app data and service data
```shell
cd $EXAMPLE_DIR
mkdir app1_data app2_data service
```

## Step 10: Provision the app files

Note: These files are required for the "simulated-enclave" which cannot measure the
example app and needs a provisioned attestation key and platform cert.  On real
hardware, these are not needed.

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

## Step 12: Start the Certifier Service
In a new terminal window:

```shell
cd $EXAMPLE_DIR/service
$CERTIFIER_PROTOTYPE/certifier_service/simpleserver \
      --policyFile=policy.bin --readPolicy=true
```

## Step 13:  Run the apps and get admission certificates from Certifier Service
Open two new terminals (one for the app as a client and one for the app as a server):

In app-as-a-client terminal run the following:

```shell
cd $EXAMPLE_DIR
./host/host enclave/enclave.signed cold-init $EXAMPLE_DIR/app1_data
./host/host enclave/enclave.signed get-certified $EXAMPLE_DIR/app1_data
```

In app-as-a-server terminal run the following:

```shell
cd $EXAMPLE_DIR
./host/host enclave/enclave.signed cold-init $EXAMPLE_DIR/app2_data
./host/host enclave/enclave.signed get-certified $EXAMPLE_DIR/app2_data
```

At this point, both versions of the app have their admission certificates.  You can look at
the output of the terminal running simpleserver for output.  Now all we have to do is have
the apps connect to each other for the final test.

The Certifier Service is no longer needed at this point.


## Step 14:  Run the apps to test trusted services

In app as a server terminal run the following:
```shell
cd $EXAMPLE_DIR
./host/host enclave/enclave.signed run-app-as-server $EXAMPLE_DIR/app2_data
```

In app as a client terminal run the following:
```shell
cd $EXAMPLE_DIR
./host/host enclave/enclave.signed run-app-as-client $EXAMPLE_DIR/app1_data
```

You should see the message "Hi from your secret server" in the client terminal window and
"Hi from your secret client".

If so, **Congratulations! Your first Confidential Computing program worked!**
