# cf_utility - Instructions

This document gives detailed instructions for buildingi and testing
cf_utility and running the examples in scenario 1 and scenario 2
as described in cf_utility_usage_notes.md.

$CERTIFIER_ROOT is the top level directory for the Certifier repository.
It is helpful to have a shell variable for it:

```shell
export CERTIFIER_ROOT=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the example application.  Again, a shell variable
is useful.

```shell
export EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
```

----
## Step 1: Build the utilities

```shell
cd $CERTIFIER_ROOT/utilities
make -f cert_utility.mak
make -f policy_utilities.mak
```

## Step 2:  Create a directory for provisioning policy files

```shell
mkdir $EXAMPLE_DIR/provisioning
```

## Step 3: Generate the policy key and self-signed certificate

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_ROOT/utilities/cert_utility.exe          \
      --operation=generate-policy-key-and-test-keys      \
      --policy_key_output_file=policy_key_file.datica_test  \
      --policy_cert_output_file=policy_cert_file.datica_test \
      --platform_key_output_file=platform_key_file.bin  \
      --attest_key_output_file=attest_key_file.bin
  ```

This will also generate the attestation key and platform key for tests
that use the simulated enclave.

You can print the certificate using:

openssl x509 -in policy_cert_file.datica_test -inform der -text

## Step 4: Compile cf_utility (note unlike app examples where
##   the app is the measured object, you need NOT include policy
##   keys in the image.

```shell
cd $CERTIFIER_ROOT/vm_model_tools/src

make -f cf_utility.mak
```

## Step 5: Obtain the measurement of the for this security domain.

cd $EXAMPLE_DIR/provisioning

##     For the simulated enclave (this is a little hokey and
##     will be removed.

```shell

$CERTIFIER_ROOT/utilities/measurement_utility.exe \
--type=hash --input=$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
--output=cf_utility.measurement
```

## Step 6: Author the policy for the security domain and produce the signed claims the apps need

```shell
cd $EXAMPLE_DIR/provisioning
```

### a. Construct policyKey says platformKey is-trusted-for-attestation

```shell
$CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
--key_subject="platform_key_file.bin" --verb="is-trusted-for-attestation" --output=ts1.bin 

$CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
--key_subject=policy_key_file.datica_test --verb="says" \
--clause=ts1.bin --output=vse_policy1.bin
```

### b. Construct  policy key says measurement is-trusted
##     Note in real applications the measurement is that
##     of the OS.

```shell
$CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
--measurement_subject="cf_utility.measurement" \
--verb="is-trusted" --output=ts2.bin

$CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
--key_subject="policy_key_file.datica_test" --verb="says" \
--clause=ts2.bin --output=vse_policy2.bin
```

### c. Produce the signed claims for each vse policy statement.
```shell
$CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
--vse_file=vse_policy1.bin --duration=9000 --private_key_file=policy_key_file.datica_test \
--output=signed_claim_1.bin

$CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
--vse_file=vse_policy2.bin  --duration=9000  \
--private_key_file=policy_key_file.datica_test --output=signed_claim_2.bin
```

### d. Combine signed policy statements for Certifier Service use

```shell
$CERTIFIER_ROOT/utilities/package_claims.exe \
--input=signed_claim_1.bin,signed_claim_2.bin --output=policy.bin
```

### e. [optional] Print the policy

```shell
$CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=policy.bin
```

### f. Construct statement "platform-key says attestation-key is-trusted-for-attestation" and sign it

```shell
$CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
--key_subject=attest_key_file.bin --verb="is-trusted-for-attestation" --output=tsc1.bin

$CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
--key_subject=platform_key_file.bin --verb="says" \
--clause=tsc1.bin --output=vse_policy3.bin

$CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
--vse_file=vse_policy3.bin --duration=9000 \
--private_key_file=platform_key_file.bin --output=platform_attest_endorsement.bin
```

### g. [optional] Print it

```shell
$CERTIFIER_ROOT/utilities/print_signed_claim.exe --input=platform_attest_endorsement.bin
```

## Step 8: Build SimpleServer

You should have gotten the protobuf compiler (protoc) for Go when you got Go.
If not, do:

```shell
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
```
Compile the protobuf

```shell
cd $CERTIFIER_ROOT/certifier_service/certprotos

protoc --go_opt=paths=source_relative --go_out=. --go_opt=M=certifier.proto ./certifier.proto
```

This should produce a Go file for the certifier protobufs called certifier.pb.go in certprotos.
Now build simpleserver, the first set of makes buils stubs for different platforms.

```shell
cd $CERTIFIER_ROOT/certifier_service/graminelib
make dummy

cd $CERTIFIER_ROOT/certifier_service/oelib
make dummy

cd $CERTIFIER_ROOT/certifier_service/isletlib
make dummy

cd $CERTIFIER_ROOT/certifier_service/teelib
make

cd $CERTIFIER_ROOT/certifier_service

go build simpleserver.go
```

## Step 9: Create a directory for service data

```shell
mkdir $EXAMPLE_DIR/service
```

## Step 10: Provision the service files
```shell
cd $EXAMPLE_DIR/provisioning

cp -p policy_key_file.datica_test policy_cert_file.datica_test policy.bin $EXAMPLE_DIR/service
```

## Step 11: Start the Certifier Service

In a new terminal window:

```shell

cd $EXAMPLE_DIR/service

# You may need to make sure the shared libraries paths are in your LD_LIBRARY_PATH.
#export LD_LIBRARY_PATH=/usr/local/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/teelib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/graminelib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/isletlib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing/certifier_service/oelib
echo $LD_LIBRARY_PATH
sudo ldconfig

$CERTIFIER_ROOT/certifier_service/simpleserver \
--policy_key_file=policy_key_file.datica_test --policy_cert_file=policy_cert_file.datica_test \
--policyFile=policy.bin --readPolicy=true
```

## Step 12:  Run the scenario tests.

First, get certified.

cf_utility.exe \
    --cf_utility_help=false \
    --init_trust=true \
    --print_cryptstore=true \
    --save_cryptstore=false \
    --enclave_type="simulated-enclave" \
    --policy_domain_name=datica_test \
    --policy_key_cert_file=policy_cert_file.datica_test \
    --policy_store_filename=policy_store.datica_test \
    --encrypted_cryptstore_filename=cryptstore.datica_test \
    --symmetric_key_algorithm=aes-256-gcm  \
    --public_key_algorithm=rsa-2048 \
    --data_dir=$(EXAMPLE_DIR) \
    --certifier_service_URL=localhost \
    --service_port=8123

Now generate a key.

Check key

-------
## Notes on real deployment and measurements

simpleserver is complete enough to serve as a server for a security domain.  In practice,
unlike this example, there will be multiple trusted measurements and possibly multiple
approved platform keys.

### Platform-specific tools

As part of program measurement, each platform has a tool that takes an application
and produces a measurement which is used to construct the policy.

* The utility `measurement_utility.exe` does this in step 6 above for the
* simulated enclave.  For SEV, you can obtain a measurement tool from
* https://github.com/AMDESE/sev-tool; however, we are switching to virtee,
* which is more flexible.  Download the utility from
* https://github.com/virtee/sev-snp-measure and follow the instructions.

* These tools both produce a file containing the binary measurement which should
be used in step 7(a), above.

-----

```shell
export GOPATH=$HOME
export GOROOT=/usr/local/go
export PATH=$PATH:$GOROOT/bin
export GO111MODULE=on
go mod init
go mod tidy
go mod init certifier.pb.go
```

## Summary and comments

These instructions might seem daunting and a little summary might
make them clearer.  See the notes in the "simple_apps/simple_example"
for more background.

