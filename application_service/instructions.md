# Instructions for building and running the Application Service

## Application Service

The Application Service is an example of providing Confidential Computing support
recursively. In this case the parent process, protected by an encrypted
virtual machine, recursively provides Confidential Computing support, through
the Certifier API to individual applications (processes) on a Unix VM.

The Application Service runs as a system (root) daemon at startup.  It accepts
requests to run applications.   When a request is received, the application is
run as a child of the service and they share a pair of pipes over which they
request services (like Seal, Unseal, Attest).  Child processes **DO NOT** run as root.

Children have the same Certifier interface and their own Certifier Service
platform support. Programming the child applications is exactly the same as in
other enclaves except they have full access to the Unix API so porting programs
is easy.

The enclave type for an application enclave is "application-enclave" and every
application enclave has a parent enclave.

As a result, an encrypted virtual machine can support many independant Confidential
Computing programs running as independent applications.  This is useful for
Kubernetes container management and encrypted virtual machines running related
trustworthy services.

The Application Service provides the Confidential Computing
interfaces for programs that run in encrypted virtual machines.
The app_service is a daemon which starts at system startup and
must run as root and should be included in `initramfs`.

## Implementation notes

- The service should have a known communications port, probably TCP.
  A request to run a Confidential Computing application naming the binary,
  comes over this port.

  When it gets such a request, the service should measure (hash) the binary,
  which is the app's measurement, and store it.  The service should have generated
  symmetric keys to encrypt and integrity-protect data for sealed storage and
  have a certificate for its authentication key.

  The service will also have a policy on what apps it is willing to run.
  App calls are passed over the pipes in serialized app_call protobufs.

- The service should fork, change owners, exec and open shared pipes to the
  application.

  The service should support four calls over the pipes: GetTrustCerts, Seal, Unseal, Attest

   - **Seal** should accept a secret to seal, put the secret and the program
     measurement in a protobuf and encrypt/integrity protect it.

   - **Unseal** should accept the output of Seal, check its integrity and decrypt it;
     if the measurement matches that of the program running, it should return the
     decrypted secret.

   - **Attest** takes user-data as an argument, builds a certificate with the
     measurement of the program, the hash of the user data and
     signs it with its public key.

   - **GetTrustCerts** returns the certificate chain for the key used by the
     service to attest.

-  The Certifier will have a new provider "application" (like SEV-SNP) that sends
   seal, unseal and attest requests over the shared pipes to the service and
   retrieves results.


$CERTIFIER_PROTOTYPE is the top level directory for the certifier repository.
It is helpful to have a shell variable for it, e.g., :

```shell
export CERTIFIER_PROTOTYPE=~/Projects/certifier-framework-for-confidential-computing
```

$APP_SERVICE_DIR is this directory containing the Application Service code.

```shell
export APP_SERVICE_DIR=$CERTIFIER_PROTOTYPE/application_service
```

## Overview

The step by step instructions for building the application
service and running the tests are enumerated below.  However,
to save time, we also supply two shell scripts to do this automatically.
The shell script prepare-test.sh builds the program and support files.
The shell script run-test.sh runs the test.  There is still benefit in
carrying out the steps in run-test by copying and pasting since you can
see all the output and preserve the running servers.

The shell scripts assume you have all the right software installed including
the go programs and libraries mentioned below.
   
The shell scripts use the new API.

To prepare the test files, type:

  prepare-test.sh fresh [domain-name]
      - This clears out all old files
then
  prepare-test.sh all [domain-name]
      - This builds the files corresponding to steps 1-9 below.
then
  run-test.sh fresh [domain-name]
      - This removes old application files (policy store and cryptstore)
      - and runs the tests, corresponding to steps 9 and 10 below.
prepare-test.sh all runs the following subcommands in order:
  prepare-test.sh compile-utilities [domain-name]
      - This performs steps 1-2 below.
  prepare-test.sh make-keys [domain-name]
      - This performs step 3 below.
  prepare-test.sh compile-program [domain-name]
      - This performs step 4 to 5 below.
  prepare-test.sh make-policy [domain-name]
      - This performs steps 6 and 7 below.
  prepare-test.sh compile-certifier [domain-name]
      - This performs step 8 below.
  prepare-test.sh copy-files [domain-name]
      - This performs steps 9 to 12 below.

Each of these subcommands is runable from prepare-test.sh, for example,
you could run,
   prepare-test.sh make-policy [domain-name]
to remake the policy.

After you run "prepare-test.sh all", you can rerun the tests without
invoking prepare-test.sh.  After you run "prepare-test.sh all",
you need only run subcommands that cause a change in the files;
for example, if you change the policy, you need only run
"prepare-test.sh make-policy" before running the tests.

To run the tests
  echo "  ./run-test.sh fresh"
  echo "  ./run-test.sh fresh domain-name"
     -- This clears previous operational files.  The first assumes the
        default domain name ("datica-test").
  echo "  ./run-test.sh run (se | sev)"
  echo "  ./run-test.sh run domain_name (se | sev)"
     -- This runds the test.  The first assumes the default domain
         name ("datica-test").

---------------------------------------------------------------------------------------

##  Detailed step by step instructions are below

## Step 1: Build the utilities

```shell
cd $CERTIFIER_PROTOTYPE/utilities

make -f cert_utility.mak
make -f policy_utilities.mak
```


## Step 2 (a):  Create a directory for the provisioning files
```shell
mkdir $APP_SERVICE_DIR/provisioning
```

## Step 2 (b): Create a directory for service data
```shell
mkdir $APP_SERVICE_DIR/service
```

## Step 3: Generate the policy key and self-signed certificate for service
```shell
cd $APP_SERVICE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe          \
      --operation=generate-policy-key-and-test-keys      \
      --policy_key_output_file=policy_key_file.bin       \
      --policy_cert_output_file=policy_cert_file.bin     \
      --platform_key_output_file=platform_key_file.bin   \
      --attest_key_output_file=attest_key_file.bin
```
This will also generate the attestation key and platform key for the these tests.


## Step 4: Embed the policy key in app_service.

```shell
cd $APP_SERVICE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/embed_policy_key.exe     \
        --input=policy_cert_file.bin                    \
        --output=../policy_key.cc
```

## Step 5: Compile app_service with the embedded policy_key

```shell
cd $APP_SERVICE_DIR
make -f app_service.mak
```

## Step 6: Obtain the measurement of the trusted application for this security domain

This is performed for the simulated enclave.

```shell
cd $APP_SERVICE_DIR/provisioning

# Use an output measurement name that is consistent with the
# instructions for other sample-apps.
$CERTIFIER_PROTOTYPE/utilities/measurement_utility.exe  \
        --type=hash                                     \
        --input=../app_service.exe                      \
        --output=example_app.measurement
```

## Step 7: Author the policy for the security domain and produce the signed claims the apps need.

This policy describes what applications the service is willing to run.

```shell
cd $APP_SERVICE_DIR/provisioning
```

### a. Construct statement "policy-key says the platform-key is-trusted-for-attestation"
```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
        --key_subject=platform_key_file.bin                 \
        --verb="is-trusted-for-attestation"                 \
        --output=ts1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe     \
        --key_subject=policy_key_file.bin                       \
        --verb="says"                                           \
        --clause=ts1.bin                                        \
        --output=vse_policy1.bin
```

### b. Construct statement "policy-key says app_service-measurement is-trusted"
```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
        --key_subject=""                                    \
        --measurement_subject=example_app.measurement       \
        --verb="is-trusted"                                 \
        --output=ts2.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe     \
        --key_subject=policy_key_file.bin                       \
        --verb="says"                                           \
        --clause=ts2.bin                                        \
        --output=vse_policy2.bin
```

### c. Produce the signed claims for each vse policy statement.
```shell
$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
        --vse_file=vse_policy1.bin                                      \
        --duration=9000                                                 \
        --private_key_file=policy_key_file.bin                          \
        --output=signed_claim_1.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
        --vse_file=vse_policy2.bin                                      \
        --duration=9000                                                 \
        --private_key_file=policy_key_file.bin                          \
        --output=signed_claim_2.bin
```

### d. Combine signed policy statements for Certifier Service use.
```shell
$CERTIFIER_PROTOTYPE/utilities/package_claims.exe       \
        --input=signed_claim_1.bin,signed_claim_2.bin   \
        --output=policy.bin
```

### e. [optional] Print the policy
```shell
$CERTIFIER_PROTOTYPE/utilities/print_packaged_claims.exe --input=policy.bin
```

### f. Construct statement "platform-key says attestation-key is-trusted-for-attestation" and sign it
```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
        --key_subject=attest_key_file.bin                   \
        --verb="is-trusted-for-attestation"                 \
        --output=tsc1.bin

$CERTIFIER_PROTOTYPE/utilities/make_indirect_vse_clause.exe     \
        --key_subject=platform_key_file.bin                     \
        --verb="says"                                           \
        --clause=tsc1.bin                                       \
        --output=vse_policy3.bin

$CERTIFIER_PROTOTYPE/utilities/make_signed_claim_from_vse_clause.exe    \
        --vse_file=vse_policy3.bin                                      \
        --duration=9000                                                 \
        --private_key_file=platform_key_file.bin                        \
        --output=platform_attest_endorsement.bin
```

g. [optional] Print it
```shell
$CERTIFIER_PROTOTYPE/utilities/print_signed_claim.exe --input=platform_attest_endorsement.bin
```

## Step 8: Create a directory for service data
```shell
mkdir $APP_SERVICE_DIR/service
```

## Step 9: Provision the service files
```shell
cd $APP_SERVICE_DIR/provisioning

cp -p policy_key_file.bin policy_cert_file.bin policy.bin attest_key_file.bin platform_attest_endorsement.bin platform_key_file.bin $APP_SERVICE_DIR/service
```

## Step 10: Start the Certifier Service
```shell
cd $APP_SERVICE_DIR/service

$CERTIFIER_PROTOTYPE/certifier_service/simpleserver \
        --policyFile=policy.bin                     \
        --readPolicy=true
```


## Step 11: Start the Application Service

  At startup (The last four flags are needed for the simulated enclave)
```shell
cd $APP_SERVICE_DIR

$ APP_SERVICE_DIR/app_service.exe                                       \
      --service_dir="./service/"                                        \
      --cold_init_service=true                                          \
      --policy_cert_file="policy_cert_file.bin"                         \
      --service_policy_store="policy_store"                             \
      --host_enclave_type="simulated-enclave"                           \
      --platform_file_name="platform_file.bin"                          \
      --platform_attest_endorsement="platform_attest_endorsement.bin"   \
      --attest_key_file="attest_key_file.bin"                           \
      --measurement_file="example_app.measurement"                      \
      --guest_login_name="guest"
```


-------------------------------

## Running the Application Service

The application_service must run as root and be started at boot.  Usually,
it is in `initramfs`.

Arguments:

- --cold_init_service=true means reinit even if there is already service data
- --policy_cert_file=policy_cert.bin
- --policy_host="address" for policy server
- --policy_port=8123, port for policy server
- --service_dir="./service/", directory for service data
- --policy_store_file="policy_store.bin, policy store for service
- --server_app_host=localhost, address for application requests
- --server_app_port=8124, port for application requests
- --run_policy="all", means run any binary
- --run_policy="signed", means run only signed binaries
- --host_enclave_type="simulated-enclave", enclave type of the primary host

To test:
```shell
$ ./send_request.exe --executable="./hello_world.exe" --server_app_port=8127 --server_app_host="localhost"

$ ./send_request.exe --executable="./test_user.exe" --server_app_port=8127 --server_app_host="localhost"
```
