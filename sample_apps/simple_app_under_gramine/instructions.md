# Simple App under Gramine Enclave SDK

This document gives detailed instructions for building and running the sample application
in Gramine enclaves. The application uses
[Gramine library](https://github.com/gramineproject/gramine) APIs to generate policy
for the Certifier Service using the policy utilities under Gramine.

## Overview

This app is similar to the application in
[simple_app](../simple_app/example_app.cc) but runs in a Gramine enclave.

This sample application demonstrates a simple client and server setup that
can certify with the Certifier Service to get admission certificates.
Once certified, the client and server can talk to each other through a
mutually trusted and authenticated TLS connection.

- A Gramine enclave uses SGX instructions to generate SGX quotes and reports.
  On initial deployment, Gramine communicates with the Quoting Enclave (QE) to
  get the SGX quote.

- The QE talks to the Provisioning Certification Enclave (PCE) to obtain the
  attestation collateral with the help of Intel Provisioning Certification
  Service (PCS). The certificates are cached locally.

- When an SGX quote is received, users can compare the certificates embedded
  in the quote against these cached certificates.

This app uses two scripts, a Makefile and the SGX manifest to setup.
The steps below describe building and running the Gramine example app.

## System Requirements

### Platform
- Intel Coffee Lake or later with Intel SGX, Intel SPS and Intel ME.
- Intel [Next Unit of Computing](https://www.intel.com/content/www/us/en/products/docs/boards-kits/nuc/what-is-nuc-article.html)
  (NUCs) with SGX capability should also work as long as they support Intel
  Flexible Launch Control (FLC). FLC allows the platform owner (not Intel),
  to control which enclaves are launched on that platform
- OS - Ubuntu 20.04 or later with Linux kernel 5.11 or higher

## Software Repositories

$CERTIFIER_PROTOTYPE is the top level directory for the Certifier repository.
It is helpful to have a shell variable for it, e.g.,:

```shell
export CERTIFIER_PROTOTYPE=~/Projects/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the example application.  Again, a shell variable
is useful.

```shell
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app_under_gramine
```

1. Clone the Certifier library

Clone the Certifier library in, say, ~/Projects

```shell
cd ~/Projects
git clone https://github.com/vmware-research/certifier-framework-for-confidential-computing.git
```

2. Clone Gramine

Clone the Gramine repo in the same directory as a sibling of the Certifier Library repo.

```shell
cd ~/Projects
mkdir gramine
cd gramine
git clone https://github.com/gramineproject/gramine.git
```

## Steps to install Gramine

3. Build Gramine

Steps required to build Gramine are provided
[here, Gramine build](https://gramine.readthedocs.io/en/stable/devel/building.html).

Detailed required steps from the link above are listed here:

a)  First install a Linux OS such as Ubuntu 20.04 with Linux kernel 5.11 or
    higher which has SGX drivers built-in. SGX drivers help in setting up
    the SGX-specific instructions on the CPU and the QE/PCE.

b)  Install common dependencies:

```shell
sudo apt-get install -y build-essential \
    autoconf bison gawk nasm ninja-build pkg-config python3 python3-click \
    python3-jinja2 python3-pip python3-pyelftools wget

sudo python3 -m pip install 'meson>=0.56' 'tomli>=1.1.0' 'tomli-w>=0.4.0'
```

c)  Install SGX dependencies:
```shell
sudo apt-get install -y libprotobuf-c-dev protobuf-c-compiler \
    protobuf-compiler python3-cryptography python3-pip python3-protobuf
```

d) Install Intel SGX SDK Platform Software (SDK/PSW):

If using kernel 5.11 or higher, SGX drivers are already built-in and need not be
installed explicitly.

This [Intel_SGX_SW_Installation_Guide_for_Linux.pdf link](https://download.01.org/intel-sgx/sgx-dcap/1.14/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)
provides all the steps required.

This document also has steps to configure Intel SGX Provisioning
Certificate Caching Service (PCCS) on a local machine to ensure Intel PCS
communication is setup correctly.

e) Install dependencies for Intel SGX Data Center Attestation Primitives (DCAP)
```shell
# (If you're on Ubuntu 18.04, write "bionic" instead of "focal" below)

curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key \
   | sudo apt-key add - echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' \
   | sudo tee /etc/apt/sources.list.d/intel-sgx.list

sudo apt-get update
sudo apt-get install libsgx-dcap-quote-verify-dev
```

f) Build Gramine

```shell
meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled -Dsgx_driver=upstream -Ddcap=enabled

ninja -C build/

sudo ninja -C build/ install
```

## Obtain Intel Certificates

4. The PCK Cert ID Retrieval Tool,
   [PCKIDRetrievalTool](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/tools/PCKRetrievalTool/README.txt),
   is used to obtain the Intel platform certificates that include the root
   certificate and the PCK certificate chain.

   Install and run the SGX PCK Cert ID retrieval tool:
```shell
sudo apt install sgx-pck-id-retrieval-tool
```
- Currently we use the Intel root certificate obtained by running the tool above.
- Copy the root certificate to a file named intel.pem (file to be renamed later).
- More info on how to run is detailed here,
  [GitHub PCKRetrievalTool](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/tools/PCKRetrievalTool).

- Convert the pem file to der format using
```
openssl x509 -in intel.pem -inform pem -out sgx.cert.der -outform der
```

-------
**NOTE:** The `run_example.sh` expects that this `sgx.cert.der` lives in your `$HOME` dir.
          The script will copy this certificate from $HOME to the provisioning dir
          for the simple_app_under_gramine .

If you generate this certificate elsewhere, run: `$ cp -p sgx.cert.der $HOME`

-------

# Steps to build-and-run Simple App under Gramine

App uses the installed Gramine SDK, Intel SGX/DCAP drivers and
[MbedTLS](https://en.wikipedia.org/wiki/Mbed_TLS) libraries for basic functionality.

This example embeds the policy key in the application using `embed_policy_key.exe`.

All these steps are packaged under the [run_example.sh](../run_example.sh) script.

## Setup MbedTLS

This script obtains the MbedTLS library and configures it to be used by an application.
Gramine APIs use the MbedTLS to encrypt/decrypt buffers or to obtain hashes.

Do a one-time setup to download and configure the MbedTLS library.
```
cd $EXAMPLE_DIR
./configureMbedTLS
```

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

Similarly, invoke the wrapper shell script as: `$ LOCAL_LIB=/usr/local/lib64 run_example.sh simple_app_under_gramine [setup]`

## Step 2:  Create a directory for the provisioning files
``` shell
mkdir $EXAMPLE_DIR/provisioning
```

## Step 3: Generate the policy key and self-signed certificate

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe     \
    --operation=generate-policy-key                 \
    --policy_key_output_file=policy_key_file.bin    \
    --policy_cert_output_file=policy_cert_file.bin  \
```

This will also generate the attestation key and platform key for these tests.

## Step 4: Embed the policy key in example_app.

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/embed_policy_key.exe \
      --input=policy_cert_file.bin                  \
      --output=../policy_key.cc
```

## Step 5. Build Gramine-Certifier app

This command builds the application that is run within a Gramine enclave.
First, the `make` builds a binary with the Gramine library and the Gramine app.

This binary in conjunction with the files listed in the Gramine manifest are
packaged together. They are input to the gramine-sgx-sign to obtain an
SGX-specific manifest file which controls the trusted enclave's TCB.

The gramine-sgx-token is run to obtain security parameters such as MR_ENCLAVE,
MR_SIGNER and other SGX attributes which can be used to verify the enclave and
the SGX platform.  MR_ENCLAVE is the measurement of the enclave.

```shell
cd $EXAMPLE_DIR

make -f gramine_example_app.mak clean
make -f gramine_example_app.mak app RA_TYPE=dcap
```
## Step 6. Obtain the measurement of the trusted application for this security domain

Use the MR_ENCLAVE_HASH that is printed in the output of gramine-sgx-get-token
after building the app in the step above.

```shell
cd $EXAMPLE_DIR/provisioning

$CERTIFIER_PROTOTYPE/utilities/measurement_init.exe \
    --out_file=example_app.measurement              \
    --mrenclave=<MR_ENCLAVE_HASH>
```

## Step 7. Author the policy for the security domain and produce the signed claims the apps need

### a. Construct policyKey says platformKey is-trusted-for-attestation
```shell
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe    \
    --cert-subject=sgx.cert.der                             \
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
# RESOLVE: This step seems different ...
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

### d. Construct the trusted platform policy
TBD in a later step.

### e. Combine signed policy statements for Certifier Service use
```shell
$CERTIFIER_PROTOTYPE/utilities/package_claims.exe   \
    --input=signed_claim_1.bin,signed_claim_2.bin   \
    --output=policy.bin
```

### step f. [optional] Print the policy
```shell
$CERTIFIER_PROTOTYPE/utilities/print_packaged_claims.exe \
    --input=policy.bin
```

## Step 8: Build SimpleServer

### a. Compile the protobuf and the C-Go interface
```shell
cd $CERTIFIER_PROTOTYPE

cd certifier_service/certprotos
protoc --go_opt=paths=source_relative \
       --go_out=.                     \
       --go_opt=M=certifier.proto     \
       ./certifier.proto
```

This should produce a Go file for the certifier protobufs called
certifier.pb.go in certprotos.

```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/graminelib
make
cd $CERTIFIER_PROTOTYPE/certifier_service/oelib
make dummy
cd $CERTIFIER_PROTOTYPE/certifier_service/isletlib
make dummy
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

## Step 13: Get admission certificates
Ensure the policy_store for each app has been added to the manifest of trusted
files. If other files are needed to be trusted, ensure the manifest file
includes the file in the section sgx.allowed_files.

## Step 14: Run the apps after getting admission certificates from Certifier Service

Open two new terminals (one for the app as a client and one for the app as a server):

In app-as-a-server terminal run the following:

```shell
cd $EXAMPLE_DIR

gramine-sgx gramine_example_app         \
    --data_dir=./app2_data/             \
    --operation=cold-init               \
    --policy_store_file=policy_store    \
    --print_all=true

gramine-sgx gramine_example_app         \
    --data_dir=./app2_data/             \
    --operation=get-certified           \
    --policy_store_file=policy_store
    --print_all=true
```

In app-as-a-client terminal run the following:

```shell
cd $EXAMPLE_DIR

gramine-sgx gramine_example_app         \
    --data_dir=./app1_data/             \
    --operation=cold-init               \
    --policy_store_file=policy_store    \
    --print_all=true

gramine-sgx gramine_example_app         \
    --data_dir=./app1_data/             \
    --operation=get-certified           \
    --policy_store_file=policy_store    \
    --print_all=true
```

At this point, both versions of the app have their admission certificates.
Output and results are printed on each of the terminals running the app and
the service.

Now all we have to do is have the apps connect to each other for the final test.
The Certifier Service is no longer needed at this point.

## Step 15: Run the apps to test trusted services

### a. In app-as-a-server terminal run the following:

```shell
cd $EXAMPLE_DIR

gramine-sgx gramine_example_app         \
    --data_dir=./app2_data/             \
    --operation=run-app-as-server       \
    --policy_store_file=policy_store    \
    --print_all=true
```

### b. In app-as-a-client terminal run the following:
```shell
cd $EXAMPLE_DIR

gramine-sgx gramine_example_app         \
    --data_dir=./app1_data/             \
    --operation=run-app-as-client       \
    --policy_store_file=policy_store    \
    --print_all=true
```

You should see the message "Hi from your secret server" in the client terminal
window and "Hi from your secret client".

If so, **your first Confidential Computing program worked!**

As shown, apps run the server and client in a Gramine enclave and return a
success/failure.

Gramine automatically talks to the configured DCAP libraries and SGX QV
libraries which in turn communicate with the remote Intel PCS to verify the
obtained SGX quote after comparing it with the cached certificates. The Gramine
application enclave through the Gramine SDK, talks to the Quoting Enclave
which in turn interacts with the Intel PCE and the PCS. The quote verifier
caches these certificates and when an SGX quote arrives, it can validate with
these cached certificates. The remote verification in this app talks to the
DCAP library and verifies the obtained SGX quote. The SGX quote contains
security characteristics such as MR_ENCLAVE, MR_SIGNER, PROD_ID and CPU_SVN to
be used for verification of the enclave and the SGX platform.

## Additional Notes

Some Gramine applications are built with a self-signed SSL certificate with
the SGX quote embedded in it. This certificate is used for establishing a
trusted communication channel.

This is not required and we do not generate either the key or the self-signed cert.

The manifest contains the files to be trusted as part of the SGX enclave.
The manifest also specifies the gramine.libos entrypoint, library paths included,
file system mounts that are to be part of the enclave. SGX-specific environment
variables can also be set in the manifest.
