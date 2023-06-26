# Gramine tests for Attest/Verify, Seal/Unseal core APIs on SGX platform

# Overview:

The gramine_tests are tests of the core APIs/primitives implemented in src/gramine. 
These APIs are used by the certifier to access Gramine trust primitives.
These tests do not depend on the Certifier and run as stand-alone tests.
The tests demonstrate how to Attest/Verify an enclave and provide Seal/Unseal
functionality for secrets management.

The tests run in a Gramine enclave. First, the API is initialized.  gramine_Attest
returns the SGX quote for this enclave. The SGX quote contains the enclave measurement.
Next, the gramine_Verify is invoked to validate this SGX quote in one of two ways -
first a local verify that can be invoked within the enclave and validate the
quote is shown when GRAMINE_LOCAL_VERIFY is defined. Secondly, the remote verification
invokes the SGX quote verification library to validate the SGX quote. This remote
verification functionality can be integrated with an external service.

The gramine_Seal demonstrates how to seal secrets with an SGX sealing key
obtained from the platform using GCM encryption with a sealing tag added to the
header of the encrypted buffer. The gramine_Unseal when provided with the correct sealing
key, will be able to decrypt the encrypted buffer and verify the original contents.
MbedTLS library is used to provide seal/unseal/hashing functions.

A Gramine enclave uses SGX instructions to generate SGX quotes and reports. On initial
deployment, Gramine communicates with the Quoting Enclave(QE) to get the SGX quote.
The QE talks to the PCE to obtain the attestation collateral with the help of Intel
Provisioning Certification Service(PCS). The certificates are cached locally. When an SGX
quote is received, users can compare the certificates embedded in the quote against these
cached certificates.

This test uses two scripts, a Makefile and the SGX manifest to setup.
The steps below describe building and running the Gramine tests.


# System Requirements:

Platform - Intel Coffee Lake or later with Intel SGX, Intel SPS and Intel ME. Intel NUCs
with SGX capability should also work as long as they support Intel FLC.

OS - Ubuntu 20.04 or later with Linux kernel 5.11 or higher

# Software Repositories:

1. Clone Gramine
```shell
mkdir gramine
cd gramine
git clone https://github.com/gramineproject/gramine.git gramine
```

2. Clone Certifier
```shell
cd ..
Clone certifier in the same directory as the parent of the outer gramine dir above.
```

```shell
git clone https://github.com/vmware-research/certifier-framework-for-confidential-computing.git certifier
```

# Steps to install Gramine:

3. Build Gramine
Steps required to build Gramine are provided here:
https://gramine.readthedocs.io/en/stable/devel/building.html

Detailed required steps from the link above are listed here:

3a. First install a Linux OS such as Ubuntu 20.04 with Linux kernel 5.11 or higher which
has SGX drivers built in. SGX drivers help in setting up the SGX-specific instructions
on the CPU and the QE/PCE.

3b. Install common dependencies as in the link above:
```shell
sudo apt-get install -y build-essential \
    autoconf bison gawk nasm ninja-build pkg-config python3 python3-click \
    python3-jinja2 python3-pip python3-pyelftools wget
sudo python3 -m pip install 'meson>=0.56' 'tomli>=1.1.0' 'tomli-w>=0.4.0'
```

3c. Install SGX dependencies as in the link above:
```shell
sudo apt-get install -y libprotobuf-c-dev protobuf-c-compiler \
    protobuf-compiler python3-cryptography python3-pip python3-protobuf
```

3d. Install Intel SGX SDK/PSW as in the link above:
If using kernel 5.11 or higher, SGX drivers are already built in and need not be
installed explicitly.
This link provides all the steps required:
https://download.01.org/intel-sgx/sgx-dcap/1.14/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf

This document also has steps to configure PCCS on local machine to ensure Intel PCS
communication is setup correctly.

3e. Install dependencies for DCAP:
```shell
curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
# (if you're on Ubuntu 18.04, write "bionic" instead of "focal" above)

sudo apt-get update
sudo apt-get install libsgx-dcap-quote-verify-dev
```

3f. Build Gramine
```shell
meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled -Dsgx_driver=upstream -Ddcap=enabled
ninja -C build/
sudo ninja -C build/ install
```

# Steps to run Gramine tests:

Tests use the installed Gramine SDK, Intel SGX/DCAP drivers and MbedTLS libraries for
core API tests.
 
4. Setup MbedTLS
This script obtains the MbedTLS library and configures it to be used by an application.
Gramine APIs use the MbedTLS to encrypt/decrypt buffers or to obtain hashes.
```shell
cd certifier/src/gramine/gramine_tests
./configureMbedTLS
```

5. Build Gramine-Certifier tests
This command builds the tests as an application that is run within a Gramine enclave.
First, the make builds a binary with the Gramine library and Gramine tests. This binary
in conjunction with the files listed in the Gramine manifest are packaged together. They
are input to the gramine-sgx-sign to obtain an SGX specific manifest file which
controls the trusted enclave's TCB. The gramine-sgx-token is run to obtain security
parameters such as MR_ENCLAVE, MR_SIGNER and other SGX attributes which can be used to
verify the enclave and the SGX platform. MR_ENCLAVE is the measurement of the enclave.
```shell
make -f gramine_tests.mak app RA_TYPE=dcap
```

To clean up built files:
```shell
make -f gramine_tests.mak clean
```

6. Run tests

Tests will run the Attest/Verify and Seal/Unseal tests and return a success/failure
result. Gramine automatically talks to the configured DCAP libraries and SGX QV libraries
which in turn communicate with the remote Intel PCS to verify the obtained SGX quote
after comparing it with the cached certificates. The Gramine application enclave through
the Gramine SDK, talks to the Quoting Enclave which in turn interacts with the Intel PCE
and the PCS. The quote verifier caches these certificates and when an SGX quote arrives,
it can validate with these cached certificates. The remote verification in this test
talks to the DCAP library and verifies the obtained SGX quote. The SGX quote contains
security characteristics such as MR_ENCLAVE, MR_SIGNER, PROD_ID and CPU_SVN to be used
for verification of the enclave and the SGX platform.
```shell
gramine-sgx ./gramine_tests dcap
```

## Additional Notes

Some Gramine applications are built with a self-signed SSL certificate with the SGX quote
embedded in it. This certificate is used for establishing a trusted communication channel.
This is not required and we do not generate either the key or the self-signed cert.

The manifest contains the files to be trusted as part of the SGX enclave. The manifest
also specifies the gramine.libos entrypoint, library paths included, file system mounts
that are to be part of the enclave. SGX specific environment variables can also be set in
the manifest.
