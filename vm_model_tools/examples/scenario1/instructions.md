# Instructions for running scenario1

This document gives detailed instructions for running scenario1
in both simulated or full SEV environment (in the case of an sev
"deployed enclave") or a simulated or real tpm environment
(in the case of tpm "deployed enclave") .  The basic vm utility
used is cf_utility.exe, cf_utility.exe is described in
cf_utility_usage_notes.md.

In the scripts, $CERTIFIER_ROOT is the top level directory for the Certifier
repository and $EXAMPLE_DIR as described above.  $EXAMPLE_DIR is this
directory containing the example application.  These are used byt the
scripts.


## Overview

Running the tests is considerably simplified by a consolidated script,
run-test-scenario1.sh.  It runs all the subordinate scripts.


### Special note for tpms:

The TPM enclave introduces an additional policy step for certification.
For enclaves like SEV, the public key for the quote or attestation, is part of
platform provisioning.  If the certifier "trusts" the manufacturer root
certificate, the elements of the certification can be provided in one pass.
By contrast, the TPM employs a "first pass" in which the quoting key
established trust with the certifier using a protocol.  This protocol
uses the "ActivateCredential" functionality of the TPM.

To implement this "first pass" mechanism, the certifier opens a new protocol channel
that accepts a certificate chain from the TPM manufacturers that offers evidence
to support the security of the TPM "endorsement cert."  The deployed
program packages this along with unforgeable information about the
ultimate "quoting key," produces a cert for the quoting key, encrypts
the cert with a random key (a "credential") and encrypts the the credential
to the endorsement key.  The credential can only be decrypted by the TPM
with the trusted endorsement cert which verifies properties of the quoting
key and unlocks the credential which, in turn, is used to decrypt the quoting
key certificate.  This certificate can then be used in the same way
an authenticated vcek key is  used in SEV.

The upshot is that the certifier is first called with the "first pass" tag
that implements the new step to approve the quote key.  After the quote key
is validated, resulting in a certificate signed by the policy key.  The
customary proof protocol used in other enclaves is used to produce an
"Admisions Certificate" as usual.

If you run in a pure tpm environment (with a real tpm), there are a number of
steps required to "take ownership" of the tpm and enable it, there is some stale
documentation about this in https://github.com/jlmucb/cloudproxy/Doc/CloudProxyNutsandBolts
but you should consult TPM documnetation.  In addition, since a "tpm only" hardware
platform does not encrypt memory, it is important to encrypt the page table, or
disable paging.  You can encrypt the page table in Linux using dmcrypt.


# Running the tests

All tests can be run from a consolidated script called run-test-scenario1.sh.
The script uses a number of variables to control test behavior.  You need not
know all the vatiables since the defaults work in most cases but some important
variables you should know have the following effect:

    "-ccf 1" tells the script that it should compile all the certifier utilities
        and programs.
    "-bss 0" tells the script NOT to build and install the driver for the
        simulated sev.
    "-pk 1" tells the script to generate keys and certificates for the domain.
    "-loud 1" tells the script to print a lot of debug output.
    "-just-compile 1" tells the script to just compile stuff (you need not be root to do this)
    "-tpm" and "-sev-dev" affect the names of the device drivers used fot the tpm or sev.
    "-tt" simulated|real says whether the test in a simulated or real environment.
    "-build-vm" says whether the vm is pre-built (as on AWS) or being built as part of the test.
    The "-cpu-type", "-n-cpus", "-cpu-model", "-cpu-stepping", "-cpu-family", "-cpu-feat", 
    "-vmm-type ", "-kernel-mfn", "-initram-mfn", "-vm-cmd", and "-ovmf-loc" flags are used
    for sev builds in a real SEV environment and will be explained below.
    Similarly, the "-npcr" and "-pcrs" are used for the tpm tests and will be explained below.

Two more important flags are "-et1" and "-et2" which specify the enclave types for the deployment
and deployed machines.

Before starting any tests, it's a good idea to define environment variables:

```shell
  export CERTIFIER_ROOT=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
  # or depending where you put the certifier repository:
  export CERTIFIER_ROOT=~/src/github.com/certifier-framework-for-confidential-computing
```
or whatever directory you cloned the certifier repository into.

Then,

```shell
    export EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
```

You may want to just compile the framework and vm_model_tools executables,
without being root.  This will save time later but is not required.
To do this:

```shell
  # if compiling for the simulated environment
  ./run-test-scenario1.sh  -bss 0 -ccf 1 -loud 1 -dn dom0 -pn cf-utility -pk 1 \
    -just-compile 1 -tt simulated
  # if compiling for a real sev platform
  ./run-test-scenario1.sh  -bss 0 -ccf 1 -loud 1 -dn dom0 -pn cf-utility -pk 1 \
    -just-compile 1 -tt real
```

If your running the tests on a raw VM, make sure you have the development tools.
The instructions for doing this is in the top level README.md for the certifier
but to remind you:

```script
sudo apt update -y && \
sudo apt install -y build-essential clang-format protobuf-compiler libprotobuf-dev libgtest-dev libgflags-dev  protoc-gen-go golang-go \
libmbedtls-dev python3-pip swig openssl libssl-dev cmake uuid-dev pkg-config python3 pylint swtpm swtpm-tools apparmor apparmor-utils \
apparmor-profiles fuse3 libfuse3-dev socat
```

## Running the tests with the simulated enclave only

The simulated enclave tests are the simplest.  You need not be root.
After defining the CERTIFIER_ROOT and EXAMPLE_DIR variables:

Compile:

```shell
  ./run-test-scenario1.sh  -bss 0 -ccf 1 -loud 1 -dn dom0 -pn cf-utility -pk 1 \
    -just-compile 1 -tt simulated
````

Run: 

```shell
  ./run-test-scenario1.sh  -bss 0 -ccf 0 -loud 1 -et2 simulated-enclave \
   -pk 1 -pn cf-utility -pfn policy.bin
```

If you rerun the tests, first clean up old processes and files:

```script
  ./cleanup.sh
  ./clean-files.sh
```

If you ran the tests as root, you have to be root to clean up and make sure
CERTIFIER_ROOT and EXAMPLE_DIR are properly defined while you're root.


## Running the tpm tests

You must build the tpm utilities as follows (you only need to do this once),
and you don't need to be root to do it.

```shell
  pushd $CERTIFIER_ROOT/src/tpm2
    make clean -f tpm2_support.mak
    make -f tpm2_support.mak
  popd
```

Except as noted, the following commands, which run the tests, must run as root
(see note above about path variables).

If you want to use the tpm simulator, first install it (see
$CERTIFIER_ROOT/src/tpm2/swtpmins.txt, for instructions).

First set the location of the simulated tpm state:

```shell
  export XDG_CONFIG_HOME=full directory name (probably $CERTIFIER_ROOT/swtpm_state)
```

You may want to clean up files and simulator state from previous runs.  To do this,
in the $CERTIFIER_ROOT/src/tpm2 type:

```shell
 ./clean-tpm-simulator.sh
```
As root, start the tpm simulator for testing, and set pcr 7:

```shell
  ./start-tpm-simulator.sh
  export TPM_SUPPORT_DIR=$CERTIFIER_ROOT/src/tpm2
  sleep 2
  $TPM_SUPPORT_DIR/tpm2_set_pcrs.exe --pcr_num=7 --num_pcrs=1 \
  --tpm_device=/dev/tpmrm1
```

If you are using a "real" tpm, make sure you set the correct device name
(-tpm /dev/tpmrm1, below).  The pcrs should already be initialized on a
real tpm.

These instructions are for the VM based platforms in the directory:

```shell
  $CERTIFIER_ROOT/vm_model_tools/examples/scenario1
```

As mentioned abolve, you may want to just compile the framework and 
vm_model_tools executables, without being root.  To do this:

```shell
  ./run-test-scenario1.sh -bss 0 -ccf 1 -loud 1 -dn dom0 -pn cf-utility \
   -pk 1 -just-compile 1 -tpm /dev/tpmrm1
```

If you do this, you can use the -ccf 0 flag when you run run-test-scenario1.sh as root.

To run run-test-scenario1.sh from scratch, in the tpm environment, as root, type:

```shell
  ./run-test-scenario1.sh  -bss 0 -ccf 1 -loud 1 -et2 tpm-enclave -tpm /dev/tpmrm1 \
   -end_chain ekchain.bin -pk 1 -pn cf-utility
```

or, if you previously did a "compile only", as root:

```shell
    ./run-test-scenario1.sh  -bss 0 -ccf 0 -loud 1 -et2 tpm-enclave -tpm /dev/tpmrm1 \
     -end_chain ekchain.bin -pk 1 -pn cf-utility
```

If you have already set pcr 7, you need not and should not reset it.
You do not need "-bss 1" and you shouldn't set it.

You can rerun the test by typing, for example, in the tpm case:

```shell
  ./clean-files.sh
  ./run-test-scenario1.sh  -bss 0 -ccf 0 -pk 1 -dn dom0 -loud 0 -et2 tpm-enclave -tpm /dev/tpmrm1 \
   -end_chain ekchain.bin -tpm /dev/tpmrm1
```

This does not recompile the utilities and is much faster.

The master test script (run-test-scenario1.sh ) uses a number of sub-scripts which
can be used in different environments.  These sub-scripts can be called from the
command line also, provided you supply the needed flags. run-test-scenario1.sh
provides ALL the arguments needed by ALL the programs. Once you become familiar with
the test harness, you can economize by examining the scripts and just pass
the relevant arguments.  Some scripts are easy.  For example, cleanup.sh and
clean-files.sh can be called with no arguments in the target directory.  These
kill running simpleserver instances and keyserver instances and remove test files
so it is useful between test runs or if the script aborts.  To do this as root
(assuming $CERTIFIER_ROOT and EXAMPLE_DIR are defined), in the $EXAMPLE_DIR
directory, type:

```shell
  ./cleanup.sh
  ./clean-files.sh
```
If you don't do this, the test won't work. You may also want to clean and restart the
tpm simulator but you usually need not do so.  To do this:

```script
  cd $CERTIFIER_ROOT/src/tpm2
  ./clean-tpm-simulator.sh
  ./start-tpm-simulator.sh
```

## Running the sev tests

Almost all the variables for the test scrripts are set within run-test-scenario1.sh.

As mentioned above, you may want to just compile the framework and vm_model_tools
executables, without being root.  To do this, for the simulated sev environment:

```shell
  # For simulated sev environment
  ./run-test-scenario1.sh  -bss 1 -ccf 1 -loud 1 -dn dom0 -pn cf-utility -pk 1 \
   -just-compile 1 -et2 sev-enclave -tt simulated -pfn sev_policy.bin

  # For real sev environment, using a prebuilt VM to run the test (eg- Amazon)
  # Note: The TCB version should match what you saw in the report.
  ./run-test-scenario1.sh  -tt real -et2 sev-enclave -bss 0 -ccf 1 -loud 1 \
   -dn dom0 -pn cf-utility -pk 1 -just-compile 1 -build-vm 0 -pfn sev_policy.bin \
   -migrate yes -smt yes -tcb -tcb 0xE11F000000000004 

  # For real sev environment, if you built an VM using the scripts
  # Note: The TCB version should match what you saw in the report.
  ./run-test-scenario1.sh  -tt real -et2 sev-enclave -bss 0 -ccf 1 -loud 1 \
   -dn dom0 -pn cf-utility -pk 1 -just-compile 1 -build-vm 1 \
   -migrate yes -smt yes -tcb 0xd517000000000003

  # For real sev environment, if you built an VM without using the scripts
  # Note: The TCB version should match what you saw in the report.
  ./run-test-scenario1.sh  -tt real -et2 sev-enclave -bss 0 -ccf 1 -loud 1 \
   -dn dom0 -pn cf-utility -pk 1 -just-compile 1 -build-vm 1 \
   -migrate yes -smt yes -tcb 0xd517000000000003
```

If you are running the simulated test, the simulation code is compiled in,
otherwise, not.  So if you compile for simulated, you MUST recompile for
the real test and vice versa.  See below for the meaning of the build-vm flag.

If you are using simulated SEV, the scripts construct the fabricated
measurement without further work.  In a real sev environment, the
measurements require additional steps.

For the simulated sev case, you can now run the test:

```script
  sudo bash
  # substitute your machine name
  export CERTIFIER_ROOT=/home/jlm/src/github.com/certifier-framework-for-confidential-computing
  export EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
  ./run-test-scenario1.sh  -bss 0 -ccf 0 -loud 1 -dn dom0 -pn cf-utility -pk 1 \
   -et2 sev-enclave -tt simulated -pfn sev_policy.bin
```

To test real snp, you need a snp enabled VM image.  There are two ways to get
the measurement which are determined by the BUILD_VM flag in the test script.

If you build a VM, the script do everything.  You should consult the document
"Building_a_VM" in this directory for notes on building a VM and the
design alternatives.  The subscript "build-vm.sh" does this for one of the
design alternatives.  It also has some notes on how the script builds the VM
and how the VM is hosted.

If you test in an sev enabled AWS machine, the VM you use on AWS is suitable
and the tests work in that partition.  Unlike when you build a VM, you will
use snpguest, rather that sev-snp-measure, to obtain the VM measurement.
Because of this, there is one additional step that is not done by the script
but must be done manually.  Measurement of a VM uses one of two tools:
sev-snp-measure (from IBM) or snpguest (from AMD).  You should install both as follows:

To install the sev-snp-measure tool:

```shell
  cd ~/src/github.com
  mkdir virtee
  cd virtee
  git clone https://github.com/virtee/sev-snp-measure.git
```

The snpguest tool has to be compiled with rust, if you don't have the rust environment on
your machine, install it:

```shell 
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source "$HOME/.cargo/env"
```

Now download the snpguest tool:

```shell 
  cd $CERTIFIER_ROOT
  cd ../virtee
  git clone https://github.com/virtee/snpguest.git
  cd snpguest
  cargo build -r
  # Check
  sudo ./snpguest ok
```

For measurement steps, it is convenient to define a variable:

```script
  pushd $CERTIFIER_ROOT
    cd ../virtee
    export MEASUREMENT_TOOLS=$(pwd)
  popd
```

You need the "ASK" cert for the target SNP family in either case. To get it,
on any sev-enabled machine in the same class as the target, use the snpguest
tool to retrieve the ASK cert.

```shell
  pushd $MEASUREMENT_TOOLS
    cd ./snpguest/target/release
    mkdir certs || true
    sudo ./snpguest certificates der ./certs
    sudo ./snpguest fetch ca der ./certs milan -e vlek
  popd
```

You can check them by:

```shell
  pushd $MEASUREMENT_TOOLS
    cd ./snpguest/target/release
    sudo ./snpguest verify certs ./certs
    sudo ./snpguest report report.bin request-file.txt –random
    sudo ./snpguest display report report.bin
  popd
```

For policy building, you only need the ARK cert but you need the ASKV and VCEK
certs on the target machine.  In a prebuilt VM running the entire test, these
are the same machine so there's nothing more you need to do. If you build a VM
and use it on a different machine, you need to provision these certs too.
Again, you must install the snpguest tool on those target machines and use:

```shell
  pushd $MEASUREMENT_TOOLS
    cd ./snpguest/target/release
    mkdir certs || true
    sudo ./snpguest certificates der ./certs
    sudo ./snpguest fetch ca der ./certs milan -e vlek
    # If you are on a "bare metal" sev VM, get the vcek rather than the vlek
    # as follows
    sudo ./snpguest fetch vcek der ./certs ./report.bin
  popd
```

to get them.

### Measurements for running the tests in a prebuilt VM (for example, the AWS tests)

For the AWS machine, to get the VM measurement, run snpguest:

```shell
  pushd $MEASUREMENT_TOOLS
    cd ./snpguest/target/release
    sudo ./snpguest report report.bin request-file.txt --random
    sudo ./snpguest display report report.bin
  popd
```

In the output, you will see a measurement like this:

```shell
...
Measurement:
7A 89 CC EA AB A0 BB DD DC 4F 77 5A CC A3 EF 15
D1 F9 BF 8A BC CD C6 11 5C FA D7 FB 8E AE 11 3D
F3 EE 0B B5 0E FA 34 DB 9C 53 AE 06 5B 1D C7 66
```

Using a text editor, put this in the file
$CERTIFIER_ROOT/vm_model_tools/examples/scenario1/sev.measurment.  The file
should have the measurement on a single line with a line feed at the
end and nothing else (just like the output from the sev-snp-measure tool).
You should remove all the spaces in this file, too.

The measurement is 48 bytes and so the file (with a line feed at the end)
should have exactly 97 bytes.

One additional note on AWS platforms.  AWS does not make VCEK certificates
available but uses a "VLEK" certificate described below.  The scripts handle
the differences but bare metal VM's should continue to use VCEKs for
attestation.

An AMD VLEK (Versioned Loaded Endorsement Key) is a versioned Elliptic Curve
Digital Signature Algorithm (ECDSA) P-384 signing key used by AMD SEV-SNP
(Secure Nested Paging) firmware to sign virtual machine attestation reports.
A VLEK is an alternative to the VCEK (Versioned Chip Endorsement Key) used
for signing SEV-SNP attestation reports, allowing virtual machines to
authenticate their launch measurements and integrity.  Unlike the VCEK—which
is derived directly from a unique device secret hardcoded into the silicon
chip—the VLEK is derived from a secret maintained and shared between AMD
and Cloud Service Providers (CSPs) via the AMD Key Derivation Service (KDS).
They are commonly used in shared-tenancy or multi-tenant cloud environments
(such as Amazon EC2 SEV-SNP instances) where guests rely on cloud-managed
endorsement keys rather than direct hardware-bound chip keys.
The certificate chain traces back to the AMD Root Key (ARK) and
AMD SEV-VLEK Key (ASVK) infrastructure, with certificate revocation
lists (CRLs) hosted via AMD's KDS endpoints
(e.g., https://kdsintf.amd.com/vlek/v1/{product_name}/crl).


### Measurements for running the tests in a new VM (for example, tests on a bare metal platform)

If you build your own VM, You should also install the ovmf firmware which is
required by the sev-snp-measure measurement tool.  The machine you build the
VM on need not be sev enabled.

```shell
  sudo apt install ovmf
  git clone https://github.com/AMDESE/AMDSEV.git
```

If you build your own VM, we use the sev-snp-measure to obtain the measurement.
The measurement requires the VM's vmlinuz and initrd.img you built as well as
the ovmf files, command line used to launch the VM and a few other arguments.
To obtain the additional arguments, we run the cpuid.exe on a target machine
as follows:

```shell
  $CERTIFIER_ROOT/utilities/cpuid.exe -sev-parameters
```
and then use the output as arguments to the run-policy-server.sh script.  We'll
complete the script that builds an snp vm soon; it is required for actual
deployments but it is not completed yet.


### Finally, running the test script

From this point on, everything should run as root and the scripts rely on a couple
of variables which are not reliably preserved across "sudo command or "sudo bash."
Provided you've set up the directories as described here, the following avoids
inconsistant behavior. Before you run any subsequent scripts:

```shell
  sudo bash
  # Use the full path name and not abbreviations leik "~".  On my AWS VM, the directory
  # is as below but you might have to change it on your machine.
  export CERTIFIER_ROOT=/home/ubuntu/src/github.com/certifier-framework-for-confidential-computing
  export EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
```

To run the sev tests from scratch, as root, run one of the following five commands:

```shell
  # 1. If you are running in the simulated environment but have not compiled the
  # certifier yet and have not build the simulator or installed the simulated driver
  ./run-test-scenario1.sh  -tt simulated -bss 1 -ccf 1 -loud 1 -dn dom0 \
   -pn cf-utility -pk 1 -et1 "simulated-enclave" -et2 "sev-enclave"
```

```shell
  # 2. If you are running in the simulated environment but have compiled the
  # certifier already but have # not installed the simulated sev driver or environment
  ./run-test-scenario1.sh  -tt simulated -bss 1 -ccf 0 -loud 1 -dn dom0 \
   -pn cf-utility -pk 1 -et1 "simulated-enclave" -et2 "sev-enclave"
```

```shell
  # 3. If you are running in the simulated environment and have compiled the
  # certifier already and have installed the simulated sev driver and environment
  ./run-test-scenario1.sh  -tt simulated -bss 0 -ccf 0 -loud 1 -dn dom0 \
  -pn cf-utility -pk 1 -et1 "simulated-enclave" -et2 "sev-enclave"
```

```shell
  # 4. If you are running for the real sev environment but have not compiled the certifier
  # and are using a prebuilt VM(AWS)
  ./run-test-scenario1.sh -tt real -bss 0 -ccf 1 -loud 1 -dn dom0 \
   -pn cf-utility -pk 1 -et1 "simulated-enclave" -et2 "sev-enclave" \
   -build-vm 0
  # Change "-build-vm 0" to "-build-vm 1" if you want to build a new VM.
  # This is not working yet.
```

```shell
  # 5. If you are running for the real sev environment and have compiled the
  # certifier and are using a prebuilt VM(AWS)
  ./run-test-scenario1.sh -tt real -bss 0 -ccf 0 -loud 1 -dn dom0 \
  -pn cf-utility -pk 1 -et1 "simulated-enclave" -et2 "sev-enclave" \
  -build-vm 0
  # Change "-build-vm 0" to "-build-vm 1" if you want to build a new VM.
  # This is not working yet.
```

In the last two cases, you should have either obtained the measurement for an
AWS machine using snpguest or obtained the arguments for the sev-snp-measure
tool as mentioned above.  The -build-vm flag should be 0 if you use a prebuilt
AWS VM and are running in it and it should be 1 if you built your own VM.

If you build your own VM, there are more arguments to the script, obtained from the
cpuid.exe program mentioned above that you should append, these look like:

```shell
  -sev-dev /dev/sev-guest -sev-mfn ./sev.measurement \
  -initram-mfn ../initrd.img -kernel-mfn ../vmlinuz \
  -ovmf-loc /usr/share/ovmf/OVMF.amdsev.fd  \
  -et2 "sev-enclave" -et1 "simulated-enclave" -et2 "sev-enclave"
```

These should be appended whether you use the -ccf 1 or -ccf 0 flags in the
commands you use and the argument to the flags should match your actual
environment.


### Rerunning the test script

After you run the test the first time, you need not re-compile the certifier,
remeasure the VM (if you use a real sev machine) or install the device driver
(if you use a simulated environment). To rerun the tests again, again make
sure you are root and have defined CERTIFIER_ROOT and EXAMPLE_DIR as mentioned
above.  It's a good idea to clean the app files and kill any residual test
created in earlier runs by typing in $EXAMPLE_DIR as root:

```shell
  ./clean-files.sh
  ./cleanup.sh
```

Then, as root, you can rerun the test by typing:

```shell
  # for real sev with built VM
  ./run-test-scenario1.sh  -tt real -bss 0 -ccf 0 -loud 1 -dn dom0 \
   -pn cf-utility -pk 1 -sev-dev /dev/sev -sev-mfn ./sev.measurement \
   -initram-mfn ../initrd.img -kernel-mfn ../vmlinuz \
   -ovmf-loc /usr/share/ovmf/OVMF.amdsev.fd  -et2 "sev-enclave" \
   -et1 "simulated-enclave" -et2 "sev-enclave" -vm-build 1
  # for real sev with pre-built VM
  ./run-test-scenario1.sh  -tt real -bss 0 -ccf 0 -loud 1 -dn dom0 \
   -pn cf-utility -pk 1 -sev-dev /dev/sev -sev-mfn ./sev.measurement 
  # for simulated sev
  ./run-test-scenario1.sh  -tt simulated -bss 0 -ccf 0 -loud 1 -dn dom0 -pn cf-utility -pk 1 -et1 "simulated-enclave" -et2 "sev-enclave"
```

The clean-files.sh script will not delete the sev.measurment file you prepared
for a real sev environment on AWS nor will you need to rerun the cpuid.exe -sev-parameters
if you built your own VM BUT you do need to redo those steps if you build a new
VM or switch target machine environments.

