# Instructions for running scenario1

This document gives detailed instructions for running scenario1
in both simulated or full SEV environment (in the case of an sev
"deployed enclave") or a simulated or real tpm environment
(in the case of tpm "deployed enclave") .  The basic vm utility
used is cf_utility.exe, cf_utility.exe is described in
cf_utility_usage_notes.md.

In the scripts, $CERTIFIER_ROOT is the top level directory for the Certifier
repository.  It is helpful to have a shell variable for it:

```shell
export CERTIFIER_ROOT=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
export EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
```

$EXAMPLE_DIR is this directory containing the example application.  Again, a
shell variable is useful, if you run the detailed steps below.


## Overview

Running the tests is considerably simplified by a consolidated script,
run-test-scenario1.sh.  It runs all the subordinate scripts.


### Special note for tpms:
The TPM enclave introduces an additional policy step for cefrtification.  For
enclaves like SEV, the public key for the quote or attestation, is part of
platform provisioning.  If the certifier "trusts" the manufacturer root
certificate, the elements of the certification can be provided in one pass.
By contrast, the TPM employs a "first pass" in which the quoting key
established trust with the certifier using a protocol.  This protocol
uses the "ActivateCredential" functionality of the TPM.

To implement this.  The certifier opens a new protocol channel that
accepts a certificate chain from the TPM manufacturers that offers evidence
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
"Admisions Certificate" as is customary.

# Running either in SEV, tpm or the test environment using the consolidated tests script

To compile the programs, establish the environment and run the entire test, the
subordinate scripts employ a number of shell variables.   It's a good idea to
define the first two in the shell you use by doing the following:

```shell
    export CERTIFIER_ROOT=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
```

or

```shell
    export CERTIFIER_ROOT=~/src/github.com/certifier-framework-for-confidential-computing
```

or specify the directory you installed the certifier.

If you're root, use the full path name without the "~" abbreviation. For
example,

```shell
    export CERTIFIER_ROOT=/home/jlm/src/github.com/certifier-framework-for-confidential-computing
```

Then,

```shell
    export EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
```

# Running the tests

All tests can be run from a consolidated script called run-test-scenario1.sh. The script
uses a number of variables to control test behavior.  Some important
variables have the following effect:

    "-ccf 1" tells the script that it should compile all the certifier utilities
        and programs.
    "-bss 0" tells the script NOT to build and install the driver for the
        simulated sev.
    "-pk 1" tells the script to generate keys and certificates for the domain.
    "-loud 1" tells the script to print a lot of debug output.
    "-just-compile 1" tells the script to just compile stuff (you need not be root to do this)

You may want to just compile the framework and vm_model_tools executables,
without being root.  To do this:

```shell
    ./run-test-scenario1.sh  -bss 0 -ccf 1 -loud 1 -dn dom0 -pn cf-utility -pk 1 -just-compile 1
```

If you do this, you can use the -ccf 0 flag when you run run-test-scenario1.sh as root for
platforms that need root privileges.  Not having to compile saves a lot of time so you should
definitely not recompile if you don't have to.

Now refer to the platform specific instructions below.


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

You may want to clean up files and simulator state from previous runs.
To do this:

```shell
    ./clean-tpm-simulator.sh
```
As root, start the tpm simulator for testing, and set pcr 7:

```shell
    ./start-tpm-simulator.sh
    export TPM_SUPPORT_DIR=$CERTIFIER_ROOT/src/tpm2
    sleep 2
    $TPM_SUPPORT_DIR/tpm2_set_pcrs.exe --pcr_num=7 --num_pcrs=1 --tpm_device=/dev/tpmrm1
```

If you are using a "real" tpm, make sure you set the correct device name
(-tpm /dev/tpmrm1, below).

as mentioned abolve, you may want to just compile the framework and 
vm_model_tools executables, without being root.  To do this:

```shell
    ./run-test-scenario1.sh  -bss 0 -ccf 1 -loud 1 -dn dom0 -pn cf-utility -pk 1 -just-compile 1 -tpm /dev/tpmrm1
```

If you do this, you can use the -ccf 0 flag when you run run-test-scenario1.sh as root.

To run run-test-scenario1.sh from scratch, in the tpm environment, as root, type:

```shell
    ./run-test-scenario1.sh  -bss 0 -ccf 1 -loud 1 -et2 tpm-enclave -tpm /dev/tpmrm1 -end_chain ekchain.bin -pk 1 -pn cf-utility
```

or, if you previously did a "compile only", as root:

```shell
    ./run-test-scenario1.sh  -bss 0 -ccf 0 -loud 1 -et2 tpm-enclave -tpm /dev/tpmrm1 -end_chain ekchain.bin -pk 1 -pn cf-utility
```

If you have already set pcr 7, you need not and should not reset it.
You do not need "-bss 1" and you shouldn't set it.

You can rerun the test by typing, for example, in the tpm case:

```shell
    ./clean-files.sh
    ./run-test-scenario1.sh  -bss 0 -ccf 0 -pk 1 -dn dom0 -loud 0 -et2 tpm-enclave -tpm /dev/tpmrm1 -end_chain ekchain.bin -tpm /dev/tpmrm1
```
This does not recompile the utilities and is much faster..

All the subcomands can be called from the command line also, provided you supply the
needed flags. run-test-scenario1.sh provides ALL the arguments needed by
ALL the programs so you can economize by examining the scripts and just passing
the relevant arguments.  Some scripts are easy.  For example, ./cleanup.sh can
be called with no arguments.  It kills running simpleserver instances and keyserver
instances so it is useful if the script aborts.

Reminder: If you run a test that fails and you want to cleanup, you should run:

```shell
    ./cleanup.sh
    ./clean-files.sh
```
This removes the application files from the last run and kills the server
processes used in the test.  If you don't do this, the test won't work. You
may also want to clean and restart the tpm simulator but you usually need
not do so.


## Running the sev tests

Again, almost all the variables are set within run-test-scenario1.sh.

As mentioned above, you may want to just compile the framework and vm_model_tools
executables, without being root.  To do this, for the simulated sev environment:

```shell
    ./run-test-scenario1.sh  -bss 1 -ccf 1 -loud 1 -dn dom0 -pn cf-utility -pk 1 -just-compile 1
```

if you are running on a real sev platform, 

```shell
    ./run-test-scenario1.sh  -bss 0 -ccf 1 -loud 1 -dn dom0 -pn cf-utility -pk 1 -just-compile 1
```

If you do this, you can use the -ccf 0 flag when you run run-test-scenario1.sh as
root.

SEV measurements for the real SEV platform requires installing an open source tool from IBM.
You will likely install this is your github.com directory.

To do this:

```shell
cd ~/src/github.com
git clone https://github.com/virtee/sev-snp-measure.git
```

You shoud also install the ovmf firmware for the measurement tool.

```shell
sudo apt install ovmf
git clone https://github.com/AMDESE/AMDSEV.git
```

The following package build host/guest kernels, QEMU, and OVMF
from AMD's development branches for SEV 3.0+ (SNP).

```shell
git clone https://github.com/AMDESE/AMDSEV.git
```

https://www.amd.com/en/developer/sev.html has useful information for sev.

If you are using real SEV, the script that measures the vm will call the utility but
the scripts assume the directory .../virtee/sev-snp-measure is in your path.
If you are using simulated SEV, the scripts construct the fabricated measurement
without this utility

To run the test from scratch, in the simulated sev environment, as root, type:

```shell
    ./run-test-scenario1.sh  -tt simulated -bss 1 -ccf 1 -loud 1 -dn dom0 -pn cf-utility -pk 1 -et1 "simulated-enclave" -et2 "sev-enclave"
```

or, if you already compiled as above, and havent installed the simulated sev driver:

```shell
    ./run-test-scenario1.sh  -tt simulated -bss 1 -ccf 0 -loud 1 -dn dom0 -pn cf-utility -pk 1 -et1 "simulated-enclave" -et2 "sev-enclave"
```

or, if you already compiled as above, and have installed the simulated sev driver:

```shell
    ./run-test-scenario1.sh  -tt simulated -bss 0 -ccf 0 -loud 1 -dn dom0 -pn cf-utility -pk 1 -et1 "simulated-enclave" -et2 "sev-enclave"
```

If you use the real SEV and have compiled the framework (and the measurement tool),

```shell
    ./run-test-scenario1.sh  -tt real -bss 0 -ccf 0 -loud 1 -dn dom0 -pn cf-utility -pk 1 -sev-dev /dev/sev -sev-mfn ./sev.measurement -initram-mfn ../initrd.img -kernel-mfn ../vmlinuz -ovmf-loc /usr/share/ovmf/OVMF.amdsev.fd  -et2 "sev-enclave" -et1 "simulated-enclave" -et2 "sev-enclave"
```

Some new flags we used are:
    "-tt simulated" tells the script that the "deployed enviornment" is the
        simulated SEV enclave.  As a result, the simulating SEV device driver
        will be build and installed and no VM is needed and simulated keys and
        keys for the simulated environment are built.
    "-bss 1" tells the script to build and install the driver for the
        simulated sev.
    "-sev-dev" specifies the sev device driver.
    "-sev-mfn specifies the location of the measurement file.

After you run the test the first time, you need not re-compile the certifier or
install the device driver. To rerun the tests again, first clean the app files:

```shell
    ./clean-files.sh

Then, as root, you can rerun the test by typing:

```shell
    ./run-test-scenario1.sh -tt simulated -bss 0 -ccf 0 -loud 1 -dn dom0 -pn cf-utility-pk 1
```

# Note

The scripts do not build a VM yet.  Stay tuned for more information on that.
