# TPM utilities and tests
----
This directory contains the tpm tests and utilities.


## Install the simulator (swtpm) --- one time step

It is usually convenient to run the simulator in a different window.
The simulator must run as root.

The simulator is at https://github.com/stefanberger/swtpm. On Ubuntu, you can install
it as follows:

```shell
  sudo apt-get update
  sudo apt install swtpm swtpm-tools apparmor -y
``
You only need to do thsi once/machine.

## Build utility and tests
------------------

$CERTIFIER_PROTOTYPE is the top level directory for the certifier repository.
It is helpful to have a shell variable for it, e.g.,:

```shell
export CERTIFIER_PROTOTYPE=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the tests and utility.

```shell
EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/src/tpm2
```

Preparing the tests and utility
------------------

```shell
   cd $EXAPLE_DIR
   make clean -f tpm2_support.mak
   make -f tpm2_support.mak
```

## run utility and tests
 
There are a number of scripts to help run the tests and simulator,
to run them, edit the .sh files to set XDG_CONFIG_HOME.  Since
the scripts are run asroot, it's best to name a full path.

In another window, the "Priviledged window":

```shell
   cd $EXAMPLE_DIR
   sudo bash
   password
   ./start-tpm-simulator.sh
```

Then run the utility to set PCR 7:

```shell
  ./tpm2_set_pcrs.exe --pcr_num=7 --num_pcrs=1 --tpm_device=/dev/tpmrm1
```

Finally, run the tests:

```shell
  ./tpm2_test.exe --operation=MiscTest --tpm_device=/dev/tpmrm1
  ./tpm2_test.exe --operation=GetCert --tpm_device=/dev/tpmrm1
  ./tpm2_test.exe --operation=EndorsementTest --tpm_device=/dev/tpmrm1
  ./tpm2_test.exe --operation=SealTest --tpm_device=/dev/tpmrm1
  ./tpm2_test.exe --operation=QuoteTest --tpm_device=/dev/tpmrm1
  ./tpm2_test.exe --operation=CertifierTest --tpm_device=/dev/tpmrm1
```

If you use the "real" tpm, you should change the device name above.
