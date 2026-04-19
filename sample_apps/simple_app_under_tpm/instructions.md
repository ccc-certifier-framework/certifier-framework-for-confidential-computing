# Simple App under TPM instructions

This example app shows all the major steps in a Confidential Computing program,
running under the TPM.

This uses the same application as in [simple_app]
This example embeds the policy key in the application using the
`embed_policy_key.exe`.

## Simulated TPM Environment

We also support a TPM simulator (swtpm) which can be configured and installed
on any Linux host.  This is done using the script start-tpm-simulator.sh.
You should follow the instructions in $CERTIFIER_PROTOTYPE/src/tpm2 to install the
simulator and build the pcr utility.  If you use a "real" tpm, you should change
the device name in the scripts.

----

## Overview

The step by step instructions for building simple_app_under_tpm and running
the tests are enumerated below.  However, to save time, we also supply two
shell scripts to do this automatically. The shell script prepare-test.sh builds
the program and support files.  The shell script run-test.sh runs the test.
There is still benefit in carrying out the steps in run-test by copying and
pasting since you can see all the output and preserve the running servers.

The shell scripts assume you have all the right software installed including
the go programs and libraries mentioned below.

The shell scripts use the new API.
If you use the "real" tpm, you should change the device name in the shell scripts.


Set up environment
------------------

$CERTIFIER_PROTOTYPE is the top level directory for the certifier repository.
It is helpful to have a shell variable for it, e.g.,:

```shell
export CERTIFIER_PROTOTYPE=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the example application.  Again, a
shell variable is useful.


Preparing the tests
------------------

First, we'll start the simulator.  AS described in the instructions for the
TPM utilities, you should set the also change the directoy set by the variable
XDG_CONFIG_HOME to the location of your tpm state;  I recommend using the full
pathname.

 In a new window ("Root window"):

```shell
   cd $CERTIFIER_ROOT/sample_apps/simple_app_under_tpm
   sudo bash
   password
   ./start-tpm-simulator.sh
```
 
In another window, not as root, ("Unpriviledged window"): 

```shell
   cd $CERTIFIER_ROOT/sample_apps/simple_app_under_tpm
```

```shell
  .prepare-test.sh fresh domain-name
```
      - This clears out all old files
then

```shell
  prepare-test.sh all domain-name
```
      - This builds the utilities and and generates the needed keys,
        compiles the programs,
        and calls the application with the "fresh-pass" option to generate
        the quote-key.

In the root window:

```shell
  ./fresh-pass.sh domain-name
```

Back in the Unpriviledged window:

```shell
 final-prep.sh domain-name
```
      - This builds the policy and copies the files for run-test.sh

Everything should be ready to test now,

Running the tests
-----------------

In the Root window:

```shell
  echo "  ./run-test.sh fresh"
```
```shell
  echo "  ./run-test.sh fresh domain-name"
```
     -- This clears previous operational files.  The first assumes the
        default domain name ("datica-test").
```shell
  echo "  ./run-test.sh run
```

```shell
  echo "  ./run-test.sh run domain_name 
```
     -- This runs the test.  The first assumes the default domain
         name ("datica-test").

The script clean-tpm-simulator.sh will stop the tpm simulator and clean-up
the files it created.


----------------------------------------------------------------------------------

