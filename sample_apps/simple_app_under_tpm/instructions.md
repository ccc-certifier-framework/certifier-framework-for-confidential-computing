# Simple App under TPM instructions

This example app shows all the major steps in a Confidential Computing program,
running under the TPM.

This uses the same application as in [simple_app]
This example embeds the policy key in the application using the
`embed_policy_key.exe`.

## Simulated TPM Environment

We also support a TPM simulator (swtpm) which can be configured and installed
on any Linux host.  This is done using the script start-tpm-simulator.sh.
You should follow the instructions in $CERTIFIER_PROTOTYPE/src/tpm2 to install
the simulator and build the pcr utility.  If you use a "real" tpm, you should
change the device name in the scripts.

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

The TPM enclave introduces an additional policy step for cefrtification.  For
enclaves like SEV, the public key for the quote or attestation, is part of
platform provisioning.  If the certifier "trusts" the manufacturer root
certificate, the elements of the certification can be provided in one pass.
By contrast, the TPM employs a "first pass" in which the quoting key established
trust with the certifier using a protocol.  This protocol uses the
"ActivateCredential" functionality of the TPM.

To implement this.  The certifier opens a new protocol channel that accepts
a certificate chain from the TPM manufacturers that offers evidence to support
the security of the TPM "endorsement cert."  The deployed program packages this
along with unforgeable information about the ultimate "quoting key," produces a
cert for the quoting key, encrypts the cert with a random key (a "credential")
and encrypts the the credential to the endorsement key.  The credential can
only be decrypted by the TPM with the trusted endorsement cert which verifies
properties of the quoting key and unlocks the credential which, in turn, is
used to decrypt the quoting key certificate.  This certificate can then be
used in the same way an authenticated vcek key is  used in SEV.

The upshot is that the certifier is first called with the "first pass" tag that
implements the new step to approve the quote key.  After the quote key is
validated, resulting in a certificate signed by the policy key.  The
proof protocol used in other enclaves is used to produce an "Admisions
Certificate" as is customary.


Set up environment
------------------

$CERTIFIER_PROTOTYPE is the top level directory for the certifier repository.
It is helpful to have a shell variable for it, e.g.,:

```shell
export CERTIFIER_PROTOTYPE=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the example application.  Again, a
shell variable is useful.

```shell
export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app_under_tpm
```


Preparing the tests
------------------

First we'll compile the application and certifier. generate the usual policy
keys and certificates, and start the certifier. To do this, in a window,
the "unprivledged window," type:

```shell
  cd $EXAMPLE_DIR
  ./prepare-test.sh all dom0 # dom0 is our domain-name in the test
```

This script also coolects the "trusted roots" for the TPM manufacturers and
builds a database for them.

Next, we'll start the simulator.  As described in the instructions for the
TPM utilities, you should change the directoy set by the variable
XDG_CONFIG_HOME to the location of your tpm state in the shell script
start-tpm-simulator.sh.  I recommend using the full pathname.

First, we need a "privilged window" where we run as root.  We will
use this window later.  If you have not already provisioned such a window,
in a new window, "priviledged window 1," type:

```shell
   cd $EXAMPLE_DIR
   sudo bash
   password
   # In the next command, use the full path name of your certifier
   # root directory.
   export CERTIFIER_PROTOTYPE=/home/jlm/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
   export EXAMPLE_DIR=$CERTIFIER_PROTOTYPE/sample_apps/simple_app_under_tpm
```

Even if you've already started a tpm simulator, if it is in a bad state,
after a previous run, you may want to reinitialize it:

```shell
  ./clean-tpm-simulator.sh
```

In any case, now start the tpm simulator:

```shell
   ./start-tpm-simulator.sh
```

Even if you've already started a tpm simulator, if it is in a bad state,
you may want to reinitialize it:

When your done, or hit an error, you can restore the pristine state of the TPM,
kill zombied processes, and delete application files by typing into priviledged
window 1:

```shell
  ./clean-tpm-simulator.sh
```

Next we use the utility in $CERTIFIER_ROOT/src/tpm2 to set pcr 7 (which holds our
application measurment).  In the "priviledged window," type:

```shell
  ../../src/tpm2/tpm2_set_pcrs.exe --pcr_num=7 --num_pcrs=1 --tpm_device=/dev/tpmrm1
```

Now, run the first pass.  In the "privilged window," type:

```shell
  ./first-pass.sh dom0 1
  cp measurement ./provisioning
  chmod 0777 measurement ./provisioning/measurement
  chmod 0777 ./provisioning/quote_cert.crt
```

This will result in the quoting cert and a measurment, normally obtained
by other means, specifying the measurement of a trusted application.

Next, now that we have the measuerment and quote cert, we complete building the
policy, producing a "policy.bin" as in the other examples.  To do this,
Back in the Unpriviledged window:

```shell
  ./final-prep.sh dom0
```

Running the tests
-----------------

Next in priviledged window 1:

```shell
 ./run-init-apps.sh run dom0
```

This starts the certifier with the now complete policy, and as with the other
applications, initializes the application twice, once for client operations,
and once for server application and communicates with the certifier service
to get them certified (thus resulting in a protected policy store and
admissions certificate for each of the application modes.

Now, in priviledged window 1, type:

```shell
  ./run-server-app.sh dom0
```

This starts the applicaton in server mode.

Finally, in a new (third) window, "priviledged window 2",

```shell
  cd $EXAMPLE_DIR
  sudo bash
  ./run-client-app.sh dom0
```

This starts the client and will establish a secure policy controlled channel
with the server producing the usual "Hi form your secret server" and
"Hi from your secret client" as in all the other examples.

Control c to stop the server in priviledged window 1.

The script clean-tpm-simulator.sh will stop the tpm simulator and clean-up
the files and processes it created.

----------------------------------------------------------------------------------

