# cf_utility - Instructions

This document gives detailed instructions for running scenario1
in both test and full SEV environment.

cf_utility.exe is described in cf_utility_usage_notes.md.

$CERTIFIER_ROOT is the top level directory for the Certifier repository.
It is helpful to have a shell variable for it:

```shell
export CERTIFIER_ROOT=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
```

$EXAMPLE_DIR is this directory containing the example application.  Again, a
shell variable is useful, if you run the detailed steps below.

```shell
export EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
```

This document has instructions corresponding to the "SevProvisioning" document
in $(CERTIFIER_ROOT)/Doc.


## Overview

Running the tests are considerably simplified by a consolidated script,
run-test-scenario1.sh.  It runs all the subordinate scripts described
in Sevprovisioning.

# Running either in SEV or the test environment using the consolidated tests script

To compile the programs, establish the environment and run the entire test, the
subordinate scripts employ a number of shell variables.   It's a good idea to
define the first two in the shell you use by doing the following:

```shell
    export CERTIFIER_ROOT=~/src/github.com//ccc-certifier-framework/certifier-framework-for-confidential-computing
    export EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
```

Almost all the variables are set within run-test-scenario1.sh.  To run it from scratch,
in the simulated sev environment type:

```shell
    ./run-test-scenario1.sh  -tt simulated -bss 0 -ccf 1 -loud 1
```

The three variable have the following effect:
    "-tt simulated" tells the script that the "deployed enviornment" is the simulated SEV enclave.
        As a result, the simulating SEV device driver will be build and installed and no
        VM is needed and simulated keys and certificates are built.
    "-ccf 1" tells the script that it should compile all the certifier utilities and programs.
    "-bss 1" tells the script to actually build and install the driver.

After you run the first time, you need not compile the certifier or install the device driver so
you can run the test by typing:

```shell
    ./run-test-scenario1.sh  -tt simulated -bss 0 -ccf 0 -loud 1
```

This saves considerable time.  You can also type:

```shell
    ./run-test-scenario1.sh  -tt simulated -bss 0 -ccf 0 -pk 0 -loud 1
```

which, does not regenerate policy keys and certificates.

Since the device driver can only be accessed by root, you should run as root when you type these commands.

All the subcomands can be called from the command line, provided you supply the
needed arguments. ./run-test-scenario1.sh provides ALL the arguments needed by
ALL the programs so you can economize by txamining the scripts.  Some are easy.
Sore example, ./cleanup.sh can be called with no arguments.  It is not described
in Sevprovisioning; it kills running simpleserver instances and keyserver
instances so it is useful if the script aborts.

You can clean all the test data and configuration files by typing:

```shell
    ./clean-files.sh
```

Once you clean the test data and configuration files, you need not recompile the certifier or device driver but
you need to do everything else, by typing:

```shell
    ./run-test-scenario1.sh  -tt simulated -bss 0 -ccf 0
```

The scripts do not build a VM yet.  Stay tuned for more information on that.
