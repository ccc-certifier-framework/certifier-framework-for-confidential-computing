# Instructions for running scenario1

This document gives detailed instructions for running scenario1
in both test and full SEV environment.  The basic certifier utility
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

This document has corresponds to the "SevProvisioning" document, in 
$(CERTIFIER_ROOT)/Doc, which should be read in conjunction with this.


## Overview

Running the tests is considerably simplified by a consolidated script,
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
    ./run-test-scenario1.sh  -tt simulated -bss 1 -ccf 1 -loud 1
```

The three variable have the following effect:
    "-tt simulated" tells the script that the "deployed enviornment" is the simulated SEV enclave.
        As a result, the simulating SEV device driver will be build and installed and no
        VM is needed and simulated keys and certificates are built.
    "-ccf 1" tells the script that it should compile all the certifier utilities and programs.
    "-bss 1" tells the script to actually build and install the driver.

After you run this the first time, you need not re-compile the certifier or install the
device driver so you can run the test by typing:

```shell
    ./run-test-scenario1.sh  -tt simulated -bss 0 -ccf 0 -loud 1
```

This saves considerable time.  However, you do need to recompile for a "real" sev
platform because it will not compile the "SIMULATED_SEV" interface.

You can also type:

```shell
    ./run-test-scenario1.sh  -tt simulated -bss 0 -ccf 0 -pk 0 -loud 1
```

which, does not regenerate policy keys and certificates.

Since the device driver can only be accessed by root, you should run as root when you type these commands.

All the subcomands can be called from the command line also, provided you supply the
needed flags. run-test-scenario1.sh provides ALL the arguments needed by
ALL the programs so you can economize by examining the scripts and just passing
the relevant arguments.  Some scripts are easy.  For example, ./cleanup.sh can
be called with no arguments.  It kills running simpleserver instances and keyserver
instances so it is useful if the script aborts.

You can clean all the test data and configuration files generated in a run
by typing:

```shell
    ./clean-files.sh
```

Once you clean the test data and configuration files, you need not recompile the certifier
or device driver but you need to do everything else, by typing:

```shell
    ./run-test-scenario1.sh  -tt simulated -bss 0 -ccf 0
```

If you installed the device driver (sev_null) before running the scripts, you do not need "-bss 1".

One more thing: If you run a test that fails and you want to cleanup, you should run:

```shell
    ./cleanup.sh
    ./clean-files.sh
```

This removes the application files from the last run and kills the server processes used in the
test.  If you don't do this, subsequent test may not be able to open the ports needed for the tests.

The scripts do not build a VM yet.  Stay tuned for more information on that.
