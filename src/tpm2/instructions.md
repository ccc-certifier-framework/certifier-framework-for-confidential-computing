# TPM utilities and tests


----

## Install the simulator (swtpm) --- one time step

It is usually convenient to run the simulator in a different window.
The simulator must run as root.


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
   cd $CERTIFIER_ROOT/sample_apps/simple_app_under_tpm
   sudo bash
   password
   ./start-tpm-simulator.sh
```

## run utility and tests
 
In another window, the "Priviledged window":w

```shell
   cd $EXAMPLE_DIR
   sudo bash
   password
   ./start-tpm-simulator.sh
```

```shell
```

```shell
```
