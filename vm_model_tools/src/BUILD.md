# Certifier Framework for Confidential Computing: cf_utility

## First define some variables
``shell
export CERTIFIER_ROOT=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
```
or, depending where the repository is,

``shell
export CERTIFIER_ROOT=~/src/github.com/certifier-framework-for-confidential-computing
```

or wherever you put it.

For simulated SEV support, you must first build the device driver.
``shell
cd $CERTIFIER_ROOT/sev-snp-simulator
```

## Follow the instructions in instructions.md

##To build the utility in the current directory:

``shell
cd $CERTIFIER_ROOT/vm_model_tools/src
make -f cf_utility.mak
```

The executable is named cf_utility.exe.
