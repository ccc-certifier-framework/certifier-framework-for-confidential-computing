# Certifier Framework for Confidential Computing: cf_utility

## First define some variables
``shell
export CERTIFIER_ROOT=~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing
```

For SEV support, you must first build the device driver.
``shell
cd $CERTIFIER_ROOT/sev-snp-simulator
```

## Follow the instructions in instructions.md

##To build the utility in the current directory:

``shell
cd $CERTIFIER_ROOT/vm_model_tools/src
make -f cf_utility.mak
```

Executable is names cf_utility.exe.
