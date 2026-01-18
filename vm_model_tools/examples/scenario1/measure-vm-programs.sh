#!/bin/bash

# ############################################################################
# measure-vm-program.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# This script measures the deployed vm in a real sev test using the
# sev-snp-measure tool.
# This script is currently incomplete and untested.

# ------------------------------------------------------------------------------------------


function do-fresh() {
        echo " "
        echo "do-fresh"

        if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
                mkdir $EXAMPLE_DIR/provisioning
        fi
        pushd $EXAMPLE_DIR/provisioning
                if [[ -f "Pauls_vm.measurement" ]] ; then
                        rm Pauls_vm.measurement
                fi
        popd
        echo "do-fresh done"
        echo " "
}

# git clone https://github.com/virtee/sev-snp-measure.git
# cd sev-snp-measure
# ./sev-snp-measure.py --help
# Something like this:
# 	sev-snp-measure --mode snp --vcpus=1 --vcpu-type=EPYC-v4 --ovmf=OVMF.fd
#         \ --kernel=vmlinuz --initrd=initrd.img --append="console=ttyS0 loglevel=7"

function do-measure-vm() {
	echo " "
	echo "measuring vm"

	if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
		mkdir $EXAMPLE_DIR/provisioning
	fi

	pushd $EXAMPLE_DIR/provisioning
	echo "virtee call goes here"
	# put it in $VM_NAME.measurement
	popd

	echo "vm measured"
	echo " "
}

echo "Processing arguments - $*"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

if [[ $TEST_TYPE = "simulated" ]]; then
        echo "Nothing to do in simulated environment"
	exit
fi

if [[ $CLEAN -eq 1 ]] ; then
        do-fresh
fi

if [[ $OPERATION  = "measure" ]] ; then
        do-measure-vm
else
        echo "Unknown operation: $OPERATION"
fi
echo " "

