#!/bin/bash

# ############################################################################
# build-sev-sim.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------


function compile-sev-programs() {
	echo " "
	echo "do-compile-sev-programs"

	cd $CERTIFIER_ROOT/sev-snp-simulator
	if lsmod | grep -wq "sevnull"; then
		sudo make rmmod sevnull
	fi
	make clean
	make
	make keys
	sudo make insmod

	echo "done"
	echo " "
}

# ------------------------------------------------------------------------------------------

echo "Processing arguments"
process-args
echo "Processed arguments"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

if [[ $BUILD_SEV_SIMULATOR -eq 1 ]]; then
	compile-sev-programs
fi
echo "simulator compiled"
echo ""
