#!/bin/bash
#
# ############################################################################
# build-sev-sim.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# This subscript builds the sev simulator (in $/CERTIFIER_ROOT/sev-snp-simulator).
# It produces and installs a loadable driver module (sevnull) and generates the
# simulated environments signing key.

# ---------------------------------------------------------------------------------

function compile-sev-programs() {
	echo " "
	echo "do-compile-sev-programs"

	cd $CERTIFIER_ROOT/sev-snp-simulator
	make clean
	make
	make keys
	sudo make insmod

	echo "done"
	echo " "
}

# ----------------------------------------------------------------------------------

echo ""
echo "build-sev-sim.sh"
echo ""

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

# ----------------------------------------------------------------------------------

