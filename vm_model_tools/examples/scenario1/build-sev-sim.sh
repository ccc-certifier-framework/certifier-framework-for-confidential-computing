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
	if [[ $CLEAN -eq 1 ]]; then
		sudo make rmmod sevnull
	fi
	make clean
	make
	make keys
	sudo make insmod

	echo "done"
	echo " "
}

function do-copy-sev-files() {
	echo " "
	echo "do-copy-sev-files"
      
	if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
		mkdir $EXAMPLE_DIR/provisioning
	fi
	if [[ ! -e "$EXAMPLE_DIR/service" ]] ; then
		mkdir $EXAMPLE_DIR/service
	fi
	if [[ ! -e "$EXAMPLE_DIR/cf_data" ]] ; then
		mkdir $EXAMPLE_DIR/cf_data
	fi
	pushd $EXAMPLE_DIR/provisioning
		cp -p ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/cf_data
	popd
	echo "do-copy-sev-files done"
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
do-copy-sev-files

echo "simulator compiled and files copied"
echo ""
