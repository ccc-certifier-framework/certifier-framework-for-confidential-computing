#!/bin/bash

# ############################################################################
# measure-programs.sh: Script to measure test program
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------

# This script measures the programs that can run under the simulated enclave,
# namely, cf_utility.exe.  The measurement is a hash for the simulated enclave
# environment and a fixed measurement in the sev simulator fir the simulated
# sev environment.  The measurements are stored in the provisiong directory
# in cf_utility.measurement and sev_cf_utility.measurement.


function do-fresh() {
	echo " "
	echo "do-fresh"

	if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
		mkdir $EXAMPLE_DIR/provisioning
	fi
	pushd $EXAMPLE_DIR/provisioning
		if [[ -f "cf_utility.measurement" ]] ; then
			rm cf_utility.measurement
		fi
	popd
	echo "do-fresh done"
  echo ""
}

function do-measure() {
  echo ""
  echo "measuring test program"

  if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
  	mkdir $EXAMPLE_DIR/provisioning
  fi

  pushd $EXAMPLE_DIR/provisioning
  $CERTIFIER_ROOT/utilities/measurement_utility.exe \
       --type=hash --input=$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
       --output=$EXAMPLE_DIR/provisioning/cf_utility.measurement
  if [[ $DEPLOYED_ENCLAVE_TYPE = "sev-enclave" && $TEST_TYPE = "simulated" ]]; then
    $CERTIFIER_ROOT/utilities/measurement_init.exe \
        --mrenclave=010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708 \
        --out_file=sev_cf_utility.measurement
  fi
  popd

  echo "test program measured"
  echo ""
}

echo "Processing arguments - $*"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

if [[ $CLEAN -eq 1 ]] ; then
	do-fresh
fi

if [[ $OPERATION  = "measure" ]] ; then
	do-measure
else
	echo "Unknown operation: $OPERATION"
fi
echo " "
