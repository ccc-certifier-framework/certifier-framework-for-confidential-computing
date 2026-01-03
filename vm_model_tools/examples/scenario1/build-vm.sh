#!/bin/bash

# ############################################################################
# build_vm.sh script to build final deployable VM
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then                   
        print-variables                         
fi
if [[ $TEST_TYPE = "simulated" ]]; then
	echo "Nothing to do in simulated environment"
fi

echo "John needs help here"
echo ""
