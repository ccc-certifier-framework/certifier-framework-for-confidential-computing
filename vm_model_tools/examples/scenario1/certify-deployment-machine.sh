#!/bin/bash

# ############################################################################
# certify deployment machine.sh 
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# -----------------------------------------------------------------------------------------------

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

echo " "
echo "Certify me"

if [ $OPERATION  == "run" ] ; then
  do-run
fi

echo "Certification complete "
echo " "
