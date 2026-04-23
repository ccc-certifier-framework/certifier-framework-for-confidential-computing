#!/bin/bash

# ############################################################################
# build-activation-policy.sh: Script to build activation policy on the deployment machine
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc


# -------------------------------------------------------------------------------

function do-make-activation-policy() {
    echo "do-make-activation-policy"

    if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
      mkdir $EXAMPLE_DIR/provisioning
    fi

    if [[ ! $DEPLOYED_ENCLAVE_TYPE = "tpm-enclave" ]]; then
        echo " "
    fi

  pushd $EXAMPLE_DIR/provisioning
  popd

  echo ""
  echo "do-make-activation-policy done"
}


# ------------------------------------------------------------------------------

echo ""
echo "build-activation-policy.sh"
echo ""

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then                   
        print-variables                         
fi

do-make-activation-policy
echo ""
echo "build-activation-policy.sh done"
echo ""

# ------------------------------------------------------------------------------

