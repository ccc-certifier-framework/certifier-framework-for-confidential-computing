#!/bin/bash

# ############################################################################
# measure-vm-program.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# This script measures the deployed vm in a real sev test using the
# sev-snp-measure tool if you build your own VM) or a predefined measurement
# in $EXAMPLE_DIR/sev.measurement in a prebuit VM (like AWS).
# This script is currently incomplete because we haven't built VMs yet.

# -----------------------------------------------------------------------------------


function do-measure-vm() {
  echo " "
  echo "measuring vm"

  if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
          mkdir $EXAMPLE_DIR/provisioning
  fi

  pushd $EXAMPLE_DIR/provisioning
    if [[ $BUILD_VM -eq 1 ]]; then
      pushd $CERTIFIER_ROOT
        cd ..
        MEASURE_PROG_DIR=$(pwd)/virtee/sev-snp-measure
      popd
      if [[ ! -e "$MEASURE_PROG_DIR" ]] ; then
        echo "Measurement program directory, $MEASURE_PROG_DIR, does not exist.  Did you install it?"
        exit
      fi
      echo ""
      echo "$MEASURE_PROG_DIR/sev-snp-measure.py --mode snp --vcpu-family $CPU_FAMILY --vcpu-model $CPU_MODEL --vcpu-stepping $CPU_STEPPING " \
        "--ovmf $OVMF_LOCATION --kernel $VM_KERNEL_FILE_NAME --initrd $VM_INITRAM_FILE_NAME  " \
        "--vcpus $NVCPUS --vmm-type $VMM_TYPE --output-format hex > $SEV_MEASUREMENT_FILE_NAME "
      $MEASURE_PROG_DIR/sev-snp-measure.py --mode snp --vcpu-family $CPU_FAMILY --vcpu-model $CPU_MODEL --vcpu-stepping $CPU_STEPPING \
        --ovmf $OVMF_LOCATION --kernel $VM_KERNEL_FILE_NAME --initrd $VM_INITRAM_FILE_NAME  \
        --vcpus $NVCPUS --vmm-type $VMM_TYPE --output-format hex > $SEV_MEASUREMENT_FILE_NAME
    else
      cp $EXAMPLE_DIR/sev.measurement $SEV_MEASUREMENT_FILE_NAME
    fi
  popd

  echo "vm measured"
  echo " "
}

echo ""
echo "measure-vm-programs.sh"
echo ""

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

if [[ $OPERATION  = "measure" ]] ; then
  do-measure-vm
else
  echo "Unknown operation: $OPERATION"
fi
echo " "

# --------------------------------------------------------------------------------

