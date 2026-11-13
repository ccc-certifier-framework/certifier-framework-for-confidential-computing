#!/bin/bash

# ############################################################################
# vm-run-test-component.sh
#   VM portion of test if VM is on VM but deployment service is as usual
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc


# -----------------------------------------------------------------------------------

echo "Processing arguments"
process-args
print-variables
echo "Arguments processed"

ALLARGS=""
ALLSIMARG1="-tt $TEST_TYPE -pn scenario1-test -dn dom0 -clean $CLEAN -loud $VERBOSE -just_compile $COMPILE_ONLY"
ALLSIMARG2="-dd $DATA_DIR -ccf $COMPILE_CF -bss $BUILD_SEV_SIMULATOR -pkn $POLICY_KEY_FILE_NAME"
ALLSIMARG3="-pkn policy_key_file -cfn policy_cert_file -psn policy_store -csn cryptstore"
ALLSIMARG4="-pfn $POLICY_FILE_NAME -psa $POLICY_SERVER_ADDRESS -ksa $KEY_SERVER_ADDRESS"
ALLSIMARG5="-vmn $VM_NAME -et1 $DEPLOYMENT_ENCLAVE_TYPE -et2 $DEPLOYED_ENCLAVE_TYPE -tpm-mfn $TPM_MEASUREMENT_FILE_NAME"
ALLSIMARG6="-psn1 $DEPLOYMENT_POLICY_STORE_NAME -csn1 $DEPLOYMENT_CRYPTSTORE_NAME -csn2 $DEPLOYED_CRYPTSTORE_NAME"
ALLSIMARG7="-npcr $NUM_PCR -pcrs $PCRSTR -tpm $TPM_DEVICE -seal $SEAL_STORE -quote $QUOTE_STORE -quote_cert $QUOTE_CERT_FILE"
ALLSIMARG8="-end_cert $END_CERT_FILE -end_chain $END_CERT_CHAIN_FILE -act_host $ACTIVATE_HOST -act_port $ACTIVATE_PORT"
ALLSIMARG9="-sev-dev $SEV_DEVICE -sev-mfn $SEV_MEASUREMENT_FILE_NAME -vmm-type $VMM_TYPE -build-vm $BUILD_VM -tcb $TCB_VER -migrate $MIGRATE_VAL -smt $SMT_VAL"
ALLSIMARG10="-kernel-mfn $VM_KERNEL_FILE_NAME -initram-mfn $VM_INITRAM_FILE_NAME -vm-cmd-line $VM_COMMAND_LINE -ovmf-loc $OVMF_LOCATION"
ALLSIMARG11="-cpu-type $CPU_TYPE -n-cpus $NVCPUS -cpu-model $CPU_MODEL -cpu-stepping $CPU_STEPPING -cpu-family $CPU_FAMILY -cpu-features $CPU_FEATURES"

ALLARGS="$ALLSIMARG1 $ALLSIMARG2 $ALLSIMARG3 $ALLSIMARG4 $ALLSIMARG5 $ALLSIMARG6 $ALLSIMARG7 $ALLSIMARG8 $ALLSIMARG9 $ALLSIMARG10 $ALLSIMARG11"

# ----------------------------------------------------------------------------------------------------------------------------

echo ""
echo "Running consolidated test with $ALLARGS"
echo ""

if [[ ! -v CERTIFIER_ROOT ]] ; then
  echo "Warning CERTIFIER_ROOT not defined yet"
  pushd ../../..
    CERTIFIER_ROOT=$(pwd)
  popd
fi
if [[ ! -v EXAMPLE_DIR ]] ; then
    EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1
fi

if [[ $TEST_TYPE == "real" && $BUILD_VM -eq 1 ]]; then
  echo "WARNING: real sev test does not build a VM yet"
fi

echo ""
echo "certify-deployed-machine.sh"
./certify-deployed-machine.sh $TA		# working

echo ""

echo ""
echo "generate-and-store-secret-for-deployment.sh"
./generate-and-store-secret-for-deployment.sh $ALLARGS # working

echo ""
echo "obtain-application-secrets.sh"
./obtain-application-secrets.sh $ALLARGS	#working

echo ""
echo "VM consolidated test complete"
echo ""

# --------------------------------------------------------------------------------

