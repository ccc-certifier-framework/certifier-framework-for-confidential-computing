#!/bin/bash

# ############################################################################
# run-test-scenario1.sh: Run entire scenario 1 test
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# This script calls a number of subordinate scripts to build the certifier, utilities
# and vm_model_tools and applications as well as the simulated-enclave and sev
# simulator.  It then generates keys and policy to run the "scenario1" example,
# which distributes symmetric keys from a deployment environment to a deployed
# environment.  It is a "one step" end-to-end test for scenario1.
#
# Throughout this example, $CERTIFIER_ROOT is the directory the certifier was cloned into,
# ~/src/github.com/ccc-certifier-framework/certifier-framework-for-confidential-computing in
# this case.
# $EXAMPLE_DIR is the application directory for the test,
#    $CERTIFIER_ROOT/vm_model_tools/examples/scenario1 in this case.
#
# This script and the subscripts it calls employ a number of parameters that affect the
# processing, for example, specifying the deployment and deployed enclave and
# environments.  The arguments are set below and the file "./arg-processing.inc"
# processes the arguments fot this script and all the subscripts.   Each subscript
# corresponds to a well encapsulated step of the "Certifier Tao."
#
# For out example,
# 	$EXAMPLE_DIR will contain the policy and cryptstore for the deployment and
# 	deployed environment.
# 	The $EXAMPLE_DIR/provisioning directory contains all the files generated for
# 	the test.
# 	The $EXAMPLE_DIR/service directory contains all the files required for
# 	the certifier sevice.
# 	The $EXAMPLE_DIR/cf_data directory contains all the application data for
# 	the application.

# -----------------------------------------------------------------------------------

function do-fresh() {
  echo " "
  echo "do-fresh"

  pushd $EXAMPLE_DIR
    if [[ -e "$POLICY_STORE_NAME" ]] ; then
      rm $POLICY_STORE_NAME
    fi
    if [[ -e "$CRYPTSTORE_NAME" ]] ; then
      rm $CRYPTSTORE_NAME
    fi
  popd

  echo "Done"
  exit
}

function do-run-simulated() {
	echo " "
	echo " "
}

function do-run-real() {
	echo " "
	echo "TODO"
	echo " "
}

echo "Processing arguments"
process-args
echo "Arguments processed"

ALLARGS=""
if [[ $TEST_TYPE = "simulated" ]]; then
	ALLSIMARG1="-tt simulated -pn scenario1-test -dn dom0"
	ALLSIMARG2="-clean 1 -loud 1 -dd ./ -ccf $COMPILE_CF -bss $BUILD_SEV_SIMULATOR"
	ALLSIMARG3="-pkn policy_key_file -cfn policy_cert_file -psn policy_store -csn cryptstore"
	ALLSIMARG4="-pfn policy.bin -psa POLICY_SERVER_ADDRESS -ksa $KEY_SERVER_ADDRESS"
	ALLSIMARG5="-vmn pauls_vm -et1 $DEPLOYMENT_ENCLAVE_TYPE -et2 $DEPLOYED_ENCLAVE_TYPE"
	ALLSIMARG6="-psn1 $DEPLOYMENT_POLICY_STORE_NAME -csn1 $DEPLOYMENT_CRYPTSTORE_NAME -csn2 $DEPLOYED_CRYPTSTORE_NAME"
	ALLSIMARG7="-npcr $NUM_PCR -pcrs $PCRSTR -tpm $TPM_DEVICE -seal $SEAL_STORE -quote $QUOTE_STORE -quote_cert $QUOTE_CERT_FILE"
	ALLSIMARG8="-end_cert $END_CERT_FILE -end_chain $END_CERT_CHAIN_FILE -act_host $ACTIVATE_HOST -act_port $ACTIVATE_PORT"

	ALLARGS="$ALLSIMARG1 $ALLSIMARG2 $ALLSIMARG3 $ALLSIMARG4 $ALLSIMARG5 $ALLSIMARG6 $ALLSIMARG7 $ALLSIMARG8"
else
	echo "\"real\" sev test not working yet"
	exit
fi

echo ""
echo "Running consolidated test with $ALLARGS"
echo ""

if [[ $COMPILE_CF -eq 1 ]]; then
	echo ""
	echo "build-certifier.sh"
	echo ""
	./build-certifier.sh $ALLARGS		# working
fi

echo ""
echo "build-sev-sim.sh"
./build-sev-sim.sh $ALLARGS			# working
if [[ $PROVISION_KEYS -eq 1 ]]; then
	echo ""
	echo "provision-keys.sh"
	echo ""
	./provision-keys.sh $ALLARGS		# working
fi

echo ""
echo "build-vm.sh"
./build-vm.sh $ALLARGS				# working

TA="$ALLARGS -op measure"

echo ""
echo "measure-programs.sh"
echo ""
./measure-programs.sh $TA			# working

echo ""
echo "measure-vm-programs.sh"
./measure-vm-programs.sh $TA			# working

if [[ $DEPLOYED_ENCLAVE_TYPE == "tpm-enclave" ]]; then
  echo "tpm enclave"
  # ../../../tpm2_set_pcrs.exe --pcr_num=7 --num_pcrs=1 --tpm_device=/dev/tpmrm1
  # ./build-activation-policy.sh $ALLARGS
  # ./run-first-pass.sh $ALLARGS
  # cp measurement ./provisioning
  # cp $QUOTE_CERT_FILE ./provisioning
fi

echo ""
echo "build-policy.sh"
./build-policy.sh $ALLARGS			# working

echo ""
echo "copy-files.sh"
./copy-files.sh $ALLARGS			# working

echo ""
echo "copy-vm-files.sh"
./copy-vm-files.sh $ALLARGS			# working

echo ""
echo "run-policy-server.sh"
./run-policy-server.sh $ALLARGS			# working

echo ""
echo "certify-deployment-machine.sh"
TA="$ALLARGS -op run"
./certify-deployment-machine.sh $TA		# working
# The following command is actually redundant in the simulated
#   environment

echo ""
echo "certify-deployed-machine.sh"
./certify-deployed-machine.sh $TA		# working

echo ""
echo "run-deployment-keyserver.sh"
./run-deployment-keyserver.sh $ALLARGS         	# working

echo ""
echo "generate-and-store-secret-for-deployment.sh"
./generate-and-store-secret-for-deployment.sh $ALLARGS # working

echo ""
echo "obtain-application-secrets.sh"
./obtain-application-secrets.sh $ALLARGS	#working

echo ""
echo "cleanup.sh"
./cleanup.sh $ALLARGS				# working

echo ""
echo "Consolidated test complete"
echo ""
