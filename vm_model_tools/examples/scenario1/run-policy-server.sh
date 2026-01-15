#!/bin/bash

# ############################################################################
# run-policy-server.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------


function run-policy-server() {
	echo " "
	echo "run-policy-server"

	if [[ $DEPLOYMENT_ENCLAVE_TYPE != "simulated-enclave" && $DEPLOYED_ENCLAVE_TYPE != "sev-enclave" ]] ; then
		echo "Unsupported enclave type: $DEPLOYED_ENCLAVE_TYPE"
	fi

	export LD_LIBRARY_PATH=/usr/local/lib
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
	export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
	echo $LD_LIBRARY_PATH
	sudo ldconfig

	pushd $EXAMPLE_DIR/service
	if [[ "$DEPLOYMENT_ENCLAVE_TYPE" == "simulated-enclave" ]] ; then
		echo "running policy server for simulated-enclave"
		$CERTIFIER_ROOT/certifier_service/simpleserver \
		  --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
		  --policyFile=policy.bin --readPolicy=true &
	fi
	if [[ "$DEPLOYED_ENCLAVE_TYPE" == "sev-enclave" ]] ; then
		echo "running policy server for sev"
		$CERTIFIER_ROOT/certifier_service/simpleserver \
		  --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
		  --policyFile=sev_policy.bin --readPolicy=true &
	
	fi
	popd

	sleep 3
}

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

echo ""
echo "running policy server"
echo ""
run-policy-server
echo ""
echo "policy server running"
echo ""
