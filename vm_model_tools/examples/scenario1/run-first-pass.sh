#!/bin/bash

# ############################################################################
# run-first-pass.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# This script runs the certifier service using the policy generated earlier
# (in the service directory).  It runs as an http service and waits for
# requests.

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../../..
  CERTIFIER_ROOT=$(pwd)
  popd
fi
EXAMPLE_DIR=$(pwd)

NO_COMPILE_UTILITIES=1

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [[ $ARG_SIZE == 0 ]] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./first-pass.sh domain_name"
  exit
fi

DOMAIN_NAME=$1
REAL_TEST=1
echo "domain name: $DOMAIN_NAME"


# ------------------------------------------------------------------------------------------


function cleanup-stale-procs() {
  echo " "
  echo "cleanup-stale-procs"

  # Find and kill simpleserver processes that may be running.
  echo " "
  set +e
  certifier_pid=$(ps -ef | grep -E "simpleserver" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  if [[ $certifier_pid != "" ]] ; then
    kill -9 $certifier_pid
    echo "killed certifier_service, pid $certifier_pid"
  else
    echo "no certifier_service running"
  fi

  echo "cleanup-stale-procs done"
}

function do-get-quote-cert-and-measurement() {
  echo " "
  echo "do-get-quote-cert-and-measurement"

  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  sleep 5

  pushd $EXAMPLE_DIR
  echo " "
  echo "first pass"

  pushd service
    echo ""
    echo "starting certifier for first pass"
    $CERTIFIER_ROOT/certifier_service/simpleserver  \
      --policy_key_file=$POLICY_KEY_FILE_NAME \
      --policy_cert_file=$POLICY_CERT_FILE_NAME \
      --trustedRootsFile="trustedRoots.bin" \
      --doActivate=true &
    echo "certifier first pass started"
    echo ""
  popd


  echo ""
  echo "getting quote cert"
  $EXAMPLE_DIR/cf_utility.exe --data_dir=./app1_data/  \
        --run-firts-pass=true \
        --domain_name=$DOMAIN_NAME \
        --tpm_device="/dev/tpmrm1" \
        --seal_hierarchy_file_name="seal_hierarchy.bin" \
        --quote_hierarchy_file_name="quote_hierarchy.bin" \
        --quote_cert_file="./provisioning/quote_cert.crt" \
        --measurement_file="./provisioning/measurement" \
        --endorsement_cert_chain_file="" \
        --endorsement_cert_file_name="" \
        --policy_store_file=$POLICY_STORE_NAME --print_all=true
  echo "got quote cert"
  echo ""

  echo ""
  echo "first pass done"

  cleanup-stale-procs
}


# ------------------------------------------------------------------------------------------

function run-first-pass() {
	echo " "
	echo "run-first-pass"

	if [[ $DEPLOYMENT_ENCLAVE_TYPE != "tpm-enclave" ]] ; then
		echo "Unsupported first pass enclave type"
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
