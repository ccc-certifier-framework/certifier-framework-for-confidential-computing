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

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then            
        print-variables 
fi

echo ""
echo "First pass"
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"
echo "Domain name: $DOMAIN_NAME"
echo "Enclave type: $DEPLOYED_ENCLAVE_TYPE"

REAL_TEST=1

# ------------------------------------------------------------------------------

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

# ------------------------------------------------------------------------------------

function run-first-pass() {
  echo " "
  echo "run-first-pass"

  if [[ $DEPLOYED_ENCLAVE_TYPE != "tpm-enclave" ]] ; then
    echo "Unsupported first pass enclave type"
  fi

  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/tpmlib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  sleep 3

  if [[ -v REAL_TEST ]] ; then
    pushd service
      echo ""
      echo "starting certifier for first pass"
      if [[ $VERBOSE -eq 1 ]]; then
        $CERTIFIER_ROOT/certifier_service/simpleserver  \
          --policy_key_file=$POLICY_KEY_FILE_NAME \
          --policy_cert_file=$POLICY_CERT_FILE_NAME \
          --trustedRootsFile="trustedRoots.bin" \
          --doActivate=true &
      else
        $CERTIFIER_ROOT/certifier_service/simpleserver  \
          --policy_key_file=$POLICY_KEY_FILE_NAME \
          --policy_cert_file=$POLICY_CERT_FILE_NAME \
          --trustedRootsFile="trustedRoots.bin" \
          --doActivate=true > certout0.txt &
      fi
      echo "certifier first pass started"
    popd
  fi

  echo ""

  $CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
    --data_dir=$DATA_DIR \
    --enclave_type=$DEPLOYED_ENCLAVE_TYPE \
    --policy_domain_name=$DOMAIN_NAME \
    --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
    --policy_store_filename=$POLICY_STORE_NAME \
    --run_first_pass=true \
    --tpm_device="$TPM_DEVICE" \
    --seal_hierarchy_file_name="$SEAL_STORE" \
    --quote_hierarchy_file_name="$QUOTE_STORE" \
    --quote_cert_file="$QUOTE_CERT_FILE" \
    --measurement_file="cf_utility.measurement" \
    --tpm_measurement_filename="$TPM_MEASUREMENT_FILE_NAME" \
    --endorsement_cert_chain_file=$END_CERT_CHAIN_FILE \
    --endorsement_cert_file_name="" \
    --generate_symmetric_key=true \
    --keyname=primary-store-encryption-key \
    --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
    --symmetric_key_algorithm=$SYMMETRIC_ENCRYPTION_ALGORITHM \
    --public_key_algorithm=$ASYMMETRIC_ENCRYPTION_ALGORITHM \
    --certifier_service_URL=$POLICY_SERVER_ADDRESS \
    --service_port=$POLICY_SERVER_PORT --print_level=1

  echo "got quote cert"
  echo ""

  echo "copy measurement"
  echo ""
  cp $TPM_MEASUREMENT_FILE_NAME provisioning
  chmod 0777 provisioning $TPM_MEASUREMENT_FILE_NAME provisioning/$TPM_MEASUREMENT_FILE_NAME

  echo ""
  echo "first pass done"

  cleanup-stale-procs
}

echo "Processing arguments"
process-args
echo ""

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

echo ""
run-first-pass
echo ""
echo "done"

# --------------------------------------------------------------------------------

