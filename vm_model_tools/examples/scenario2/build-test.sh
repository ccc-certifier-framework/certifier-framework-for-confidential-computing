#!/bin/bash

# ############################################################################
# build-test.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------


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

function do-run() {
  echo " "
  echo "do-run"

  if [[ $DEPLOYMENT_ENCLAVE_TYPE != "simulated-enclave" ]]; then
    echo "Unsupported deployment enclave type: $DEPLOYMENT_ENCLAVE_TYPE"
    exit
  fi
  if [[ $DEPLOYED_ENCLAVE_TYPE != "simulated-enclave" && $DEPLOYED_ENCLAVE_TYPE != "sev-enclave" ]] ; then
    echo "Unsupported deployed enclave type: $DEPLOYED_ENCLAVE_TYPE"
    exit
  fi

  cleanup_stale_procs

  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  pushd $EXAMPLE_DIR/service
  $CERTIFIER_ROOT/certifier_service/simpleserver \
        --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
        --policyFile=$POLICY_FILE_NAME --readPolicy=true &
  popd

  sleep 3

  pushd $EXAMPLE_DIR

    if [[ "$ENCLAVE_TYPE" == "simulated-enclave" ]] ; then

      echo " "
      echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
        --cf_utility_help=false \
        --init_trust=true \
        --print_cryptstore=true \
        --enclave_type="simulated-enclave" \
        --policy_domain_name=$DOMAIN_NAME \
        --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
        --policy_store_filename=$POLICY_STORE_NAME \
        --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
        --symmetric_key_algorithm=aes-256-gcm  \
        --public_key_algorithm=rsa-2048 \
        --data_dir="$EXAMPLE_DIR/" \
        --certifier_service_URL=localhost \
        --service_port=8123" --print_level=1 \
	--trust_anchors=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1/cf_data/my_certs
      echo " "


      $CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
        --cf_utility_help=false \
        --init_trust=true \
        --print_cryptstore=true \
        --enclave_type="simulated-enclave" \
        --policy_domain_name=$DOMAIN_NAME \
        --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
        --policy_store_filename=$POLICY_STORE_NAME \
        --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
        --symmetric_key_algorithm=aes-256-gcm  \
        --public_key_algorithm=rsa-2048 \
        --data_dir="$EXAMPLE_DIR/" \
        --certifier_service_URL=localhost \
        --service_port=8123 --print_level=1

      sleep 3

      echo " "
      echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
        --cf_utility_help=false \
        --init_trust=false \
        --generate_symmetric_key=true \
	--keyname=primary-store-encryption-key \
        --enclave_type="simulated-enclave" \
        --policy_domain_name=$DOMAIN_NAME \
        --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
        --policy_store_filename=$POLICY_STORE_NAME \
        --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
        --symmetric_key_algorithm=aes-256-gcm  \
        --public_key_algorithm=rsa-2048 \
        --data_dir="$EXAMPLE_DIR/" \
        --certifier_service_URL=localhost \
        --service_port=8123" --print_level=1
      echo " "
      echo " Alternatively add \
	--trust_anchors=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1/cf_data/my_certs"
      echo " "

      $CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
        --cf_utility_help=false \
        --init_trust=false \
        --generate_symmetric_key=true \
	--keyname=primary-store-encryption-key \
        --enclave_type="simulated-enclave" \
        --policy_domain_name=$DOMAIN_NAME \
        --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
        --policy_store_filename=$POLICY_STORE_NAME \
        --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
        --symmetric_key_algorithm=aes-256-gcm  \
        --public_key_algorithm=rsa-2048 \
        --data_dir="$EXAMPLE_DIR/" \
        --certifier_service_URL=localhost \
        --service_port=8123 --print_level=1 \
	--trust_anchors=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1/cf_data/my_certs
    fi

    This next call must be made as root.
    if [[ "$ENCLAVE_TYPE" == "sev-enclave" ]] ; then
      sudo ./sev-client-call.sh $DOMAIN_NAME $POLICY_CERT_FILE_NAME $POLICY_STORE_NAME $CRYPTSTORE_NAME "$EXAMPLE_DIR/"
    fi
  popd

  cleanup_stale_procs

  echo "do-run done"
}

# ---------------------------------------------------------------------------------

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then                   
        print-variables 
fi
if [ $CLEAN -eq 1 ] ; then
  exit
fi

echo "This was done in build-certifier.sh in step 0"
echo " "
