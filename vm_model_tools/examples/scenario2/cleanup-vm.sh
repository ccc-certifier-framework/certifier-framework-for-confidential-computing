#!/bin/bash

# ############################################################################
# cleanup-vm.sh
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

  if [[ $ENCLAVE_TYPE != "simulated-enclave" && $ENCLAVE_TYPE != "sev" ]] ; then
    echo "Unsupported enclave type: $ENCLAVE_TYPE"
    exit
  fi

  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  pushd $EXAMPLE_DIR/service
    if [[ "$ENCLAVE_TYPE" == "simulated-enclave" ]] ; then
      echo "running policy server for simulated-enclave"
      $CERTIFIER_ROOT/certifier_service/simpleserver \
        --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
        --policyFile=policy.bin --readPolicy=true &
    fi
    if [[ "$ENCLAVE_TYPE" == "sev" ]] ; then
      echo "running policy server for sev"
      $CERTIFIER_ROOT/certifier_service/simpleserver \
        --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
          --policyFile=sev_policy.bin --readPolicy=true &
    fi
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

    if [[ "$DEPLOYED_ENCLAVE_TYPE" == "sev-enclave" ]] ; then
      sudo ./sev-client-call.sh $DOMAIN_NAME $POLICY_CERT_FILE_NAME $POLICY_STORE_NAME $CRYPTSTORE_NAME "$EXAMPLE_DIR/"
    fi
  popd

  echo "do-run done"
}

# -----------------------------------------------------------------------------------------------------

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

if [[ $CLEAN -eq 1 ]] ; then
  do-fresh
fi

if [[ $TT -eq 0 ]]; then
        echo "Nothing to do in simulated environment"
fi
