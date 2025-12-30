#!/bin/bash
# ############################################################################
# certify-deployed-machine.sh  Script to certify machine
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../../.. > /dev/null
  CERTIFIER_ROOT=$(pwd) > /dev/null
  popd
fi
EXAMPLE_DIR=$(pwd) > /dev/null

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [ $ARG_SIZE == 0 ] ; then
  exit
fi

if [[ $ARG_SIZE != 1 && $ARG_SIZE != 2 && $ARG_SIZE != 3  ]] ; then
  echo "Wrong number of arguments"
  echo "Must call, as follows:"
  exit
fi

if [[ $ARG_SIZE == 1 && $1 == "fresh" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE="none"
fi
if [[ $ARG_SIZE == 2  && $1 == "fresh" ]] ; then
  DOMAIN_NAME=$2
  ENCLAVE_TYPE="none"
fi

if [[ $ARG_SIZE == 2  && $1 == "run" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE=$2
fi
if [[ $ARG_SIZE == 3 && $1 == "run" ]] ; then
  DOMAIN_NAME=$3
  ENCLAVE_TYPE=$2
fi

echo "Domain name: $DOMAIN_NAME"
echo "Enclave type: $ENCLAVE_TYPE"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "Policy key file name: $POLICY_KEY_FILE_NAME"
echo "Policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
CRYPTSTORE_NAME="cryptstore.$DOMAIN_NAME"
echo "Policy store name: $POLICY_STORE_NAME"
echo "Cryptstore name: $CRYPTSTORE_NAME"


  pushd $EXAMPLE_DIR

    if [[ "$ENCLAVE_TYPE" == "se" ]] ; then

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
  .fi
