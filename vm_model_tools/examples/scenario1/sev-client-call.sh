#!/bin/bash
# ############################################################################
# sev-client-call.sh: Script to run client cf_utility for sev as root.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

ARG_SIZE="$#"

if [ $ARG_SIZE != 5 ] ; then
  echo "This should only be called by run-test.sh and it has the wrong number of args"
fi

CERTIFIER_ROOT=../../..
EXAMPLE_DIR=.
echo "New root: $CERTIFIER_ROOT"
echo "New example: $EXAMPLE_DIR"
echo "Domain name: $1"
echo "Cert file name: $2"
echo "policy store name: $3"
echo "cryptstore name: $4"

$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
  --cf_utility_help=false \
  --init_trust=true \
  --print_cryptstore=true \
  --enclave_type="sev-enclave" \
  --policy_domain_name=$1 \
  --policy_key_cert_file=$2 \
  --policy_store_filename=$3 \
  --encrypted_cryptstore_filename=$4 \
  --symmetric_key_algorithm=aes-256-gcm  \
  --public_key_algorithm=rsa-2048 \
  --data_dir=$5 \
  --certifier_service_URL=localhost \
  --service_port=8123

sleep 3

$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
    --cf_utility_help=false \
    --init_trust=false \
    --generate_symmetric_key=true \
    --enclave_type="sev-enclave" \
    --policy_domain_name=$1 \
    --policy_key_cert_file=$2 \
    --policy_store_filename=$3 \
    --encrypted_cryptstore_filename=$4 \
    --symmetric_key_algorithm=aes-256-gcm  \
    --public_key_algorithm=rsa-2048 \
    --data_dir=$5 \
    --certifier_service_URL=localhost \
    --service_port=8123
exit
