#!/bin/bash

# ############################################################################
# generate-and-store-secret-for-deployment.sh
# This can only be run after the certification
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------

echo ""
echo "generate-and-store-secret staring"
echo ""

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

CLIENT_IN_FILE="./cf_data/client.in"
CLIENT_OUT_FILE="./cf_data/client.out"

echo " "
echo "key-client: storing new value"
echo "01234567890123456789012345678901" > $CLIENT_IN_FILE
echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=$DOMAIN_NAME \
    --encrypted_cryptstore_filename=$DEPLOYMENT_CRYPTSTORE_NAME \
    --print_level=5 \
    --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE \
    --policy_store_filename=$DEPLOYMENT_POLICY_STORE_NAME \
    --policy_key_cert_file=$POLICY_CERT_FILE_NAME --data_dir=./  \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=$CLIENT_IN_FILE --output_file=$CLIENT_OUT_FILE --action=store"

$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=$DOMAIN_NAME \
    --encrypted_cryptstore_filename=$DEPLOYMENT_CRYPTSTORE_NAME \
    --print_level=5 \
    --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE \
    --policy_store_filename=$DEPLOYMENT_POLICY_STORE_NAME \
    --policy_key_cert_file=$POLICY_CERT_FILE_NAME --data_dir="./"  \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=$CLIENT_IN_FILE --output_file=$CLIENT_OUT_FILE --action=store

echo " "
echo "key-client: retrieving"
echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=$DOMAIN_NAME \
    --encrypted_cryptstore_filename=$DEPLOYMENT_CRYPTSTORE_NAME \
    --print_level=5 \
    --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE \
    --policy_store_filename=$DEPLOYMENT_POLICY_STORE_NAME \
    --policy_key_cert_file=$POLICY_CERT_FILE_NAME --data_dir=./  \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=$CLIENT_IN_FILE --output_file=$CLIENT_OUT_FILE --action=retrieve"
$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=$DOMAIN_NAME \
    --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
    --print_level=5 \
    --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE \
    --policy_store_filename=$DEPLOYMENT_POLICY_STORE_NAME \
    --policy_key_cert_file=$POLICY_CERT_FILE_NAME --data_dir=./ \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=$CLIENT_IN_FILE --output_file=$CLIENT_OUT_FILE --action=retrieve

echo "generate-and-store-secret succeeded"
echo ""
