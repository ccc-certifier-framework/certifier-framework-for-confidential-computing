#!/bin/bash

# ############################################################################
# obtain-application-secrets.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------


echo "Processing arguments"
process-args
echo "Arguments processed"

CLIENT_IN_FILE="./cf_data/client.in"
CLIENT_OUT_FILE="./cf_data/client.out"

echo ""
echo "Calling keyclient"
$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=$DOMAIN_NAME \
    --encrypted_cryptstore_filename=$DEPLOYED_CRYPTSTORE_NAME \
    --print_level=5 \
    --enclave_type=$DEPLOYED_ENCLAVE_TYPE \
    --policy_store_filename=$DEPLOYED_POLICY_STORE_NAME \
    --policy_key_cert_file=$POLICY_CERT_FILE_NAME --data_dir="./" \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=$CLIENT_IN_FILE --output_file=$CLIENT_OUT_FILE --action=retrieve \
    --key_server_url=$KEY_SERVER_ADDRESS --key_server_port=$KEY_SERVER_PORT

sleep 3

echo "key retrieved"
echo ""
