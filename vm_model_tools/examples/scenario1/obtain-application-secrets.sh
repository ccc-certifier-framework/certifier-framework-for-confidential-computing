#!/bin/bash

# ############################################################################
# obtain-application-secrets.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# This script uses cf_key_client to contact a key server and retrieve
# a secret previously stored.  Again, this happend over an http API mediated
# secure channel establised using certifier credentials.

# ----------------------------------------------------------------------------------

echo ""
echo "obtain-application-secrets.sh"
echo ""

echo "Processing arguments"
process-args
echo "Arguments processed"
if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

CLIENT_IN_FILE="./cf_data/client.in"
CLIENT_OUT_FILE="./cf_data/client.out"

echo ""
echo "Calling keyclient"
$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe \
    --policy_domain_name=$DOMAIN_NAME \
    --encrypted_cryptstore_filename=$DEPLOYED_CRYPTSTORE_NAME \
    --enclave_type=$DEPLOYED_ENCLAVE_TYPE \
    --policy_store_filename=$DEPLOYED_POLICY_STORE_NAME \
    --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
    --data_dir="$DATA_DIR" \
    --resource_name=key-client-test-key \
    --version=0 \
    --input_format=raw \
    --output_format=raw \
    --input_file=$CLIENT_IN_FILE \
    --output_file=$CLIENT_OUT_FILE \
    --action=retrieve \
    --key_server_url=$KEY_SERVER_ADDRESS \
    --key_server_port=$KEY_SERVER_PORT \
    --tpm_device="$TPM_DEVICE" \
    --seal_hierarchy_file_name="$SEAL_STORE" \
    --quote_hierarchy_file_name="$QUOTE_STORE"

sleep 3

echo "key retrieved"
echo ""

# --------------------------------------------------------------------------------

