#!/bin/bash

# ############################################################################
# run-deployment-keyserver.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------


echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

echo " "
echo "running key-server"
echo " "
echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_key_server.exe --policy_domain_name=$DOMAIN_NAME \
    --encrypted_cryptstore_filename=$DEPLOYMENT_CRYPTSTORE_NAME \
    --print_level=5 --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE 
    --policy_store_filename=$DEPLOYMENT_POLICY_STORE_NAME \
    --key_server_url=$KEY_SERVER_ADDRESS --key_server_port=$KEY_SERVER_PORT \
    --policy_key_cert_file=$POLICY_CERT_FILE_NAME --data_dir=./ &"

$CERTIFIER_ROOT/vm_model_tools/src/cf_key_server.exe --policy_domain_name=$DOMAIN_NAME \
    --encrypted_cryptstore_filename=$DEPLOYMENT_CRYPTSTORE_NAME \
    --print_level=5 \
    --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE \
    --policy_store_filename=$DEPLOYMENT_POLICY_STORE_NAME \
    --key_server_url=$KEY_SERVER_ADDRESS --key_server_port=$KEY_SERVER_PORT \
    --policy_key_cert_file=$POLICY_CERT_FILE_NAME --data_dir=./ &

sleep 5
echo "keyserver running"
echo ""
