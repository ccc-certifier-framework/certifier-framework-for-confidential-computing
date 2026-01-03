#!/bin/bash

# ############################################################################
# certify-deployed-machine.sh  Script to certify machine
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
echo "Running"
echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
        --cf_utility_help=false \
        --init_trust=true \
        --print_cryptstore=true \
        --enclave_type=$DEPLOYED_ENCLAVE_TYPE \
        --policy_domain_name=$DOMAIN_NAME \
        --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
        --policy_store_filename=$POLICY_STORE_NAME \
        --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
        --symmetric_key_algorithm=aes-256-gcm  \
        --public_key_algorithm=rsa-2048 \
        --data_dir="$EXAMPLE_DIR/" \
        --certifier_service_URL=$POLICY_SERVER_ADDRESS \
        --service_port=$POLICY_SERVER_PORT " --print_level=1 \
	--trust_anchors=$EXAMPLE_DIR/cf_data/my_certs
echo " "

$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
        --cf_utility_help=false \
        --init_trust=true \
        --print_cryptstore=true \
        --enclave_type=$DEPLOYED_ENCLAVE_TYPE \
        --policy_domain_name=$DOMAIN_NAME \
        --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
        --policy_store_filename=$DEPLOYED_POLICY_STORE_NAME \
        --encrypted_cryptstore_filename=$DEPLOYED_CRYPTSTORE_NAME \
        --symmetric_key_algorithm=aes-256-gcm  \
        --public_key_algorithm=rsa-2048 \
        --data_dir="$EXAMPLE_DIR/" \
        --certifier_service_URL=$POLICY_SERVER_ADDRESS \
        --service_port=8123 --print_level=1

sleep 3

echo " "
echo "Running"
echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
        --cf_utility_help=false \
        --init_trust=false \
        --generate_symmetric_key=true \
	--keyname=primary-store-encryption-key \
        --enclave_type=$DEPLOYED_ENCLAVE_TYPE \
        --policy_domain_name=$DOMAIN_NAME \
        --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
        --policy_store_filename=$POLICY_STORE_NAME \
        --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
        --symmetric_key_algorithm=aes-256-gcm  \
        --public_key_algorithm=rsa-2048 \
        --data_dir="$EXAMPLE_DIR/" \
        --certifier_service_URL=$POLICY_SERVER_ADDRESS \
        --service_port=$POLICY_SERVER_PORT --print_level=1"
echo " "
echo " Alternatively add \
	--trust_anchors=$EXAMPLE_DIR/cf_data/my_certs"
echo " "

echo " "
echo "deployed machine certified"
