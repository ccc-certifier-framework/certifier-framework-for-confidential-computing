#!/bin/bash

# ############################################################################
# certify deployment machine.sh 
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# This script calls the certifier service to certify the deployment
# environment.  In the case of the simulated enclave, the thing certified
# is cf_utility.exe.  If the deployment environment is an entire VM,
# it would certify a VM based on its measurement.  In all cases here,
# the client here generates a public private keypair (stored in the deployment
# policy store) called its authentication key pair .  A successful
# certification results in "Admissions certificate" which is stored in both
# the policy store and keystore.  Both the private key and the Admissions
# Certificate are used to open and authenticated secure channel to other
# certified environments in this security domain.

# -----------------------------------------------------------------------------------------------

function do-run() {
        echo " "
        echo "do-run"

        if [[ $DEPLOYMENT_ENCLAVE_TYPE != "simulated-enclave"  ]] ; then
                echo "Unsupported deployment enclave type: $DEPLOYMENT_ENCLAVE_TYPE"
                exit
        fi

        echo "Calling"
        echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
          --cf_utility_help=false \
          --init_trust=true \
          --print_cryptstore=true \
          --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE \
          --policy_domain_name=$DOMAIN_NAME \
          --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
          --policy_store_filename=$DEPLOYMENT_POLICY_STORE_NAME \
          --encrypted_cryptstore_filename=$DEPLOYMENT_CRYPTSTORE_NAME \
          --symmetric_key_algorithm=aes-256-gcm  \
          --public_key_algorithm=rsa-2048 \
          --data_dir="$EXAMPLE_DIR/" \
          --certifier_service_URL=$POLICY_SERVER_ADDRESS \
          --service_port=$POLICY_SERVER_PORT --print_level=1 \
          --trust_anchors=$EXAMPLE_DIR/cf_data/my_certs"
        echo " "

        echo "Program 1"
        $CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
          --cf_utility_help=false \
          --init_trust=true \
          --print_cryptstore=true \
          --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE  \
          --policy_domain_name=$DOMAIN_NAME \
          --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
          --policy_store_filename=$DEPLOYMENT_POLICY_STORE_NAME \
          --encrypted_cryptstore_filename=$DEPLOYMENT_CRYPTSTORE_NAME \
          --symmetric_key_algorithm=aes-256-gcm  \
	  --public_key_algorithm=rsa-2048 \
          --data_dir="$EXAMPLE_DIR/" \
          --certifier_service_URL=$POLICY_SERVER_ADDRESS \
          --service_port=$POLICY_SERVER_PORT --print_level=1
        echo " "

        sleep 3

        echo "Calling"
        echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
          --cf_utility_help=false \
          --init_trust=false \
          --generate_symmetric_key=true \
          --keyname=primary-store-encryption-key \
          --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE  \
          --policy_domain_name=$DOMAIN_NAME \
          --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
          --policy_store_filename=$DEPLOYMENT_POLICY_STORE_NAME \
          --encrypted_cryptstore_filename=$DEPLOYMENT_CRYPTSTORE_NAME \
          --symmetric_key_algorithm=aes-256-gcm  \
          --public_key_algorithm=rsa-2048 \
          --data_dir='$EXAMPLE_DIR/' \
          --certifier_service_URL=$POLICY_SERVER_ADDRESS \
          --service_port=$POLICY_SERVER_PORT --print_level=1"

        echo " "
        echo " Alternatively add \
        --trust_anchors=$CERTIFIER_ROOT/vm_model_tools/examples/scenario1/cf_data/my_certs"
        echo " "

        echo "Program 2"
        $CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
          --cf_utility_help=false \
          --init_trust=false \
          --generate_symmetric_key=true \
          --keyname=primary-store-encryption-key \
          --enclave_type=$DEPLOYMENT_ENCLAVE_TYPE \
          --policy_domain_name=$DOMAIN_NAME \
          --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
          --policy_store_filename=$DEPLOYMENT_POLICY_STORE_NAME \
          --encrypted_cryptstore_filename=$DEPLOYMENT_CRYPTSTORE_NAME \
          --symmetric_key_algorithm=aes-256-gcm  \
          --public_key_algorithm=rsa-2048 \
          --data_dir="$EXAMPLE_DIR/" \
          --certifier_service_URL=$POLICY_SERVER_ADDRESS \
          --service_port=$POLICY_SERVER_PORT --print_level=1 \
          --trust_anchors=$EXAMPLE_DIR/cf_data/my_certs
        echo ""
}

# ------------------------------------------------------------------------------

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

echo " "
echo "Certify me"

if [ $OPERATION  == "run" ] ; then
  do-run
fi

echo "Certification complete "
echo " "
