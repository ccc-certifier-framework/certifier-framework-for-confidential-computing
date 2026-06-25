#!/bin/bash

# ############################################################################
# util-tests.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [[ ${CERTIFIER_ROOT+x} ]]; then
        echo "CERTIFIER_ROOT already set"
else
        echo "setting CERTIFIER_ROOT"
        pushd ../../.. > /dev/null
        CERTIFIER_ROOT=$(pwd) > /dev/null
        popd > /dev/null
fi

echo "setting EXAMPLE_DIR"
EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools > /dev/null
SRC_DIR=$EXAMPLE_DIR/src > /dev/null
TEST_DIR=$SRC_DIR/test > /dev/null

echo "Certifier directory: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"
echo "Source directory: $SRC_DIR"
echo "Test directory: $TEST_DIR"

exit

source ./util-arg-processing.inc

# This script builds the certifier utility and runs some tests.
# Throughout this example, $CERTIFIER_ROOT is the directory the certifier
# was cloned into.
# $EXAMPLE_DIR is the utility directory for the test,
#    $CERTIFIER_ROOT/vm_model_tools
#
# The utility call is:
# cf_utility.exe
#    --cf_utility_help=false
#    --init_trust=false
#    --reinit_trust=false
#    --generate_symmetric_key=false
#    --generate_public_key=false
#    --get_item=false
#    --put_item=false
#    --print_cryptstore=true
#
#    --enclave_type="sev-enclave"
#    --data_dir=./cf_data
#    --policy_domain_name=datica_file_share_1
#    --policy_key_file=policy_cert_file.policy_domain_name
#    --policy_store_filename=MUST-SPECIFY-IF-NEEDED
#    --encrypted_cryptstore_filename=MUST-SPECIFY
#    --keyname="store_encryption_key_1"
#    --symmetric_algorithm=aes-256-gcm
#    --public_key_algorithm=rsa_2048
#
#    --tag=MUST-SPECIFY-IF-NEEDED
#    --entry_version=MUST-SPECIFY-IF-NEEDED
#    --type=MUST-SPECIFY-IF-NEEDED
#
#    --certifier_service_URL=MUST-BE-SPECIFIED-IF-NEEDED
#    --service_port=port-for-certifier-service, MUST-BE-SPECIFIED-IF-NEEDED
#
#    --output_format=key-message-serialized-protobuf
#    --input_format=key-message-serialized-protobuf
#    --input_file=in_1
#    --output_file=out_1


