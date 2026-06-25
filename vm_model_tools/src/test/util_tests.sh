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

echo "Processing arguments"
process-args
echo "Arguments processed"

function compile-certifier-utilities() {
  pushd $CERTIFIER_ROOT/utilities
    if [[ $CLEAN -eq 1 ]] ; then
        pushd $CERTIFIER_ROOT/utilities
        make clean -f cert_utility.mak
        make clean -f policy_utilities.mak
    fi
    make -f cert_utility.mak
    make -f policy_utilities.mak
  popd
}

function compile-certifier() {
  pushd $CERTIFIER_ROOT/certifier_service/certprotos
    if [[ ! -e "./certifier.proto.go" ]] ; then
      echo " "
      echo "making protobufs"
      protoc --go_opt=paths=source_relative --go_out=. --go_opt=M=certifier.proto ./certifier.proto
    fi
  popd

  pushd $CERTIFIER_ROOT/certifier_service
    pushd graminelib
      make dummy
    popd
    pushd oelib
      make dummy
    popd
      pushd isletlib
      make dummy
    popd
    pushd teelib
      make
    popd
    pushd tpmlib
      make
    popd

    go build simpleserver.go
  popd
}

function compile-program() {
  pushd $SRC_DIR
    if [[ $CLEAN -eq 1 ]] ; then
      make clean -f cf_utility.mak
    fi
    make -f cf_utility.mak
  popd
}

function make-directories() {
  pushd $TEST_DIR
    if [[ ! -e "$TEST_DIR/provisioning" ]] ; then
       mkdir $TEST_DIR/provisioning
    fi
    if [[ ! -e "$TEST_DIR/service" ]] ; then
       mkdir $TEST_DIR/service
    fi
    if [[ ! -e "$TEST_DIR/cf_data" ]] ; then
       mkdir $TEST_DIR/cf_data
    fi
  popd
}

function provision-keys() {
  echo "provision-keys"
  make-directories
  pushd $TEST_DIR/provisioning
    $CERTIFIER_ROOT/utilities/cert_utility.exe  \
      --operation=generate-policy-key-and-test-keys  \
      --domain_name=$DOMAIN_NAME \
      --policy_key_output_file=$POLICY_KEY_FILE_NAME  \
      --policy_cert_output_file=$POLICY_CERT_FILE_NAME \
      --platform_key_output_file=platform_key_file.bin  \
      --attest_key_output_file=attest_key_file.bin
  popd
}

function cleanup-stale-procs() {
  echo " "
  echo "cleanup-stale-procs"

  # Find and kill simpleserver processes that may be running.
  echo " "
  set +e
  certifier_pid=$(ps -ef | grep -E "simpleserver" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  if [[ $certifier_pid != "" ]] ; then
    kill -9 $certifier_pid
    echo "killed certifier_service, pid $certifier_pid"
  else
    echo "no certifier_service running"
  fi

  echo "cleanup-stale-procs done"
}

function certify-programs() {
  echo "certify-programs"
}

function run-tests() {
  echo "run tests"
}

if [[ $VERBOSE -eq 1 ]]; then
  print-variables
fi
if [[ $COMPILE_UTIL -eq 1 ]]; then
  compile-certifier-utilities
fi
if [[ $COMPILE_PROGRAM -eq 1 ]]; then
  compile-program
fi
if [[ $PROVISION_KEYS -eq 1 ]]; then
  provision-keys
fi
if [[ $RUN_TEST -eq 1 ]]; then
  run-tests
fi

