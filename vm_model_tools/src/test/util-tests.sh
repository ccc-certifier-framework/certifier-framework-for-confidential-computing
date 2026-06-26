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
  echo " "
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
  set +e

  certifier_pid=$(ps -ef | grep -E "simpleserver" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  if [[ $certifier_pid != "" ]] ; then
    kill -9 $certifier_pid
    echo "killed certifier_service, pid $certifier_pid"
  else
    echo "no certifier_service running"
  fi
}

function clear-keys() {
  echo " "
  echo "clear-keys"
  pushd $TEST_DIR
    if [[ ! -e "./provisioning" ]] ; then
      rm ./provisioning/* || true
    fi
  popd
}

function clean-run-time-files() {
  echo " "
  echo "clean-runtime-files"
  pushd $TEST_DIR
    rm $POLICY_STORE_NAME $CRYPTSTORE_NAME || true
    if [[ ! -e "./service" ]] ; then
      rm ./service/* || true
    fi
    if [[ ! -e "./cf_data" ]] ; then
      rm ./cf_data/* || true
    fi
  popd
}

function copy-files() {
  echo " "
  echo "copy-files"

  pushd $TEST_DIR
    if [[ ! -e "./provisioning" ]] ; then
            mkdir ./provisioning
    fi
    if [[ ! -e "./service" ]] ; then
            mkdir ./service
    fi
    if [[ ! -e "./cf_data" ]] ; then
            mkdir ./cf_data
    fi

    pushd provisioning
      cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin ../service
      cp -p $POLICY_CERT_FILE_NAME ../cf_data

      if [[ -f cf_utility.measurement ]]; then
          cp -p cf_utility.measurement ../cf_data
      fi
      if [[ -f platform_attest_endorsement.bin ]]; then
          cp -p platform_key_file.bin attest_key_file.bin \
                platform_attest_endorsement.bin ../cf_data
      fi

      $CERTIFIER_ROOT/utilities/combine_policy_certs.exe \
          --init=true \
          --new_cert_file=$POLICY_CERT_FILE_NAME \
          --output=../my_certs
    popd
  popd
}

function build-policy() {
  echo " "
  echo "build-policy"
  make-directories

  COMBINED_STATEMENTS=""

  pushd $TEST_DIR/provisioning 

    if [[ $ENCLAVE_TYPE = "simulated-enclave" ]]; then
      $CERTIFIER_ROOT/utilities/measurement_utility.exe \
        --type=hash \
        --input=$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
        --output=cf_utility.measurement
  
      $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
        --key_subject="platform_key_file.bin" \
        --verb="is-trusted-for-attestation" \
        --output=ts1.bin

      $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
        --key_subject=$POLICY_KEY_FILE_NAME \
        --verb="says" \
        --clause=ts1.bin \
        --output=vse_policy1.bin

      $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
        --vse_file=vse_policy1.bin \
        --duration=9000 \
        --private_key_file=$POLICY_KEY_FILE_NAME \
        --output=signed_claim_1.bin

      $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
        --measurement_subject="cf_utility.measurement" \
        --verb="is-trusted" \
        --output=ts2.bin

      $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
        --key_subject=$POLICY_KEY_FILE_NAME \
        --verb="says" \
        --clause=ts2.bin \
        --output=vse_policy2.bin

      $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
        --vse_file=vse_policy2.bin  \
        --duration=9000  \
        --private_key_file=$POLICY_KEY_FILE_NAME \
        --output=signed_claim_2.bin

      $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
        --key_subject=attest_key_file.bin \
        --verb="is-trusted-for-attestation" \
        --output=tsc1.bin

      $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
        --key_subject=platform_key_file.bin \
        --verb="says" \
        --clause=tsc1.bin \
        --output=vse_policy3.bin

      $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
        --vse_file=vse_policy3.bin \
        --duration=9000 \
        --private_key_file=platform_key_file.bin \
        --output=platform_attest_endorsement.bin

      COMBINED_STATEMENTS="signed_claim_1.bin,signed_claim_2.bin"
    fi

    if [[ $ENCLAVE_TYPE = "tpm-enclave" ]]; then

      $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
         --config="$PCRSTR" \
         --key_subject="" \
         --measurement_subject=tpm_cf_utility.measurement \
         --verb="is-trusted" \
          --output=tpm_ts2.bin

      $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
          --key_subject=$POLICY_KEY_FILE_NAME \
          --verb="says" \
          --clause=tpm_ts2.bin \
          --output=tpm_vse_policy2.bin


      $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
          --vse_file=tpm_vse_policy2.bin \
          --duration=9000 \
          --private_key_file=$POLICY_KEY_FILE_NAME \
          --output=tpm_signed_claim_2.bin

      COMBINED_STATEMENTS="$COMBINED_STATEMENTS,tpm_signed_claim_2.bin"
    fi

    $CERTIFIER_ROOT/utilities/package_claims.exe \
      --input=$COMBINED_STATEMENTS \
      --output=$POLICY_FILE_NAME


    echo ""
    echo "Final policy"
    echo ""
    $CERTIFIER_ROOT/utilities/print_packaged_claims.exe \
      --input=$POLICY_FILE_NAME
    echo ""
  popd
}

function run-policy-server() {
  echo " "
  echo "run-policy-server"

  if [[ $ENCLAVE_TYPE == "simulated-enclave" ]] ; then

   export LD_LIBRARY_PATH=/usr/local/lib
   export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
   export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
   export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
   export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
   export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/tpmlib
   echo $LD_LIBRARY_PATH
   sudo ldconfig

   pushd $TEST_DIR/service
     if [[ $VERBOSE -eq 1 ]]; then
       if [[ "$ENCLAVE_TYPE" == "simulated-enclave" ]] ; then
         echo "running policy server for simulated-enclave"
         $CERTIFIER_ROOT/certifier_service/simpleserver \
              --policy_key_file=$POLICY_KEY_FILE_NAME \
              --policy_cert_file=$POLICY_CERT_FILE_NAME \
              --policyFile=$POLICY_FILE_NAME \
              --readPolicy=true &
          fi
      fi
    popd
    sleep 3
  fi
}

function certify-programs() {
  echo " "
  echo "certify-programs"
  make-directories

  pushd $TEST_DIR

    $CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
        --cf_utility_help=false \
        --init_trust=true \
        --print_cryptstore=true \
        --enclave_type=$ENCLAVE_TYPE \
        --policy_domain_name=$DOMAIN_NAME \
        --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
        --policy_store_filename=$POLICY_STORE_NAME \
        --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
        --symmetric_key_algorithm=aes-256-gcm  \
        --public_key_algorithm=rsa-2048 \
        --data_dir="$TEST_DIR/" \
        --certifier_service_URL=$POLICY_SERVER_ADDRESS \
        --service_port=8123 --print_level=1 \
  popd
}

function run-tests() {
  echo " "
  echo "run tests"

  pushd $TEST_DIR
    if [[ $RECERTIFY -eq 1 ]]; then
       clean-run-time-files
       build-policy
       copy-files
       run-policy-server
       certify-programs
    fi

    # Check help
    $SRC_DIR/cf_utility.exe --cf_utility_help=true

    # make symmetric key as protobuf and store it
    $SRC_DIR/cf_utility.exe \
      --cf_utility_help=false \
      --init_trust=false \
      --reinit_trust=false \
      --generate_symmetric_key=true \
      --generate_public_key=false \
      --get_item=false \
      --put_item=false \
      --print_cryptstore=true \
      --enclave_type="simulated-enclave" \
      --data_dir=$DATA_DIR \
      --policy_domain_name=$DOMAIN_NAME \
      --policy_key_cert_file=policy_cert_file.$DOMAIN_NAME \
      --policy_store_filename=$POLICY_STORE_NAME \
      --encrypted_cryptstore_filename= $CRYPTSTORE_NAME \
      --keyname="encryption_key_1" \
      --symmetric_key_algorithm=aes-256-gcm \
      --public_key_algorithm=rsa_2048 \
      --entry_tag=test-key-1 \
      --entry_version=0 \
      --entry_type="key-message-serialized-protobuf" \
      --output_format="key-message-serialized-protobuf" \
      --input_format="key-message-serialized-protobuf" \
      --input_file="in_1" \
      --output_file="out_1"

    return 0

    # retrieve symmetric key
    $SRC_DIR/cf_utility.exe \
      --cf_utility_help=false \
      --init_trust=false \
      --reinit_trust=false \
      --generate_symmetric_key=false \
      --generate_public_key=false \
      --get_item=true \
      --put_item=false \
      --print_cryptstore=true \
      --enclave_type="simulated-enclave" \
      --data_dir=$DATA_DIR \
      --policy_domain_name=$DOMAIN_NAME \
      --policy_key_file=policy_cert_file.$DOMAIN_NAME \
      --policy_store_filename=$POLICY_STORE_NAME \
      --encrypted_cryptstore_filename= $CRYPTSTORE_NAME \
      --keyname="encryption_key_1" \
      --symmetric_key_algorithm=aes-256-gcm \
      --public_key_algorithm=rsa_2048 \
      --entry_tag=test-key-1 \
      --entry_version=0 \
      --entry_type="key-message-serialized-protobuf" \
      --output_format="key-message-serialized-protobuf" \
      --input_format="key-message-serialized-protobuf" \
      --input_file="in_1" \
      --output_file="out_1"

    # make asymmetric key
    $SRC_DIR/cf_utility.exe \
      --cf_utility_help=false \
      --init_trust=false \
      --reinit_trust=false \
      --generate_symmetric_key=false \
      --generate_public_key=true \
      --get_item=false \
      --put_item=false \
      --print_cryptstore=true \
      --enclave_type="simulated-enclave" \
      --data_dir=$DATA_DIR \
      --policy_domain_name=$DOMAIN_NAME \
      --policy_key_file=policy_cert_file.$DOMAIN_NAME \
      --policy_store_filename=$POLICY_STORE_NAME \
      --encrypted_cryptstore_filename= $CRYPTSTORE_NAME \
      --keyname="encryption_key_2" \
      --symmetric_key_algorithm=aes-256-gcm \
      --public_key_algorithm=rsa_2048 \
      --entry_tag=test-key-2 \
      --entry_version=0 \
      --entry_type="key-message-serialized-protobuf" \
      --output_format="key-message-serialized-protobuf" \
      --input_format="key-message-serialized-protobuf" \
      --input_file="in_1" \
      --output_file="out_1"

    # retrieve asymmetric key
    $SRC_DIR/cf_utility.exe \
      --cf_utility_help=false \
      --init_trust=false \
      --reinit_trust=false \
      --generate_symmetric_key=false \
      --generate_public_key=false \
      --get_item=true \
      --put_item=false \
      --print_cryptstore=true \
      --enclave_type="simulated-enclave" \
      --data_dir=$DATA_DIR \
      --policy_domain_name=$DOMAIN_NAME \
      --policy_key_file=policy_cert_file.$DOMAIN_NAME \
      --policy_store_filename=$POLICY_STORE_NAME \
      --encrypted_cryptstore_filename= $CRYPTSTORE_NAME \
      --keyname="encryption_key_2" \
      --symmetric_key_algorithm=aes-256-gcm \
      --public_key_algorithm=rsa_2048 \
      --entry_tag=test-key-2 \
      --entry_version=0 \
      --entry_type="key-message-serialized-protobuf" \
      --output_format="key-message-serialized-protobuf" \
      --input_format="key-message-serialized-protobuf" \
      --input_file="in_1" \
      --output_file="out_1"

    # make symmetric key as binary-blob and store it
    $SRC_DIR/cf_utility.exe \
      --cf_utility_help=false \
      --init_trust=false \
      --reinit_trust=false \
      --generate_symmetric_key=true \
      --generate_public_key=false \
      --get_item=false \
      --put_item=false \
      --print_cryptstore=true \
      --enclave_type="simulated-enclave" \
      --data_dir=$DATA_DIR \
      --policy_domain_name=$DOMAIN_NAME \
      --policy_key_file=policy_cert_file.$DOMAIN_NAME \
      --policy_store_filename=$POLICY_STORE_NAME \
      --encrypted_cryptstore_filename= $CRYPTSTORE_NAME \
      --keyname="encryption_key_3" \
      --symmetric_key_algorithm=aes-256-gcm \
      --public_key_algorithm=rsa_2048 \
      --entry_tag=test-key-3 \
      --entry_version=0 \
      --entry_type="binary-blob" \
      --output_format="raw" \
      --input_format="raw" \
      --input_file="in_1" \
      --output_file="out_1"

    # retrieve symmetric key
    $SRC_DIR/cf_utility.exe \
      --cf_utility_help=false \
      --init_trust=false \
      --reinit_trust=false \
      --generate_symmetric_key=false \
      --generate_public_key=false \
      --get_item=true \
      --put_item=false \
      --print_cryptstore=true \
      --enclave_type="simulated-enclave" \
      --data_dir=$DATA_DIR \
      --policy_domain_name=$DOMAIN_NAME \
      --policy_key_file=policy_cert_file.$DOMAIN_NAME \
      --policy_store_filename=$POLICY_STORE_NAME \
      --encrypted_cryptstore_filename= $CRYPTSTORE_NAME \
      --keyname="encryption_key_3" \
      --symmetric_key_algorithm=aes-256-gcm \
      --public_key_algorithm=rsa_2048 \
      --entry_tag=test-key-3 \
      --entry_version=0 \
      --entry_type="binary-blob" \
      --output_format="raw" \
      --input_format="raw" \
      --input_file="in_1" \
      --output_file="out_1"
    
    # print cryptstore
  popd
}

function run-support-test() {
  pushd $SRC_DIR
    if [[ $VERBOSE -eq 1 ]]; then
      ./cf_support_test.exe --print_all=true
    else
      ./cf_support_test.exe
    fi
  popd
}

if [[ $VERBOSE -eq 1 ]]; then
  print-variables
fi
if [[ $COMPILE_PROGRAM -eq 1 ]]; then
  compile-program
fi
if [[ $RUN_GTESTS -eq 1 ]]; then
  run-support-test
fi
if [[ $COMPILE_UTIL -eq 1 ]]; then
  compile-certifier-utilities
fi
if [[ $PROVISION_KEYS -eq 1 ]]; then
  provision-keys
fi
if [[ $RUN_TEST -eq 1 ]]; then
  run-tests
fi

cleanup-stale-procs

echo ""
echo "Done"
echo ""
