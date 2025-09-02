#!/bin/bash
# ############################################################################
# run-test.sh: Driver script to run cf_utility test.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [ -z "{$CERTIFIER_ROOT}+set" ] ; then
  echo " "
  CERTIFIER_ROOT=../../..
else
  echo " "
  echo "CERTIFIER_ROOT already set."
fi
EXAMPLE_DIR=$(pwd)

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

## Please dont name a domain "fresh"
if [ $ARG_SIZE == 0 ] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./run-test.sh fresh"
  echo "  ./run-test.sh fresh domain-name"
  echo "  ./run-test.sh run (se | sev)"
  echo "  ./run-test.sh run (se | sev) domain-name"
  exit
fi

if [[ $ARG_SIZE != 1 && $ARG_SIZE != 2 && $ARG_SIZE != 3  ]] ; then
  echo "Wrong number of arguments"
  echo "Must call, as follows:"
  echo "  ./run-test.sh fresh"
  echo "  ./run-test.sh fresh domain-name"
  echo "  ./run-test.sh run  (se | sev)"
  echo "  ./run-test.sh run  (se | sev) domain-name"
  exit
fi

if [[ $ARG_SIZE == 1  && $1 == "fresh" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE="none"
fi
if [[ $ARG_SIZE == 2  && $1 == "run" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE=$2
fi
if [[ $ARG_SIZE == 3 && $1 == "run" ]] ; then
  DOMAIN_NAME=$2
  ENCLAVE_TYPE=$3
fi

echo "domain name: $DOMAIN_NAME"
echo "enclave type: $ENCLAVE_TYPE"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "policy key file name: $POLICY_KEY_FILE_NAME"
echo "policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
CRYPTSTORE_NAME="cryptstore.$DOMAIN_NAME"
echo "policy store name: $POLICY_STORE_NAME"
echo "cryptstore name: $CRYPTSTORE_NAME"

function do-fresh() {
  echo "do-fresh"

  pushd $EXAMPLE_DIR > /dev/null
  rm $POLICY_STORE_NAME > /dev/null || true
  rm $CRYPTSTORE_NAME > /dev/null || true
  popd > /dev/null

  echo "Done"
  exit
}

function do-run() {
  echo "do-run"

  if [[ $ENCLAVE_TYPE != "se" && $ENCLAVE_TYPE != "sev" ]] ; then
    echo "Unsupported enclave type: $ENCLAVE_TYPE"
    exit
  fi

  pushd $EXAMPLE_DIR/service > /dev/null
  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  if [[ "$ENCLAVE_TYPE" == "se" ]] ; then
    echo "running policy server for simulated-enclave"
    $CERTIFIER_ROOT/certifier_service/simpleserver \
       --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
       --policyFile=policy.bin --readPolicy=true & > /dev/null
  fi
  if [[ "$ENCLAVE_TYPE" == "sev" ]] ; then
    echo "running policy server for sev"
    $CERTIFIER_ROOT/certifier_service/simpleserver \
       --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
        --policyFile=sev_policy.bin --readPolicy=true & > /dev/null
  fi
  popd > /dev/null

  sleep 3

  pushd $EXAMPLE_DIR > /dev/null

  if [[ "$ENCLAVE_TYPE" == "se" ]] ; then

    $CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
      --cf_utility_help=false \
      --init_trust=true \
      --print_cryptstore=true \
      --save_cryptstore=false \
      --enclave_type="simulated-enclave" \
      --policy_domain_name=$DOMAIN_NAME \
      --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
      --policy_store_filename=$POLICY_STORE_NAME \
      --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
      --symmetric_key_algorithm=aes-256-gcm  \
      --public_key_algorithm=rsa-2048 \
      --data_dir="$EXAMPLE_DIR/" \
      --certifier_service_URL=localhost \
      --service_port=8123

  sleep 3

  $CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
      --cf_utility_help=false \
      --init_trust=false \
      --generate_symmetric_key=true \
      --save_cryptstore=false \
      --enclave_type="simulated-enclave" \
      --policy_domain_name=$DOMAIN_NAME \
      --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
      --policy_store_filename=$POLICY_STORE_NAME \
      --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
      --symmetric_key_algorithm=aes-256-gcm  \
      --public_key_algorithm=rsa-2048 \
      --data_dir="$EXAMPLE_DIR/" \
      --certifier_service_URL=localhost \
      --service_port=8123
  fi

  if [[ "$ENCLAVE_TYPE" == "sev" ]] ; then

    sudo bash

    CERTIFIER_ROOT=../../..
    EXIMPLE_DIR=.

    $CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
      --cf_utility_help=false \
      --init_trust=true \
      --print_cryptstore=true \
      --save_cryptstore=false \
      --enclave_type="sev-enclave" \
      --policy_domain_name=$DOMAIN_NAME \
      --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
      --policy_store_filename=$POLICY_STORE_NAME \
      --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
      --symmetric_key_algorithm=aes-256-gcm  \
      --public_key_algorithm=rsa-2048 \
      --data_dir="$EXAMPLE_DIR/" \
      --certifier_service_URL=localhost \
      --service_port=8123
  sleep 3

  $CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
      --cf_utility_help=false \
      --init_trust=false \
      --generate_symmetric_key=true \
      --save_cryptstore=false \
      --enclave_type="sev-enclave" \
      --policy_domain_name=$DOMAIN_NAME \
      --policy_key_cert_file=$POLICY_CERT_FILE_NAME \
      --policy_store_filename=$POLICY_STORE_NAME \
      --encrypted_cryptstore_filename=$CRYPTSTORE_NAME \
      --symmetric_key_algorithm=aes-256-gcm  \
      --public_key_algorithm=rsa-2048 \
      --data_dir="$EXAMPLE_DIR/" \
      --certifier_service_URL=localhost \
      --service_port=8123
    exit
  fi

  popd > /dev/null


  echo "do-run done"
}

if [ "$1" == "fresh" ] ; then
  do-fresh
  exit
fi

if [ "$1" == "run" ] ; then
  do-run
  exit
fi

echo " "
echo "Unknown option: $1"
