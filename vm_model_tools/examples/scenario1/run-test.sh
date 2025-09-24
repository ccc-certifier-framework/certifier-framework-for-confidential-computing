#!/bin/bash
# ############################################################################
# run-test.sh: Script to run cf_utility test.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../../.. > /dev/null
  CERTIFIER_ROOT=$(pwd) > /dev/null
  popd
fi
EXAMPLE_DIR=$(pwd) > /dev/null

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

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

if [[ $ARG_SIZE == 1 && $1 == "fresh" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE="none"
fi
if [[ $ARG_SIZE == 2  && $1 == "fresh" ]] ; then
  DOMAIN_NAME=$2
  ENCLAVE_TYPE="none"
fi

if [[ $ARG_SIZE == 2  && $1 == "run" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE=$2
fi
if [[ $ARG_SIZE == 3 && $1 == "run" ]] ; then
  DOMAIN_NAME=$3
  ENCLAVE_TYPE=$2
fi

echo "Domain name: $DOMAIN_NAME"
echo "Enclave type: $ENCLAVE_TYPE"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "Policy key file name: $POLICY_KEY_FILE_NAME"
echo "Policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
CRYPTSTORE_NAME="cryptstore.$DOMAIN_NAME"
echo "Policy store name: $POLICY_STORE_NAME"
echo "Cryptstore name: $CRYPTSTORE_NAME"

function do-fresh() {
  echo " "
  echo "do-fresh"

  pushd $EXAMPLE_DIR
    if [[ -e "$POLICY_STORE_NAME" ]] ; then
      rm $POLICY_STORE_NAME
    fi
    if [[ -e "$CRYPTSTORE_NAME" ]] ; then
      rm $CRYPTSTORE_NAME
    fi
  popd

  echo "Done"
  exit
}

function cleanup_stale_procs() {
  # Find and kill simpleserver processes that may be running.
  echo " "
  echo "cleanup_stale_procs"

  set +e
  certifier_pid=$(ps -ef | grep -E "simpleserver" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  if [[ $certifier_pid != "" ]] ; then
    kill -9 $certifier_pid
    echo "killed certifier_service, pid $certifier_pid"
  else
    echo "no certifier_service running"
  fi

  echo "cleanup_stale_procs done"
}

function do-run() {
  echo " "
  echo "do-run"

  if [[ $ENCLAVE_TYPE != "se" && $ENCLAVE_TYPE != "sev" ]] ; then
    echo "Unsupported enclave type: $ENCLAVE_TYPE"
    exit
  fi

  cleanup_stale_procs

  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  pushd $EXAMPLE_DIR/service
    if [[ "$ENCLAVE_TYPE" == "se" ]] ; then
      echo "running policy server for simulated-enclave"
      $CERTIFIER_ROOT/certifier_service/simpleserver \
        --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
        --policyFile=policy.bin --readPolicy=true &
    fi
    if [[ "$ENCLAVE_TYPE" == "sev" ]] ; then
      echo "running policy server for sev"
      $CERTIFIER_ROOT/certifier_service/simpleserver \
        --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
          --policyFile=sev_policy.bin --readPolicy=true &
    fi
  popd

  sleep 3

  pushd $EXAMPLE_DIR

    if [[ "$ENCLAVE_TYPE" == "se" ]] ; then

      echo " "
      echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
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
        --service_port=8123" --print_level=1
      echo " "


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
        --service_port=8123 --print_level=1

      sleep 3

      echo " "
      echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
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
        --service_port=8123" --print_level=3
      echo " "

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
        --service_port=8123 --print_level=3
    fi

    if [[ "$ENCLAVE_TYPE" == "sev" ]] ; then
      sudo ./sev-client-call.sh $DOMAIN_NAME $POLICY_CERT_FILE_NAME $POLICY_STORE_NAME $CRYPTSTORE_NAME "$EXAMPLE_DIR/"
    fi
  popd

  cleanup_stale_procs

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
