#!/bin/bash
# ############################################################################
# obtain-application-secrets.sh
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
  exit
fi

if [[ $ARG_SIZE != 1 && $ARG_SIZE != 2 && $ARG_SIZE != 3  ]] ; then
  echo "Wrong number of arguments"
  echo "Must call, as follows:"
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

$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --print_level=5 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=client.in --output_file=client.out --action=retrieve \
    --key_server_url=localhost --key_server_port=8120

sleep 3

echo "key retrieved"
echo ""
