#!/bin/bash
# ############################################################################
# generate-and-store-secret-for-deployment.sh
# This can only be run after the certification
# ############################################################################

pushd ../../..
  CERTIFIER_ROOT=$(pwd)
popd
EXAMPLE_DIR=$(pwd)

echo " "
echo "CERTIFIER_ROOT: $CERTIFIER_ROOT"
echo "EXAMPLE_DIR: $EXAMPLE_DIR"
echo " "

function cleanup_stale_procs() {
  # Find and kill simpleserver processes that may be running.
  echo " "
  echo "cleanup_stale_procs"

  set +e
  key_server_pid=$(ps -ef | grep -E "cf_key_server" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  if [[ $key_server_pid != "" ]] ; then
    kill -9 $key_server_pid
    echo "killed key_server_service, pid $key_server_pid"
  else
    echo "no key_server_service running"
  fi

  echo "cleanup_stale_procs done"
}

# kill running key servers

echo " "
echo "key-client: storing new value"
echo " "
echo "First, create key in client.in"
echo "01234567890123456789012345678901" > client.in
echo " "
echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --print_level=5 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=client.in --output_file=client.out --action=store"
echo " "
$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --print_level=5 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=client.in --output_file=client.out --action=store

echo " "
echo "key-client: retrieving"
echo " "
echo "$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --print_level=5 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=client.in --output_file=client.out --action=retrieve"
echo " "
$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --print_level=5 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=client.in --output_file=client.out --action=retrieve



