#!/bin/bash
# ############################################################################
# test-script.sh: Additional tests  for cf_utility, key-client and key-server
# This can only be run after the certification is ./run-test.sh.
# ############################################################################

pushd ../../..
  CERTIFIER_ROOT=$(pwd)
popd
EXAMPLE_DIR=$(pwd)

echo " "
echo "CERTIFIER_ROOT: $CERTIFIER_ROOT"
echo "EXAMPLE_DIR: $EXAMPLE_DIR"
echo " "

echo " "
echo "printing cryptstore"
echo " "
$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe --print_cryptstore=true --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 --policy_store_filename=policy_store.dom0 \
    --enclave_type=simulated-enclave \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./

echo " "
echo "exporting cryptstore"
echo " "
$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe --export_cryptstore=true --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 --output_file=exported.cryptstore \
    --policy_store_filename=policy_store.dom0 --enclave_type=simulated-enclave \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./

echo " "
echo "running key-server"
echo " "
$CERTIFIER_ROOT/vm_model_tools/src/cf_key_server.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ &

sleep 5

echo " "
echo "key-client: storing new value"
echo " "
$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=client.in --output_file=client.out --action=store

echo " "
echo "key-client: retrieving"
echo " "
$CERTIFIER_ROOT/vm_model_tools/src/cf_key_client.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=client.in --output_file=client.out --action=retrieve

sleep 3

echo " "
echo "printing cryptstore"
echo " "
$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe --print_cryptstore=true --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 --policy_store_filename=policy_store.dom0 \
    --enclave_type=simulated-enclave \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./

