#!/bin/bash
# ############################################################################
# test-script.sh: Additional tests  for cf_utility, key-client and key-server
# This can only be run after the certification is ./run-test.sh.
# ############################################################################


../../src/cf_utility.exe --print_cryptstore=true --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 --policy_store_filename=policy_store.dom0 \
    --enclave_type=simulated-enclave \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./

../../src/cf_utility.exe --export_cryptstore=true --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 --output_file=exported.cryptstore \
    --policy_store_filename=policy_store.dom0 --enclave_type=simulated-enclave \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./

../../src/cf_key_server.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ &

sleep 5

../../src/cf_key_client.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=client.in --output_file=client.out --action=store

../../src/cf_key_client.exe --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 \
    --enclave_type=simulated-enclave --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./ \
    --resource_name=key-client-test-key --version=0 \
    --input_format=raw --output_format=raw \
    --input_file=client.in --output_file=client.out --action=retrieve

sleep 3

../../src/cf_utility.exe --print_cryptstore=true --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 --policy_store_filename=policy_store.dom0 \
    --enclave_type=simulated-enclave \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./

