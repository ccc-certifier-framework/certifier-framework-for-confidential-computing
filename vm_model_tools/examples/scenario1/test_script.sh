#!/bin/bash
# ############################################################################
# test-script.sh: Additional tests  for cf_utility, key-client and key-server
# This can only be run after the certification is ./run-test.sh.
# ############################################################################



../../src/cf_utility.exe --print_cryptstore=true --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./

../../src/cf_utility.exe --export_cryptstore=true --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 --output_file=exported.cryptstore \
    --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./

../../src/cf_utility.exe --import_cryptstore=true --policy_domain_name=dom0 \
    --encrypted_cryptstore_filename=cryptstore.dom0 --input_file=exported.cryptstore \
    --policy_store_filename=policy_store.dom0 \
    --policy_key_cert_file=policy_cert_file.dom0 --data_dir=./
