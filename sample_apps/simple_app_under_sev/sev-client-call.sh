#!/bin/bash
# ############################################################################
# sev-client-call.sh: Script to run client cf_utility for sev as root.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

ARG_SIZE="$#"

if [ $ARG_SIZE != 5 ] ; then
  echo "This should only be called by run-test.sh and it has the wrong number of args"
fi

CERTIFIER_ROOT=../../..
EXAMPLE_DIR=.
echo "New root: $CERTIFIER_ROOT"
echo "New example: $EXAMPLE_DIR"
echo "Domain name: $1"
echo "Cert file name: $2"
echo "Policy store name: $3"

# --policy_domain_name=$1 \
# --policy_key_cert_file=$2 \
# --policy_store_filename=$3 \
#--certifier_service_URL=localhost \
#--service_port=8123

sleep 3

$EXAMPLE_DIR/sev_example_app.exe            \
	--domain_name=$1 \
        --data_dir="./app1_data/"             \
        --operation=cold-init               \
        --policy_store_file=$3 \
        --print_all=true
sleep 1
$EXAMPLE_DIR/sev_example_app.exe            \
        --data_dir="./app1_data/"            \
        --operation=get-certified           \
        --policy_store_file=$3 \
        --print_all=true
sleep 2
$EXAMPLE_DIR/sev_example_app.exe            \
        --data_dir="./app2_data/"            \
        --operation=cold-init               \
        --policy_store_file=$3 \
        --print_all=true
sleep 1
$EXAMPLE_DIR/sev_example_app.exe            \
        --data_dir="./app2_data/"            \
        --operation=get-certified           \
        --policy_store_file=$3\
        --print_all=true

sleep 1
$EXAMPLE_DIR/sev_example_app.exe            \
        --data_dir="./app2_data/"            \
        --operation=run-app-as-server       \
        --policy_store_file=$3 \
        --print_all=true
sleep 3
$EXAMPLE_DIR/sev_example_app.exe            \
        --data_dir="./app1_data/"            \
        --operation=run-app-as-client       \
        --policy_store_file=$3 \
        --print_all=true
exit
