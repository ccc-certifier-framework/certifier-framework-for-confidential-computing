#!/bin/bash
# ############################################################################
# prepare-test.sh: Script to run build simple_app_under_tpm test environment.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../..
  CERTIFIER_ROOT=$(pwd)
  popd
fi
EXAMPLE_DIR=$(pwd)

NO_COMPILE_UTILITIES=1

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [[ $ARG_SIZE == 0 ]] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./first-pass.sh domain_name"
  exit
fi

DOMAIN_NAME=$1
echo "domain name: $DOMAIN_NAME"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "policy key file name: $POLICY_KEY_FILE_NAME"
echo "policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
echo "policy store name: $POLICY_STORE_NAME"

function do-get-quote-cert-and-measurement() {
  echo " "
  echo "do-get-quote-cert-and-measurement"

  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  sleep 5

  pushd $EXAMPLE_DIR
  echo " "
  echo "first pass"
  $EXAMPLE_DIR/tpm_example_app.exe --data_dir=./app1_data/  \
        --domain_name=$DOMAIN_NAME \
        --operation="first-pass" \
        --tpm_device="/dev/tpmrm1" \
        --seal_hierarchy_file_name="seal_hierarchy.bin" \
        --quote_hierarchy_file_name="quote_hierarchy.bin" \
	--policy_key_file="./provisioning/policy_key_file.$DOMAIN_NAME" \
	--quote_cert_file="./provisioning/quote_cert.crt" \
	--measurement_file="./provisioning/measurement" \
        --policy_store_file=$POLICY_STORE_NAME --print_all=true
  echo ""
  echo "first pass done"
}

do-get-quote-cert-and-measurement

echo " "
echo "Done"
