#!/bin/bash
# ############################################################################
# run-server-app.sh: Driver script to run tpm simple-example test
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

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [[ $ARG_SIZE != 1 ]] ; then
  echo "Wrong number of arguments"
  echo "Must call, as follows:"
  echo "  ./run-server-app.sh domain-name"
  exit
fi
DOMAIN_NAME=$1

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
POLICY_STORE_FILE_NAME="policy_store.$DOMAIN_NAME"

echo "Policy key file name: $POLICY_KEY_FILE_NAME"
echo "Policy cert file name: $POLICY_CERT_FILE_NAME"
echo "Example dir: : $EXAMPLE_DIR"
echo "Domain name: $DOMAIN_NAME"
echo "Policy store file name: $POLICY_STORE_FILE_NAME"

function do-run() {
  echo " "
  echo "do-run"

  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/tpmlib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  sleep 5

  pushd $EXAMPLE_DIR
    echo " "
    echo "running app-as-server"
    $EXAMPLE_DIR/tpm_example_app.exe \
      --data_dir=./app2_data/ --operation="run-app-as-server"   \
      --domain_name=$DOMAIN_NAME \
      --tpm_device="/dev/tpmrm1" \
      --seal_hierarchy_file_name="seal_hierarchy.bin" \
      --quote_hierarchy_file_name="quote_hierarchy.bin" \
      --policy_store_file=$POLICY_STORE_FILE_NAME --print_all=true
  popd

  echo "do-run done"
}

do-run
echo " "
