
#!/bin/bash
# ############################################################################
# copy-vm-files-test.sh
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
  exit
fi

if [[ $ARG_SIZE != 1 && $ARG_SIZE != 2 && $ARG_SIZE != 3  ]] ; then
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

function do-copy-files() {
  echo " "
  echo "do-copy-files"
      
  if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi
  if [[ ! -e "$EXAMPLE_DIR/service" ]] ; then
    mkdir $EXAMPLE_DIR/service
  fi
  if [[ ! -e "$EXAMPLE_DIR/cf_data" ]] ; then
    mkdir $EXAMPLE_DIR/cf_data
  fi
  pushd $EXAMPLE_DIR/provisioning
    cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/service
    cp -p sev_policy.bin ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/service
    cp -p $POLICY_CERT_FILE_NAME $EXAMPLE_DIR/cf_data
    cp -p platform_key_file.bin attest_key_file.bin sev_cf_utility.measurement $EXAMPLE_DIR/cf_data
    cp -p cf_utility.measurement platform_attest_endorsement.bin $EXAMPLE_DIR/cf_data
    cp -p ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/cf_data
  popd

  pushd $EXAMPLE_DIR/cf_data
    $CERTIFIER_ROOT/utilities/combine_policy_certs.exe \
      --init=true --new_cert_file=$POLICY_CERT_FILE_NAME \
      --output=my_certs
  popd

  echo "do-copy-files done"
}

do-copy-files
echo " files copied"
echo ""
