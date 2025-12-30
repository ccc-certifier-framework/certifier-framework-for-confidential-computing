#!/bin/bash
# ############################################################################
# run-policy-server.sh
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

function run-policy-server() {
  echo " "
  echo "run-policy-server"

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
}

run-policy-server
echo "policy server running"
echo ""
echo "Unknown option: $1"
