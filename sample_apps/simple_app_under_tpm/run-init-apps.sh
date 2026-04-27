#!/bin/bash
# ############################################################################
# run-init-apps.sh: Driver script to run tpm simple-example test
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

## Please dont name a domain "fresh"
if [ $ARG_SIZE == 0 ] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./run-init-apps.sh fresh"
  echo "  ./run-init-apps.sh fresh domain-name"
  echo "  ./run-init-apps.sh run"
  echo "  ./run-init-apps.sh run domain-name"
  exit
fi

if [[ $ARG_SIZE != 1 && $ARG_SIZE != 2 ]] ; then
  echo "Wrong number of arguments"
  echo "Must call, as follows:"
  echo "  ./run-init-apps.sh fresh"
  echo "  ./run-init-apps.sh fresh domain-name"
  echo "  ./run-init-apps.sh run"
  echo "  ./run-init-apps.sh run domain-name"
  exit
fi

if [[ $ARG_SIZE == 1  && $1 == "fresh" ]] ; then
  DOMAIN_NAME="datica-test"
fi
if [[ $ARG_SIZE == 2  && $1 == "fresh" ]] ; then
  DOMAIN_NAME=$2
fi
if [[ $ARG_SIZE == 1  && $1 == "run" ]] ; then
  DOMAIN_NAME="datica-test"
fi
if [[ $ARG_SIZE == 2  && $1 == "run" ]] ; then
  DOMAIN_NAME=$2
fi

echo "Domain name: $DOMAIN_NAME"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "Policy key file name: $POLICY_KEY_FILE_NAME"
echo "Policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
echo "Policy store name 1: ./app1_data/$POLICY_STORE_NAME"
echo "Policy store name 2: ./app2_data/$POLICY_STORE_NAME"

function do-fresh() {
  echo " "
  echo "do-fresh"

  pushd $EXAMPLE_DIR
    if [[ ! -d "./app1_data" ]] ; then
      mkdir ./app1_data
    fi
    if [[ ! -d "./app2_data" ]] ; then
      mkdir ./app2_data
    fi
    if [[ -e "./app1_data/$POLICY_STORE_NAME" ]] ; then
      rm ./app1_data/$POLICY_STORE_NAME
    fi
    if [[ -e "./app2_data/$POLICY_STORE_NAME" ]] ; then
      rm ./app2_data/$POLICY_STORE_NAME
    fi
  popd

  echo "Done"
  exit
}

function cleanup_stale_procs() {
  echo " "
  echo "cleanup_stale_procs"

  # Find and kill simpleserver processes that may be running.
  echo " "
  set +e
  certifier_pid=$(ps -ef | grep -E "simpleserver" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  if [[ $certifier_pid != "" ]] ; then
    kill -9 $certifier_pid
    echo "killed certifier_service, pid $certifier_pid"
  else
    echo "no certifier_service running"
  fi

  # Find and kill app processes that may be running.
  echo " "
  set +e
  app_pid=$(ps -ef | grep -E "tpm_example_app" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  if [[ $app_pid != "" ]] ; then
    kill -9 $app_pid
    echo "killed app, pid $app_pid"
  else
    echo "no certifier_service running"
  fi

  # once more
  echo " "
  set +e
  app_pid=$(ps -ef | grep -E "tpm_example_app" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  if [[ $app_pid != "" ]] ; then
    kill -9 $app_pid
    echo "killed app, pid $app_pid"
  else
    echo "no certifier_service running"
  fi

  echo "cleanup_stale_procs done"
}

function do-run() {
  echo " "
  echo "do-run"

  cleanup_stale_procs
  echo " "
  echo " cleaned old  procs"

  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/tpmlib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  sleep 5

  pushd $EXAMPLE_DIR/service
    echo " "
    echo "$CERTIFIER_ROOT/certifier_service/simpleserver  \
      --policy_key_file=$POLICY_KEY_FILE_NAME 
      --policy_cert_file=$POLICY_CERT_FILE_NAME \
      --policyFile=policy.bin --readPolicy=true"
    $CERTIFIER_ROOT/certifier_service/simpleserver  \
      --policy_key_file=$POLICY_KEY_FILE_NAME \
      --policy_cert_file=$POLICY_CERT_FILE_NAME \
      --policyFile=policy.bin --readPolicy=true &
    echo "simpleserver started"
    echo " "

    sleep 5
  popd

    echo " "
    echo "initializing app1"
    $EXAMPLE_DIR/tpm_example_app.exe --data_dir=./app1_data/  \
        --domain_name=$DOMAIN_NAME \
        --operation=fresh-start  \
        --tpm_device="/dev/tpmrm1" \
        --seal_hierarchy_file_name="seal_hierarchy.bin" \
        --quote_hierarchy_file_name="quote_hierarchy.bin" \
        --policy_store_file=$POLICY_STORE_NAME --print_all=true
    echo "certifying app1"
    $EXAMPLE_DIR/tpm_example_app.exe --data_dir=./app1_data/  \
        --domain_name=$DOMAIN_NAME \
        --operation=get-certified \
        --tpm_device="/dev/tpmrm1" \
        --seal_hierarchy_file_name="seal_hierarchy.bin" \
        --quote_hierarchy_file_name="quote_hierarchy.bin" \
        --policy_store_file=$POLICY_STORE_NAME --print_all=true

    sleep 5

    echo " "
    echo "initializing app2"
    $EXAMPLE_DIR/tpm_example_app.exe  --data_dir=./app2_data/ \
        --domain_name=$DOMAIN_NAME \
        --operation=fresh-start \
        --tpm_device="/dev/tpmrm1" \
        --seal_hierarchy_file_name="seal_hierarchy.bin" \
        --quote_hierarchy_file_name="quote_hierarchy.bin" \
        --policy_store_file=$POLICY_STORE_NAME --print_all=true
    echo "certifying app2"
    $EXAMPLE_DIR/tpm_example_app.exe  --data_dir=./app2_data/ \
        --domain_name=$DOMAIN_NAME \
        --operation=get-certified  \
        --tpm_device="/dev/tpmrm1" \
        --seal_hierarchy_file_name="seal_hierarchy.bin" \
        --quote_hierarchy_file_name="quote_hierarchy.bin" \
        --policy_store_file=$POLICY_STORE_NAME --print_all=true

  cleanup_stale_procs

  echo "do-run done"
}

if [ "$1" == "fresh" ] ; then
  do-fresh
  exit
fi

if [ "$1" == "run" ] ; then
  do-run
  exit
fi

echo " "
echo "Unknown option: $1"
