#!/bin/bash
# ############################################################################
# run-test.sh: Driver script to run cf_utility test.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../../ > /dev/null
  CERTIFIER_ROOT=$(pwd)
  popd > /dev/null
fi
EXAMPLE_DIR=$(pwd)

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

## Please dont name a domain "fresh"
if [ $ARG_SIZE == 0 ] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./run-test.sh fresh"
  echo "  ./run-test.sh fresh domain-name"
  echo "  ./run-test.sh run
  echo "  ./run-test.sh run domain-name"
  exit
fi

if [[ $ARG_SIZE != 1 && $ARG_SIZE != 2 ]] ; then
  echo "Wrong number of arguments"
  echo "Must call, as follows:"
  echo "  ./run-test.sh fresh"
  echo "  ./run-test.sh fresh domain-name"
  echo "  ./run-test.sh run
  echo "  ./run-test.sh run domain-name"
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

echo "domain name: $DOMAIN_NAME"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "policy key file name: $POLICY_KEY_FILE_NAME"
echo "policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
echo "policy store name 1: ./app1_data/$POLICY_STORE_NAME
echo "policy store name 2: ./app2_data/$POLICY_STORE_NAME

function do-fresh() {
  echo "do-fresh"

  pushd $EXAMPLE_DIR > /dev/null
  if [[ ! -d "./app1" ]] ; then
    mkdir ./app1
  fi
  if [[ ! -d "./app2" ]] ; then
    mkdir ./app2
  fi
  if [[ -e "./app1_data/$POLICY_STORE_NAME" ]] ; then
    rm ./app1_data/$POLICY_STORE_NAME
  fi
  if [[ -e "./app2_data/$POLICY_STORE_NAME" ]] ; then
    rm ./app2_data/$POLICY_STORE_NAME
  fi
  popd > /dev/null

  echo "Done"
  exit
}

function cleanup_stale_procs() {

  # Find and kill simpleserver processes that may be running.
  echo " "
  certifier_pid=$(ps -ef | grep -E "simpleserver" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -x
  kill -9 $certifier_pid || true

  # Find and kill simpleserver processes that app serverrunning.
  echo " "
  app_pid=$(ps -ef | grep -E "example_app" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -x
  kill -9 $app_pid || true

  echo "killed $certifier_pid $app_pid"
}

function do-run() {
  echo "do-run"
  echo " "

  pushd $EXAMPLE_DIR/service > /dev/null
  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  sleep 5

  echo " "
  echo "$CERTIFIER_ROOT/certifier_service/simpleserver  \
    --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
    --policyFile=policy.bin --readPolicy=true"
  $CERTIFIER_ROOT/certifier_service/simpleserver  \
    --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
    --policyFile=policy.bin --readPolicy=true > /dev/null &
  echo "simpleserver started"
  echo " "

  sleep 5

  popd > /dev/null

  pushd $EXAMPLE_DIR > /dev/null

  echo " "
  echo "certifying app1"
  $EXAMPLE_DIR/example_app.exe --data_dir=./app1_data/  \
      --domain_name=$DOMAIN_NAME \
      --operation=fresh-start  --measurement_file="example_app.measurement" \
      --policy_store_file=$POLICY_STORE_NAME --print_all=true

  sleep 5

  echo " "
  echo "certifying app2"
  $EXAMPLE_DIR/example_app.exe  --data_dir=./app2_data/ \
      --domain_name=$DOMAIN_NAME \
      --operation=fresh-start  --measurement_file="example_app.measurement" \
      --policy_store_file=$POLICY_STORE_NAME --print_all=true

  sleep 5

  echo " "
  echo "running app-as-server"
  $EXAMPLE_DIR/example_app.exe \
    --data_dir=./app2_data/ --operation="run-app-as-server" \
    --domain_name=$DOMAIN_NAME \
    --measurement_file="example_app.measurement" \
    --policy_store_file=$POLICY_STORE_NAME  --print_all=true > /dev/null &

  sleep 5

  echo " "
  echo "running app-as-client"
  $EXAMPLE_DIR/example_app.exe \
    --data_dir=./app1_data/ --operation="run-app-as-client"   \
    --domain_name=$DOMAIN_NAME \
    --measurement_file="example_app.measurement" \
    --policy_store_file=$POLICY_STORE_NAME --print_all=true

  popd > /dev/null

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
