#!/bin/bash
# ############################################################################
# run-test.sh: Script to run app service test.
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
APP_SERVICE_DIR=$(pwd)
    
echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "App service directory: $APP_SERVICE_DIR"

ARG_SIZE="$#"

## Please dont name a domain "fresh"
if [[ $ARG_SIZE == 0 || $ARG_SIZE > 3 ]] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./run-test.sh fresh"
  echo "  ./run-test.sh fresh domain-name"
  echo "  ./run-test.sh run (se|sev)"
  echo "  ./run-test.sh run (se|sev) domain-name"
  exit
fi

if [[ $ARG_SIZE == 1  && $1 == "fresh" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE="unknown"
fi
if [[ $ARG_SIZE == 2  && $1 == "fresh" ]] ; then
  DOMAIN_NAME=$2
  ENCLAVE_TYPE="unknown"
fi
if [[ $ARG_SIZE == 1  && $1 == "run" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE="se"
fi
if [[ $ARG_SIZE == 2  && $1 == "run" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE="se"
fi
if [[ $ARG_SIZE == 3  && $1 == "run" ]] ; then
  ENCLAVE_TYPE=$2
  DOMAIN_NAME=$3
fi

echo "domain name: $DOMAIN_NAME"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "policy key file name: $POLICY_KEY_FILE_NAME"
echo "policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
echo "policy store name: ./service_data/$POLICY_STORE_NAME"


function do-fresh() {
  echo " "
  echo "do-fresh"

  pushd $APP_SERVICE_DIR
    if [[ ! -d "./service_data" ]] ; then
      mkdir ./service_data
    fi
    if [[ -e "./service_data/$POLICY_STORE_NAME" ]] ; then
      rm ./service_data/$POLICY_STORE_NAME
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

  # Find and kill app processes that app still running.
  echo " "
  set +e
  app_pid=$(ps -ef | grep -E "app_service" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  
  if [[ $app_pid != "" ]] ; then
  set +e
    kill -9 $app_pid
  set -e
    echo "killed app server, pid: $app_pid"
  else
    echo "no app server running"
  fi

  echo "cleanup_stale_procs done"
}

# In call to sev-client-call.sh
#   --policy_domain_name=$1 \
#   --policy_key_cert_file=$2 \
#   --policy_store_filename=$3 \
#   --certifier_service_URL=localhost \
#   --service_port=8123
function do-run() {
  echo " "
  echo "do-run"

  cleanup_stale_procs
  echo " "
  echo " cleaned old  procs"
  echo " "

  export LD_LIBRARY_PATH=/usr/local/lib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/teelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/graminelib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/isletlib
  export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$CERTIFIER_ROOT/certifier_service/oelib
  echo $LD_LIBRARY_PATH
  sudo ldconfig

  sleep 5

  pushd $APP_SERVICE_DIR/service
    echo " "
    echo "running simpleserver"
    $CERTIFIER_ROOT/certifier_service/simpleserver  \
      --policy_key_file=$POLICY_KEY_FILE_NAME --policy_cert_file=$POLICY_CERT_FILE_NAME \
      --policyFile=policy.bin --readPolicy=true &
    echo "simpleserver started"
    echo " "

    sleep 5
  popd

  pushd $APP_SERVICE_DIR
    echo " "
    if [[ "$ENCLAVE_TYPE" == "se" ]] ;  then
      $APP_SERVICE_DIR/app_service.exe \
        --domain_name=$DOMAIN_NAME \
        --service_dir="./service/" --cold_init_service=true  \
        --policy_cert_file=$POLICY_KEY_FILE_NAME 
        --service_policy_store=$POLICY_STORE_NAME \
        --host_enclave_type="simulated-enclave" --platform_file_name="platform_file.bin" \
        --platform_attest_endorsement="platform_attest_endorsement.bin"   \
        --attest_key_file="attest_key_file.bin"                           \
        --measurement_file="app_service.measurement" \ --guest_login_name="guest" &
    fi
    if [[ "$ENCLAVE_TYPE" == "sev" ]] ;  then
      $APP_SERVICE_DIR/app_service.exe \
        --domain_name=$DOMAIN_NAME \
        --service_dir="./service/" --cold_init_service=true  \
        --policy_cert_file=$POLICY_KEY_FILE_NAME 
        --service_policy_store=$POLICY_STORE_NAME \
        --host_enclave_type="sev-enclave" --platform_file_name="platform_file.bin" \
        --platform_attest_endorsement="platform_attest_endorsement.bin"   \
        --attest_key_file="attest_key_file.bin"                           \
        --measurement_file="app_service.measurement" \ --guest_login_name="guest" &
    fi
    sleep 3
    echo "sending requests"
    ./send_request.exe --executable="./hello_world.exe" --server_app_port=8127 \
         --server_app_host="localhost"
$   ./send_request.exe --executable="./test_user.exe" --server_app_port=8127
         --server_app_host="localhost"
    echo " "
  popd

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
