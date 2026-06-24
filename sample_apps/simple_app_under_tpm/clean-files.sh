#!/bin/bash
# ############################################################################
# cleanup after tpm simulator
# ############################################################################

# maybe add args later

set -Eeuo pipefail
Me=$(basename "$0")

function cleanup-stale-procs() {
  echo " "
  echo "cleanup-stale-procs"

  # Find and kill certifier-service processes that may be running.
  echo " "
  set +e
  service_pid=$(ps -ef | grep -E "simpleserver" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  if [[ $service_pid != "" ]] ; then
    kill -9 $service_pid
    echo "killed simulator _service, pid $service_pid"
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

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../..
  CERTIFIER_ROOT=$(pwd)
  popd
fi
EXAMPLE_DIR=$(pwd)

ARG_SIZE="$#"

if [[ $ARG_SIZE != 1 ]] ; then
  echo "Wrong number of arguments"
  echo "Must call, as follows:"
  echo "  ./clean-files.sh domain"
  exit
fi
DOMAIN_NAME=$1
echo "Domain name: $DOMAIN_NAME"
POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
POLICY_STORE_FILE_NAME="policy_store.$DOMAIN_NAME"

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"
echo "Policy key file name: $POLICY_KEY_FILE_NAME"
echo "Policy cert file name: $POLICY_CERT_FILE_NAME"

  echo " "
  echo "clean-files and old procs"

  # kill the server
  cleanup-stale-procs

  # remove the files
  rm app1_data/*
  rm app2_data/*
  rm service/*
  echo "rm provisioning/*"
  rm provisioning/*
  rm seal_hierarchy.bin quote_hierarchy.bin

echo "Done"
exit
