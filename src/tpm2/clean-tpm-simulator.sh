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

  # Find and kill simulator processes that may be running.
  echo " "
  set +e
  sim_pid=$(ps -ef | grep -E "swtpm" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
  set -e
  if [[ $sim_pid != "" ]] ; then
    kill -9 $sim_pid
    echo "killed simulator service, pid $sim_pid"
  else
    echo "no simulator service running"
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
TPM_SUPPORT_DIR=$CERTIFIER_ROOT/src/tpm2

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "TPM support directory: $TPM_SUPPORT_DIR"

pushd $TPM_SUPPORT_DIR
  echo " "
  echo "cleanup-tpm-simulator"

  # kill the server
  cleanup-stale-procs

  # remove the files
  rm seal_hierarchy.bin quote_hierarchy.bin
popd

echo "Done"
exit
