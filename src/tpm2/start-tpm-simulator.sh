#!/bin/bash

# ############################################################################
# Start tpm simulator
# ############################################################################

# maybe add args later

set -Eeuo pipefail
Me=$(basename "$0")

if [[ "$(id -u)" -ne 0 ]]; then
   echo "Must be root, exiting"
   exit 1
fi

pushd ../.. > /dev/null
  CERTIFIER_ROOT=$(pwd)
popd
TPM_SUPPORT_DIR=$CERTIFIER_ROOT/src/tpm2

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "TPM support directory: $TPM_SUPPORT_DIR"
if [[ ! -v XDG_CONFIG_HOME ]]; then
  XDG_CONFIG_HOME=$CERTIFIER_ROOT/swtpm_state
fi
if [[ ! -e $XDG_CONFIG_HOME ]]; then
  echo "$XDG_CONFIG_HOME does not exist"
  exit 1
fi
echo "TPM state directory: $XDG_CONFIG_HOME"

pushd $TPM_SUPPORT_DIR
  echo " "
  echo "start-tpm-simulator"

  echo "Tpm simulator state in $XDG_CONFIG_HOME"
  echo "Current directory: $(pwd)"

  swtpm_setup --tpmstate ${XDG_CONFIG_HOME}/mytpm1 --create-ek-cert \
    --create-platform-cert --tpm2 --write-ek-cert-files .

  set +e
  modprobe tpm_vtpm_proxy
  if [[ $? -eq 0 ]] ; then
    set -e
    echo "Using chardev"
    swtpm chardev --vtpm-proxy --tpmstate dir=${XDG_CONFIG_HOME}/mytpm1 \
      --tpm2 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
  else
    set -e
    echo "chardev unavailable, using socket"
    swtpm socket --tpmstate dir=${XDG_CONFIG_HOME}/mytpm1 --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init,startup-clear --log level=0 &
    sleep 5
    socat PTY,link=/dev/tpmrm1,raw,echo=0 TCP4:127.0.0.1:2321 &
  fi
  echo "tpm simulator started"
  chmod 0777 *.crt || true
popd
echo "Done"
