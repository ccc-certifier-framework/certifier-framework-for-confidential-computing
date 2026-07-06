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
CUSE=0

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
  mkdir $XDG_CONFIG_HOME
  mkdir $XDG_CONFIG_HOME/mytpm1
fi
echo "TPM state directory: $XDG_CONFIG_HOME"

pushd $TPM_SUPPORT_DIR
  echo " "
  echo "start-tpm-simulator"

  echo "Tpm simulator state in $XDG_CONFIG_HOME"
  echo "Current directory: $(pwd)"

  swtpm_setup --tpmstate ${XDG_CONFIG_HOME}/mytpm1 --create-ek-cert \
    --create-platform-cert --tpm2 --write-ek-cert-files .

  if [[ $CUSE -eq 1 ]]; then
    swtpm cuse --name mytpm1 --tpmstate dir=$XDG_CONFIG_HOME  --tpm2
  else
    set +e
    # /usr/bin/echo "capability sys_admin," > /etc/apparmor.d/local/usr.bin.swtpm aa-enforce /usr/bin/swtpm
    modprobe tpm_vtpm_proxy
    if [[ $? -eq 0 ]] ; then
      set -e
      echo "Using chardev"
      swtpm chardev --vtpm-proxy --tpmstate dir=${XDG_CONFIG_HOME}/mytpm1 \
        --tpm2 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
    else
      set -e
      echo "chardev unavailable, using socket"
      swtpm socket --tpmstate dir=${XDG_CONFIG_HOME}/mytpm1 --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init,startup-clear --log level=20 &
      sleep 5
      socat PTY,link=/dev/tpmrm1,raw,echo=0 TCP4:127.0.0.1:2321 &
  fi
fi

  echo "tpm simulator started"
  chmod 0777 *.crt || true
popd
echo "Done"
