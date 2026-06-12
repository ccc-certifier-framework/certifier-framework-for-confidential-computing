#!/bin/bash
# ############################################################################
# Start tpm simulator
# ############################################################################

# maybe add args later

set -Eeuo pipefail
Me=$(basename "$0")

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../../..
  CERTIFIER_ROOT=$(pwd)
  popd
fi
TPM_SUPPORT_DIR=$CERTIFIER_ROOT/src/tpm2

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "TPM support directory: $TPM_SUPPORT_DIR"

if [[ ! -v XDG_CONFIG_HOME ]]; then
  echo "Using export XDG_CONFIG_HOME=$HOME/.config"
  export XDG_CONFIG_HOME="$HOME/.config"
fi
if [[ ! -e $XDG_CONFIG_HOME ]]; then
  echo "$XDG_CONFIG_HOME does not exist"
  exit
fi
echo "Tpm simulator state in $XDG_CONFIG_HOME"
echo "Current directory: $(pwd)"

pushd $TPM_SUPPORT_DIR

  echo " "
  echo "start-tpm-simulator"

  swtpm_setup --tpmstate ${XDG_CONFIG_HOME}/mytpm1 --create-ek-cert \
      --create-platform-cert --tpm2 --write-ek-cert-files .

    modprobe tpm_vtpm_proxy
  if [[ $? -eq 0 ]] ; then
    swtpm chardev --vtpm-proxy --tpmstate dir=${XDG_CONFIG_HOME}/mytpm1 \
      --tpm2 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
  else
    swtpm socket --tpmstate dir=${XDG_CONFIG_HOME}/mytpm1--tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init,startup-clear --log level=20 &
    socat PTY,link=/dev/tpmrm1,raw,echo=0 TCP4:127.0.0.1:2321 &
  fi

  chmod 0777 *.crt || true
popd
#endif

echo "Done"
exit
