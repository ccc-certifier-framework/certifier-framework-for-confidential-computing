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
  echo "start-tpm-simulator"

  export XDG_CONFIG_HOME="/home/jlm/.config"
  echo $XDG_CONFIG_HOME
  echo $(pwd)

  pushd $XDG_CONFIG_HOME/mytpm1
    rm ./*
    rm ./.lock
  popd

  modprobe tpm_vtpm_proxy

  swtpm_setup --tpmstate ${XDG_CONFIG_HOME}/mytpm1 --create-ek-cert \
    --create-platform-cert --tpm2 --write-ek-cert-files . --create-platform-cert .

  chmod 0777 *.crt

  swtpm chardev --vtpm-proxy --tpmstate dir=${XDG_CONFIG_HOME}/mytpm1 \
    --tpm2 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear &
popd
#endif

echo "Done"
exit
