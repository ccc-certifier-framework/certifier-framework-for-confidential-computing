#
#    Copyright 2026 John Manferdelli, All Rights Reserved.
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#       http://www.apache.org/licenses/LICENSE-2.0
#    or in the the file LICENSE-2.0.txt in the top level sourcedirectory
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License
#    File: tpm2_support.mak


if [[ ${CERTIFIER_ROOT+x} ]]; then
  echo "CERTIFIER_ROOT already set"
else
  echo "setting CERTIFIER_ROOT"
  pushd ../.. > /dev/null
    CERTIFIER_ROOT=$(pwd) > /dev/null
  popd > /dev/null
fi
echo "CERTIFIER ROOT: $CERTIFIER_ROOT"
export TPM_SUPPORT_DIR=$CERTIFIER_ROOT/src/tpm2
echo "Tpm support dir: $TPM_SUPPORT_DIR"
export XDG_CONFIG_HOME="$CERTIFIER_ROOT/swtpm_state"
echo "swtpm state dir: $XDG_CONFIG_HOME"

set -e 
# compile
pushd $TPM_SUPPORT_DIR >> /dev/null
  make clean -f tpm2_support.mak
  make -f tpm2_support.mak
popd >> /dev/null

sudo bash

# reset defines as root
if [[ ${CERTIFIER_ROOT+x} ]]; then
  echo "CERTIFIER_ROOT already set"
else
  echo "setting CERTIFIER_ROOT"
  pushd ../.. >> /dev/null
    CERTIFIER_ROOT=$(pwd) > /dev/null
  popd >> /dev/null
fi
echo "CERTIFIER ROOT: $CERTIFIER_ROOT"
export TPM_SUPPORT_DIR=$CERTIFIER_ROOT/src/tpm2
echo "Tpm support dir: $TPM_SUPPORT_DIR"
XDG_CONFIG_HOME=$CERTIFIER_ROOT/swtpm_state
echo "swtpm state: $XDG_CONFIG_HOME"

set +e
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (or with sudo)." >&2
    return 1
fi

if [[ ! -e "$XDG_CONFIG_HOME" ]] ; then
  pushd $CERTIFIER_ROOT
    if [[ ! -e "$XDG_CONFIG_HOME" ]] ; then
       echo ""
       echo "making simulator state directories"
       sudo mkdir $XDG_CONFIG_HOME
       sudo mkdir $XDG_CONFIG_HOME/mytpm1
       sudo chmod 0777 $XDG_CONFIG_HOME
       sudo chmod 0777 $XDG_CONFIG_HOME/mytpm1
       sudo ls -l $CERTIFIER_ROOT
       sudo ls -l $XDG_CONFIG_HOME
       echo "simulator state directories made"
    else
       echo "simulator state directories exist"
    fi
  popd
fi
set -e
if [[ ! -e "$XDG_CONFIG_HOME" ]] ; then
  echo "Couldn't make tpm state dir"
  return 1
fi

pushd $TPM_SUPPORT_DIR
  ./clean-tpm-simulator.sh || true
  ./start-tpm-simulator.sh || true

  ./tpm2_set_pcrs.exe --pcr_num=7 --num_pcrs=1 --tpm_device=/dev/tpmrm1
  ./tpm2_test.exe --operation=MiscTest --tpm_device=/dev/tpmrm1
  ./tpm2_test.exe --operation=GetCert --tpm_device=/dev/tpmrm1
  ./tpm2_test.exe --operation=EndorsementTest --tpm_device=/dev/tpmrm1
  ./tpm2_test.exe --operation=SealTest --tpm_device=/dev/tpmrm1
  ./tpm2_test.exe --operation=QuoteTest --tpm_device=/dev/tpmrm1
  ./clean-tpm-simulator.sh || true
popd

