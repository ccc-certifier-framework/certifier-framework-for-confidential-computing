#!/bin/bash

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
#    File: checkin_test.sh


set -e

# reset defines as root
if [[ -n "${CERTIFIER_ROOT+x}" ]] ; then
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

# compile
pushd $TPM_SUPPORT_DIR >> /dev/null
  make clean -f tpm2_support.mak
  make -f tpm2_support.mak
popd >> /dev/null

# Should be root
  set +e
  if [[ "$(id -u)" -ne 0 ]]; then
     echo "Must be root, exiting"
     exit 1
  fi

  if [[ ! -d "$XDG_CONFIG_HOME" ]] ; then
     echo ""
     echo "making simulator state directories"
     mkdir $XDG_CONFIG_HOME || true
     mkdir $XDG_CONFIG_HOME/mytpm1 || true
     chmod 0777 $XDG_CONFIG_HOME || true
     chmod 0777 $XDG_CONFIG_HOME/mytpm1 || true
     ls -l $CERTIFIER_ROOT || true
     ls -l $XDG_CONFIG_HOME || true
     echo "simulator state directories made"
  else
     echo "simulator state directories exist"
  fi

  set -e
  if [[ ! -d "$XDG_CONFIG_HOME" ]] ; then
    echo "Tpm state dir $XDG_CONFIG_HOME does not exist"
    return 1
  fi

  pushd $TPM_SUPPORT_DIR
    echo "TPM tests"
    ./clean-tpm-simulator.sh || true
    ./start-tpm-simulator.sh || true
    sleep 2
    ./tpm2_set_pcrs.exe --pcr_num=7 --num_pcrs=1 --tpm_device=/dev/tpmrm1
    ./tpm2_test.exe --operation=EndorsementTest --tpm_device=/dev/tpmrm1

    # These work on my machine
    #sleep 2
    #echo "seal test"
    #./tpm2_test.exe --operation=SealTest --tpm_device=/dev/tpmrm1
    #sleep 2
    #echo "quote test"
    #./tpm2_test.exe --operation=QuoteTest --tpm_device=/dev/tpmrm1

    ./clean-tpm-simulator.sh || true
  popd
