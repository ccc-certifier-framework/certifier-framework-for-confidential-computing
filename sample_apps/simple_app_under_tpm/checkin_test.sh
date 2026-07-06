#!/bin/bash

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
#    File: checkin_test.sh

if [[ ${CERTIFIER_ROOT+x} ]]; then
  echo "CERTIFIER_ROOT already set"
else
  echo "setting CERTIFIER_ROOT"
  pushd ../.. > /dev/null
    CERTIFIER_ROOT=$(pwd) > /dev/null
  popd > /dev/null
fi

echo "CERTIFIER ROOT: $CERTIFIER_ROOT"
EXAMPLE_DIR=$(pwd)
echo "Example dir: $EXAMPLE_DIR"
export XDG_CONFIG_HOME="$CERTIFIER_ROOT/swtpm_state"
echo "swtpm state dir: $XDG_CONFIG_HOME"

pushd $CERTIFIER_ROOT/src/tpm2
  make -clean -f tpm2_support.mak
  make -f tpm2_support.mak
popd

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

pushd $EXAMPLE_DIR
  if [[ ! -d "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi
  if [[ ! -d "$EXAMPLE_DIR/service" ]] ; then
    mkdir $EXAMPLE_DIR/service
  fi
  if [[ ! -d "$EXAMPLE_DIR/app1_data" ]] ; then
    mkdir $EXAMPLE_DIR/app1_data
  fi
  if [[ ! -d "$EXAMPLE_DIR/app2_data" ]] ; then
    mkdir $EXAMPLE_DIR/app2_data
  fi

  # These tests run on my machine but ...
  exit 0

  rm ekchain.bin quote_hierarchy.bin seal_hierarchy.bin || true
  rm ./app1_data/* ./app2_data/* ./service/* ./provisioning/* || true
  ./prepare-test.sh all dom0

  ./clean-tpm-simulator.sh || true
  ./start-tpm-simulator.sh
  echo "simulator started"
  sleep 2

  ../../src/tpm2/tpm2_set_pcrs.exe --pcr_num=7 --num_pcrs=1 --tpm_device=/dev/tpmrm1
  ./first-pass.sh dom0 1
  cp measurement ./provisioning
  chmod 0777 measurement ./provisioning/measurement
  chmod 0777 ./provisioning/quote_cert.crt

  ./final-prep.sh dom0
  sleep 3
  ./run-init-apps.sh run dom0
  sleep 3
  ./run-server-app.sh dom0 &
  sleep 3
  ./run-client-app.sh dom0

  ./clean-tpm-simulator.sh || true
  echo "done"
popd
