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
EXAMPLE_DIR=$(pwd)
echo "Example dir: $EXAMPLE_DIR"
export XDG_CONFIG_HOME="$CERTIFIER_ROOT/swtpm_state"
echo "swtpm state dir: $XDG_CONFIG_HOME"

exit 0 || true

