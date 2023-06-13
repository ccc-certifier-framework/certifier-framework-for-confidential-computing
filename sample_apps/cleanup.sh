#!/bin/bash
# ##############################################################################
#  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# ##############################################################################
# cleanup.sh:
# Helper script to clean-up running processes after a successful / failed
# execution of run_example.sh
#
# Arguments: <pid> of process to not kill (our calling process' pid)
# ##############################################################################

Me=$(basename "$0")

# Init to an illegal value, so we filter out nothing if $1 is not provided
parent_pid=-99999
if [ $# -eq 1 ]; then parent_pid="$1"; fi

Killed_some_procs=0

# ##############################################################################
function cleanup_stale_procs() {

    # Find and kill processes that may be running. We cannot use pgrep to find the
    # pid, and / or use 'pgrep --signal pkill' to kill such processes, because in
    # case the process does not exist, 'pgrep' will exit with $rc=1. This will cause
    # this entire script to abort prematurely before cleanup is finished.
    for procname in simpleserver \
                    example_app.exe \
                    run_example.sh \
                    host \
                    gramine/sgx/loader \
                    sev_example_app.exe \
                    run-app-as-server \
                    run-app-as-client \
                    app_service.exe
    do
        # shellcheck disable=SC2046,SC2009
        if [ $(ps -ef | grep -E "${procname}" \
            | grep -c -v -w -E "grep|vi|vim|${parent_pid}") -ne 0 ];
        then
            echo
            ps -ef | grep -E "${procname}" | grep -v -w -E 'grep|vi|vim'
            # Workaround: Handle procname so pgrep can succeed
            if [ "${procname}" = "gramine/sgx/loader" ]; then
                procname="loader"
            fi
            set -x
            # Somehow this does not work for programs started as root
            # pid=$(pgrep "${procname}")
            pid=$(ps -ef | grep -w "${procname}" \
                        | grep -v -w -E "grep|vi|vim|${parent_pid}" \
                        | awk '{print $2}')

            # shellcheck disable=SC2086
            # kill -9 ${pid}
            kill -s SIGKILL ${pid} || :
            set +x
            Killed_some_procs=1
        fi
    done
}

# shellcheck disable=SC2086
if [ ${parent_pid} -gt 0 ]; then
   echo "${Me}: Cleanup stale processes (parent_pid=${parent_pid}) ..."
fi
cleanup_stale_procs

# To let open sockets be drained etc ... Empirical fix to get stuff running on CI
if [ "${Killed_some_procs}" = "1" ]; then
   echo "${Me}: $(TZ="America/Los_Angeles" date) Completed."
fi
exit 0
