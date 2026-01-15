#!/bin/bash

# ############################################################################
# cleanup.sh
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# ------------------------------------------------------------------------------------------


function cleanup-stale-procs() {
	# Find and kill simpleserver processes that may be running.
	echo " "
	echo "cleanup-stale-procs"

	set +e
	certifier_pid=$(ps -ef | grep -E "simpleserver" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
	set -e
	if [[ $certifier_pid != "" ]] ; then
		kill -9 $certifier_pid
		echo "killed certifier_service, pid $certifier_pid"
	else
		echo "no certifier_service running"
	fi

	key_server_pid=$(ps -ef | grep -E "cf_key_server" | grep -v -w -E 'grep|vi|vim' | awk '{print $2}')
	set -e
	if [[ $key_server_pid != "" ]] ; then
		kill -9 $key_server_pid
		echo "killed key_server_service, pid $key_server_pid"
	else
		echo "no key_server_service running"
	fi
	echo "cleanup-stale-procs done"
	echo " "
}

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then
        print-variables
fi

echo " "
echo "cleaning stale procs"
cleanup-stale-procs
echo "cleaned stale procs"
echo " "
