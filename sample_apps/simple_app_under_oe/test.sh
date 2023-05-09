#!/bin/bash
# ##############################################################################
# test.sh: Execute build-and-test of simple_app_under_oe with diff arguments
# NOTE: If needed, specify the location of your OpenSSL libraries when
#       running this script, as: LOCAL_LIB=/usr/local/lib64 ./test.sh
# ##############################################################################

set -Eeuo pipefail

Me=$(basename "$0")

pushd "$(dirname "$0")" > /dev/null 2>&1
AppName=$(basename "$(pwd)")
popd > /dev/null 2>&1

echo "**** ${Me}: Basic build-and-test exercise. ${AppName} ****"

../cleanup.sh
../run_example.sh rm_non_git_files
../run_example.sh "${AppName}"

echo "**** ${Me}: Basic setup and run_test exercise. ${AppName} ****"

../cleanup.sh
../run_example.sh rm_non_git_files
../run_example.sh "${AppName}" setup
../run_example.sh "${AppName}" run_test

echo "**** ${Me}: Basic setup with auto-policy-generation and run_test exercise. ${AppName} ****"

../cleanup.sh
../run_example.sh rm_non_git_files
../run_example.sh "${AppName}" setup_with_auto_policy_generation_for_OE
../run_example.sh "${AppName}" run_test
