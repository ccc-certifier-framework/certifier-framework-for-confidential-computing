#!/bin/bash
# ##############################################################################
# run_example.sh - Driver script to build things needed to run sample-apps
# ##############################################################################

set -Eeuo pipefail

# Setup script globals, to establish curdir and root path to Certifier code base
Me=$(basename "$0")

# Establish full dirpath where this script lives
pushd "$(dirname "$0")" > /dev/null 2>&1
EXAMPLE_DIR=$(pwd); export EXAMPLE_DIR
popd > /dev/null 2>&1

Cleanup="${EXAMPLE_DIR}/cleanup.sh"
PROV_DIR="${EXAMPLE_DIR}/provisioning"

# shellcheck disable=SC2046
CERT_PROTO="$(dirname $(dirname "$EXAMPLE_DIR"))"; export CERT_PROTO
CERT_UTILS="${CERT_PROTO}/utilities"
ExName=$(basename "$EXAMPLE_DIR")

MeMsg="Build and run example program ${ExName}"

# Script global symbols to app-data dirs
Client_app_data="./app1_data/"
Srvr_app_data="./app2_data/"

SimpleServer_PID=0
Found_step=0        # While looking thru Steps[] for user-specified fn-name

# build_utilites needs access to OpenSSL libraries, that may live on a diff
# dir location, depending on how OpenSSL was installed on diff machines.
# User can over-ride our default by specifying LOCAL_LIB env-var
Local_lib_path=${LOCAL_LIB:-/usr/local/lib64}

# ###########################################################################
# Set trap handlers for all errors. Needs -E (-o errtrace): Ensures that ERR
# traps (see below) get inherited by functions, command substitutions, and
# subshell environments
# Ref: https://citizen428.net/blog/bash-error-handling-with-trap/
#
function cleanup() {
    set +x
    echo "${Me}: Failed command, ${BASH_COMMAND}, at line $(caller) while executing function ${This_fn}"

    do_cleanup
}

# ###########################################################################
# Calls the cleanup sub-script, which cleans up and returns 0 (always)
# This avoids this script failing with non-zero $rc when stale stuff is cleaned up.
function do_cleanup() {
    ${Cleanup} $$
}
trap cleanup ERR

# ##################################################################
# Print help / usage
# ##################################################################
function usage() {

   echo "You can use this script to ${MeMsg}.

   - Setup and execute the example program.
   - List the individual steps needed to setup the example program.
   - Run individual step in sequence.
"

   # Computed elapsed hours, mins, seconds from total elapsed seconds
   echo "Usage: $Me [--help | --list]"
   echo "  To run the example program          : ./${Me}"
   echo "  To setup the example program        : ./${Me} setup"
   echo "  To run and test the example program : ./${Me} run_test"
   echo "  To list the individual steps        : ./${Me} --list"
   echo "  To run an individual step           : ./${Me} <step name>"
}

# ###########################################################################
# Dump the list of functions, one for each step, that user can invoke.
# Ref: https://www.freecodecamp.org/news/bash-array-how-to-declare-an-array-of-strings-in-a-bash-script/
# ###########################################################################
Steps=( "rm_non_git_files"
        "show_env"
        "do_cleanup"
        "build_utilities"
        "gen_policy_and_self_signed_cert"
        "emded_policy_in_example_app"
        "compile_app"
        "get_measurement_of_trusted_app"
        "author_policy"
        "construct_policyKey_platform_is_trusted"
        "construct_policyKey_measurement_is_trusted"
        "combine_policy_stmts"
        "print_policy"
        "construct_platform_key_attestation_stmt_sign_it"
        "print_signed_claim"
        "build_simple_server"
        "mk_dirs_for_test"
        "provision_app_service_files"
        "start_certifier_service"
        "run_app_as_server_talk_to_Cert_Service"
        "run_app_as_client_talk_to_Cert_Service"
        "run_app_as_server_offers_trusted_service"
        "run_app_as_client_make_trusted_request"
)

function list_steps() {
    echo "List of individual steps you can execute, in this order:"
    echo
    for str in "${Steps[@]}"; do
        echo "  ${str}"
    done
}

# ###########################################################################
# Validate that a user-specified 'step'-function-name is valid in Steps[] array.
# Although this wants to be a boolean function, we can't return 1 for success
# as the is being run with -Eo pipefail at the top. Return 0 for success.
# ###########################################################################
function is_valid_step() {
    local fn="$1"
    # Special-case setup and run-test functions
    if [ "${fn}" == "setup" ] || [ "${fn}" == "run_test" ]; then
        Found_step=1
        return
    fi

    for i in "${!Steps[@]}"; do
        if [ "${fn}" == "${Steps[$i]}" ]; then
            Found_step=1
            return
        fi
    done
    Found_step=0
    return
}

# 'Globals' to track who's calling run_cmd
Prev_fn=""
This_fn=""

# ###########################################################################
# Wrapper to run a command w/ parameters.
# ###########################################################################
function run_cmd() {
   echo
   This_fn="${FUNCNAME[1]}"
   if [ "${Prev_fn}" != "${This_fn}" ]; then
       echo "******************************************************************************"
       echo "${Me}: Running ${FUNCNAME[1]} "
       echo
       Prev_fn="${This_fn}"
   fi
   set -x

   "$@"

   set +x
}

# ###########################################################################
# Deep-clean the build-env to remove artifacts (e.g. generated files, binaries
# etc.) that may have been produced by other steps. We run this to ensure
# that this script will run successfully w/o any dependencies on executing
# some prior steps.
# ###########################################################################
function rm_non_git_files() {
    pushd "${CERT_PROTO}" > /dev/null 2>&1

    echo "${Me}: Delete all files not tracked by git"
    # shellcheck disable=SC2046
    run_cmd rm -rf $(git ls-files . --exclude-standard --others)

    echo "${Me}: Delete all files not tracked by git that are also ignored"
    # shellcheck disable=SC2046
    run_cmd rm -rf $(git ls-files . --exclude-standard --others --ignored)

    popd > /dev/null 2>&1
}

# ###########################################################################
function build_utilities() {
   pushd "${CERT_PROTO}/utilities" > /dev/null 2>&1

   clean_done=0
   for mkf in cert_utility.mak policy_utilities.mak;
   do
      if [ "${clean_done}" -eq 0 ]; then
         run_cmd make -f ${mkf} clean
         clean_done=1
      fi
      LOCAL_LIB=${Local_lib_path} run_cmd make -f ${mkf}
   done

   popd > /dev/null 2>&1
}

# ###########################################################################
function gen_policy_and_self_signed_cert() {
   pushd "${PROV_DIR}" > /dev/null 2>&1

   run_cmd "$CERT_UTILS"/cert_utility.exe                       \
               --operation=generate-policy-key-and-test-keys    \
               --policy_key_output_file=policy_key_file.bin     \
               --policy_cert_output_file=policy_cert_file.bin   \
               --platform_key_output_file=platform_key_file.bin \
               --attest_key_output_file=attest_key_file.bin

   popd > /dev/null 2>&1
}

# ###########################################################################
function emded_policy_in_example_app() {
   pushd "${PROV_DIR}" > /dev/null 2>&1

   run_cmd "$CERT_UTILS"/embed_policy_key.exe   \
               --input=policy_cert_file.bin     \
               --output=../policy_key.cc

   popd > /dev/null 2>&1
}

# ###########################################################################
# Do some cleanup of previously-generated protobuf-files. We are using a
# specific 'protoc' compiler in this 'make' step below (enclave/Makefile).
# It's likely that protobuf files generated while building the utilities
# could be incompatible in format with the hard-coded version of protoc
# used in this step.
# ###########################################################################
function compile_app() {
   pushd "${CERT_UTILS}" > /dev/null 2>&1

   run_cmd rm -rf certifier.pb.cc
   cd ../include
   run_cmd rm -rf certifier.pb.h

   popd > /dev/null 2>&1

   pushd "${EXAMPLE_DIR}" > /dev/null 2>&1

   run_cmd make
   run_cmd make dump_mrenclave

   popd > /dev/null 2>&1
}

# ###########################################################################
# Obtain the measurement of the trusted application for the security domain.
# ###########################################################################
function get_measurement_of_trusted_app() {
   pushd "${PROV_DIR}" > /dev/null 2>&1

   run_cmd "$CERT_UTILS"/measurement_utility.exe    \
               --type=hash                          \
               --input=../example_app.exe           \
               --output=example_app.measurement

   popd > /dev/null 2>&1
}

# ###########################################################################
# Author the policy for the security domain and produce the signed claims
# that the apps need. This is just a wrapper function to drive the execution
# of sub-steps, each of which is implemented by a minion function.
# ###########################################################################
function author_policy() {
    pushd "${PROV_DIR}" > /dev/null 2>&1

    construct_policyKey_platform_is_trusted

    construct_policyKey_measurement_is_trusted

    combine_policy_stmts

    print_policy

    construct_platform_key_attestation_stmt_sign_it

    print_signed_claim

    popd > /dev/null 2>&1
}

# ###########################################################################
# Construct policy key says platformKey is-trused-for-attestation
# ###########################################################################
function construct_policyKey_platform_is_trusted() {
   pushd "${PROV_DIR}" > /dev/null 2>&1

   run_cmd "${CERT_UTILS}"/make_unary_vse_clause.exe    \
               --key_subject=platform_key_file.bin      \
               --verb="is-trusted-for-attestation"      \
               --output=ts1.bin

   run_cmd "${CERT_UTILS}"/make_indirect_vse_clause.exe \
               --key_subject=policy_key_file.bin        \
               --verb="says"                            \
               --clause=ts1.bin                         \
               --output=vse_policy1.bin

   run_cmd "${CERT_UTILS}"/make_signed_claim_from_vse_clause.exe    \
               --vse_file=vse_policy1.bin                           \
               --duration=9000                                      \
               --private_key_file=policy_key_file.bin               \
               --output=signed_claim_1.bin

   popd > /dev/null 2>&1
}

# ###########################################################################
# Construct policy key says measurement is-trusted
# ###########################################################################
function construct_policyKey_measurement_is_trusted() {
   pushd "${PROV_DIR}" > /dev/null 2>&1

   run_cmd "${CERT_UTILS}"/measurement_utility.exe  \
               --type=hash                          \
               --input=../example_app.exe           \
               --output=example_app.measurement

   run_cmd "${CERT_UTILS}"/make_unary_vse_clause.exe            \
               --key_subject=""                                 \
               --measurement_subject=example_app.measurement    \
               --verb="is-trusted"                              \
               --output=ts2.bin

   run_cmd "${CERT_UTILS}"/make_indirect_vse_clause.exe     \
               --key_subject=policy_key_file.bin            \
               --verb="says"                                \
               --clause=ts2.bin                             \
               --output=vse_policy2.bin

   run_cmd "${CERT_UTILS}"/make_signed_claim_from_vse_clause.exe    \
               --vse_file=vse_policy2.bin                           \
               --duration=9000                                      \
               --private_key_file=policy_key_file.bin               \
               --output=signed_claim_2.bin

   popd > /dev/null 2>&1
}

# ###########################################################################
# Combine signed policy statements for Certifier Service use.
# ###########################################################################
function combine_policy_stmts() {
   pushd "${PROV_DIR}" > /dev/null 2>&1

   run_cmd "${CERT_UTILS}"/package_claims.exe                   \
               --input=signed_claim_1.bin,signed_claim_2.bin    \
               --output=policy.bin

   popd > /dev/null 2>&1
}

# ###########################################################################
# Print the policy (Optional)
# ###########################################################################
function print_policy() {
   pushd "${PROV_DIR}" > /dev/null 2>&1

   run_cmd "${CERT_UTILS}"/print_packaged_claims.exe --input=policy.bin

   popd > /dev/null 2>&1
}

# ###########################################################################
# Construct statement:
# "platform-key says attestation-key is-trusted-for-attestation"
# and sign it
# ###########################################################################
function construct_platform_key_attestation_stmt_sign_it() {
   pushd "${PROV_DIR}" > /dev/null 2>&1

   run_cmd "${CERT_UTILS}"/make_unary_vse_clause.exe    \
               --key_subject=attest_key_file.bin        \
               --verb="is-trusted-for-attestation"      \
               --output=tsc1.bin

   run_cmd "${CERT_UTILS}"/make_indirect_vse_clause.exe     \
               --key_subject=platform_key_file.bin          \
               --verb="says"                                \
               --clause=tsc1.bin                            \
               --output=vse_policy3.bin

   run_cmd "${CERT_UTILS}"/make_signed_claim_from_vse_clause.exe    \
               --vse_file=vse_policy3.bin                           \
               --duration=9000                                      \
               --private_key_file=platform_key_file.bin             \
               --output=platform_attest_endorsement.bin

   popd > /dev/null 2>&1
}

# ###########################################################################
# Print signed claim (Optional)
# ###########################################################################
function print_signed_claim() {
   pushd "${PROV_DIR}" > /dev/null 2>&1

   run_cmd "${CERT_UTILS}"/print_signed_claim.exe   \
               --input=platform_attest_endorsement.bin

   popd > /dev/null 2>&1
}

# ###########################################################################
# Build SimpleServer: You should have gotten the protobuf compiler (protoc)
# for Go, while installing 'go'. Otherwise, do:
#   $ go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
# ###########################################################################
function build_simple_server() {
    pushd "${CERT_PROTO}" > /dev/null 2>&1

    # Compiler the protobuf
    cd certifier_service/certprotos
    run_cmd protoc                              \
                --go_opt=paths=source_relative  \
                --go_out=.                      \
                --go_opt=M=certifier.proto ./certifier.proto

    # Compile the oelib for OE host verification
    # Likely, user does not have OE SDK installed or does not want to enable OE:
    # This should produce a go file for the certifier protobufs
    # called certifier.pb.go in certprotos.
    cd "${CERT_PROTO}"/certifier_service/oelib
    run_cmd make dummy

    cd "${CERT_PROTO}"/certifier_service/graminelib
    run_cmd make dummy

    # Now, build simpleserver:
    cd "${CERT_PROTO}"/certifier_service
    rm -rf simpleserver
    run_cmd go build simpleserver.go

    popd > /dev/null 2>&1
}

# ###########################################################################
# Re-create dirs for app and service data
# ###########################################################################
function mk_dirs_for_test() {
    pushd "${EXAMPLE_DIR}" > /dev/null 2>&1

    run_cmd rm -rf app1_data app2_data service
    run_cmd mkdir  app1_data app2_data service

    popd > /dev/null 2>&1
}

# ###########################################################################
# Provision the app and service files
# Note: These files are required for the "simulated-enclave" which cannot measure
# the example app and needs a provisioned attestation key and platform cert.
# On real hardware, these are not needed.
# ###########################################################################
function provision_app_service_files() {
    pushd "${PROV_DIR}" > /dev/null 2>&1

    run_cmd cp -p ./* "$EXAMPLE_DIR"/app1_data
    run_cmd cp -p ./* "$EXAMPLE_DIR"/app2_data

    run_cmd cp -p policy_key_file.bin policy_cert_file.bin policy.bin \
                    "$EXAMPLE_DIR"/service

    popd > /dev/null 2>&1
}

# ###########################################################################
# Start the Certifier Service: This will need to be killed manually.
# ###########################################################################
function start_certifier_service() {
    pushd "${EXAMPLE_DIR}"/service > /dev/null 2>&1

    echo
    outfile="${PROV_DIR}/cert.service.out"
    echo "$Me: Starting Certifier Service ..."
    echo "$Me: To see messages from Certifier Server: tail -f ${outfile}"

    run_cmd "${CERT_PROTO}"/certifier_service/simpleserver  \
                --policyFile=policy.bin                     \
                --readPolicy=true                           \
                > "${outfile}" 2>&1 &

    popd > /dev/null 2>&1
    sleep 5

    echo "$Me: Kill this server process when the test is completed."
    # shellcheck disable=SC2009
    ps -ef | grep simpleserver | grep -v grep

    SimpleServer_PID=$(pgrep simpleserver)
}

# ###########################################################################
# Run the app as server and get admission certificates from Certifier Service
# ###########################################################################
function run_app_as_server_talk_to_Cert_Service() {
    pushd "${EXAMPLE_DIR}" > /dev/null 2>&1

    run_cmd "${EXAMPLE_DIR}"/example_app.exe                    \
                --data_dir="${Srvr_app_data}"                   \
                --operation=cold-init                           \
                --measurement_file="example_app.measurement"    \
                --policy_store_file=policy_store                \
                --print_all=true

    run_cmd sleep 1

    run_cmd "${EXAMPLE_DIR}"/example_app.exe                    \
                --data_dir="${Srvr_app_data}"                   \
                --operation=get-certifier                       \
                --measurement_file="example_app.measurement"    \
                --policy_store_file=policy_store                \
                --print_all=true

    popd > /dev/null 2>&1
}

# ###########################################################################
# Run the app as client and get admission certificates from Certifier Service
# In a manual demo: Open two new terminals (one for the app as a client and
# one for the app as a server):
# ###########################################################################
function run_app_as_client_talk_to_Cert_Service() {
    pushd "${EXAMPLE_DIR}" > /dev/null 2>&1

    run_cmd "${EXAMPLE_DIR}"/example_app.exe                    \
                --data_dir="${Client_app_data}"                 \
                --operation=cold-init                           \
                --measurement_file="example_app.measurement"    \
                --policy_store_file=policy_store                \
                --print_all=true

    run_cmd sleep 1

    run_cmd "${EXAMPLE_DIR}"/example_app.exe                    \
                --data_dir="${Client_app_data}"                 \
                --operation=get-certifier                       \
                --measurement_file="example_app.measurement"    \
                --policy_store_file=policy_store                \
                --print_all=true

    popd > /dev/null 2>&1
}

# ###########################################################################
# Run the apps to test trusted services. This is a two-part exercise:
#  - run_app_as_server_trusted_service()
#  - run_app_as_client_make_trusted_request()
# ###########################################################################
function run_app_as_server_offers_trusted_service() {
    pushd "${EXAMPLE_DIR}" > /dev/null 2>&1

    # Run app as a server: In app as a server terminal run the following:
    run_cmd "${EXAMPLE_DIR}"/example_app.exe        \
                --data_dir="${Srvr_app_data}"       \
                --operation=run-app-as-server       \
                --policy_store_file=policy_store    \
                --print_all=true &

    run_cmd sleep 5

    popd > /dev/null 2>&1

    # Report this, for debugging on CI-machines
    echo "${Me}: $(TZ="America/Los_Angeles" date) $(pwd) Completed ${FUNCNAME[0]}"
}

# ###########################################################################
# Run the app-as-a-trusted client sending request to trusted server:
# ###########################################################################
function run_app_as_client_make_trusted_request() {
    pushd "${EXAMPLE_DIR}" >/dev/null 2>&1

    # Run app as a client: In app as a client terminal run the following:
    run_cmd "${EXAMPLE_DIR}"/example_app.exe        \
                --data_dir="${Client_app_data}"     \
                --operation=run-app-as-client       \
                --policy_store_file=policy_store    \
                --print_all=true

    popd > /dev/null 2>&1
    # Report this, for debugging on CI-machines
    echo "${Me}: $(TZ="America/Los_Angeles" date) $(pwd) Completed ${FUNCNAME[0]}"
}

# ###########################################################################
function show_env() {
   echo "Environment variables, script globals:"
   env | grep -E "CERT_PROTO|EXAMPLE_DIR"
   echo "LOCAL_LIB=${Local_lib_path}"

   local numCPUs=0
   local cpuModel=0
   local cpuVendor=0
   local totalMemGB=0

   numCPUs=$(grep -c "^processor" /proc/cpuinfo)
   cpuModel=$(grep "model name" /proc/cpuinfo | head -1 | cut -f2 -d':')
   cpuVendor=$(grep "vendor_id" /proc/cpuinfo | head -1 | cut -f2 -d':')
   totalMemGB=$(free -g | grep "^Mem:" | awk '{print $2}')

    echo
    uname -a
    echo
    echo "${Me}: ${cpuVendor}, ${numCPUs} CPUs, ${totalMemGB} GB, ${cpuModel}"
    ping -4 -c 1 "$(uname -n | head -2)"

    echo
    lsb_release -a
}


# ###########################################################################
# Execute a list of steps starting from: from_step, to: to_step, both inclusive
# ###########################################################################
function run_steps() {
    local from_step="$1"
    local to_step="$2"

    local do_exec=0
    for i in "${!Steps[@]}"; do
        if [ "${Steps[$i]}" == "${from_step}" ]; then
            do_exec=1
        fi
        # Execute this new step as it's within range of [from, to]
        if [ ${do_exec} -eq 1 ]; then
            # shellcheck disable=SC2048
            ${Steps[$i]}
        fi

        # We are done executing the last step
        if [ "${Steps[$i]}" == "${to_step}" ]; then
            do_exec=0
            break
        fi
    done
}

# ###########################################################################
# Do initial setup of the sample app test-case
# ###########################################################################
function setup() {
    run_steps "show_env" "provision_app_service_files"
}

# ###########################################################################
# After setup is done, run-the-test, setting up Cert Service etc.
# ###########################################################################
function run_test() {
    run_steps "start_certifier_service" "run_app_as_client_make_trusted_request"
}

# ##################################################################
# main() begins here
# ##################################################################

# Simple command-line arg processing. Expect just one arg, if any.
if [ $# -eq 1 ]; then
    if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        usage
        exit 0
    fi
    if [ "$1" == "--list" ]; then
        list_steps
        exit 0
    fi

    # Execute a user-supplied name of a function implementing a step.
    # If a wrong name was supplied, we will error out.
    is_valid_step "$1"
    if [ "${Found_step}" == "0" ]; then
        echo "${Me}: Invalid step name provided: $1"
        exit 1
    fi
    # Else, it's a valid step / function name. Execute it.
    # shellcheck disable=SC2048
    $1
    exit 0
fi

echo "${Me}: $(TZ="America/Los_Angeles" date) ${MeMsg}"

if [ ! -d "${PROV_DIR}" ]; then mkdir "${PROV_DIR}"; fi

# Run through the list of steps as arranged in Steps[] sequence
# for str in "${Steps[@]}"; do
#     ${str}
# done

#  For a full end2end run, also clean-up build-env of stale artifacts
rm_non_git_files
setup

run_test

# Cleanup running processes ...
trap "" ERR

# shellcheck disable=SC2086
if [ ${SimpleServer_PID} -ne 0 ]; then kill -9 "${SimpleServer_PID}"; fi

echo "${Me}: $(TZ="America/Los_Angeles" date) $(pwd) Completed."
