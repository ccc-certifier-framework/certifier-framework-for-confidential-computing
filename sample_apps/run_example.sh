#!/bin/bash
# ##############################################################################
# run_example.sh - Driver script to build things needed to run sample-apps
# ##############################################################################

set -Eeuo pipefail

# Setup script globals, to establish curdir and root path to Certifier code base
Me=$(basename "$0")

SampleAppName="simple_app"
pushd "$(dirname "$0")" > /dev/null 2>&1

# shellcheck disable=SC2046
CERT_PROTO="$(dirname $(pwd))"; export CERT_PROTO

Cleanup="$(pwd)/cleanup.sh"
popd > /dev/null 2>&1

MeMsg="Build and run example program"

# Script global symbols to app-data dirs
Client_app_data="app1_data"
Srvr_app_data="app2_data"

SimpleServer_PID=0
Valid_app=0         # While looking thru SampleApps[] for supported app
Found_step=0        # While looking thru Steps[] for user-specified fn-name
DryRun=0            # --dry-run will turn this ON; off by default
DryRun_msg=""

# build_utilites needs access to OpenSSL libraries, that may live on a diff
# dir location, depending on how OpenSSL was installed on diff machines.
# User can over-ride our default by specifying LOCAL_LIB env-var
Local_lib_path=${LOCAL_LIB:-/usr/local/lib}

# Sub-tools used in this script
Jq=jq    # Needed for OE app; will be established later on.

# --------------------------------------------------------------------------------
# sample_app_under_gramine uses MbedTLS library, which needs to be downloaded.
# And some minor configuration is done as part of setup_MbedTLS(). We want to
# avoid downloading repos frequently, so provide this global variable to
# detect if this dir exists. If so, rm_non_git_files() will do special-case
# handling of these contents.
# --------------------------------------------------------------------------------
MbedTLS_dir="mbedtls"
Simple_App_under_gramine_MbedTLS_dir="sample_apps/simple_app_under_gramine/${MbedTLS_dir}"

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

# List of sample-apps supported, currently
SampleApps=( "simple_app"
             "simple_app_under_oe"
             "simple_app_under_gramine"
           )

# ###########################################################################
function list_apps() {
    echo "List of sample applications you can execute with this script:"
    echo " "
    for str in "${SampleApps[@]}"; do
        echo "  - ${str}"
    done
}

function is_valid_app() {
    local fn="$1"
    for i in "${!SampleApps[@]}"; do
        if [ "${fn}" == "${SampleApps[$i]}" ]; then
            Valid_app=1
            return
        fi
    done
    Valid_app=0
    return
}

# ##################################################################
# Print help / usage
# ##################################################################
function usage_brief() {
    echo "Usage: $Me [-h | --help | --list | --dry-run] <sample-app-name> [ setup | run_test ]"
    list_apps
}

# ---- Generic help/usage output
function usage() {

    echo "You can use this script to ${MeMsg}

   - Setup and execute the example program.
   - List the individual steps needed to setup the example program.
   - Run individual steps in sequence.
"
    usage_brief
    echo " "
    echo "  To setup and run the ${SampleAppName} program, end-to-end : ./${Me} ${SampleAppName} "
    echo "  To setup the ${SampleAppName} program                     : ./${Me} ${SampleAppName} setup"
    echo "  To run and test the ${SampleAppName} program              : ./${Me} ${SampleAppName} run_test"
    echo "  To list the individual steps for ${SampleAppName}         : ./${Me} ${SampleAppName} --list"
    echo "  To run an individual step of the ${SampleAppName}         : ./${Me} ${SampleAppName} <step name>"
    echo " "
    # Indentation to align with previous output lines.
    echo "  Cleanup stale artifacts from build area             : ./${Me} rm_non_git_files"
    echo "  Show the environment used to build-and-run a program: ./${Me} ${SampleAppName} show_env"

    local test_app="simple_app_under_oe"
    echo " "
    echo "Dry-run execution mode to inspect tasks performed:"
    echo "  Setup and run the simple_app_under_oe program : ./${Me} --dry-run ${test_app}"
    echo "  Setup simple_app_under_oe program             : ./${Me} --dry-run ${test_app} setup"
    echo "  Run and test the simple_app_under_oe program  : ./${Me} --dry-run ${test_app} run_test"
    echo "  Cleanup stale artifacts from build area       : ./${Me} --dry-run rm_non_git_files"
}

# ---- Open-Enclave app-specific help/usage output
function usage_OE() {
    echo " "
    echo "For simple_app_under_oe, you can alternatively use this script "
    echo "to generate the policy by editing the measurement in the policy JSON file:"
    echo "  To setup the example program        : ./${Me} simple_app_under_oe setup_with_auto_policy_generation_for_OE"
    echo "  To run and test the example program : ./${Me} simple_app_under_oe run_test"
}

# ###########################################################################
# Dump the list of functions, one for each step, that user can invoke.
# Ref: https://www.freecodecamp.org/news/bash-array-how-to-declare-an-array-of-strings-in-a-bash-script/
# ###########################################################################
Steps=( "rm_non_git_files"

        # 'setup' argument starts from here:
        "show_env"
        "do_cleanup"
        "build_utilities"
        "gen_policy_and_self_signed_cert"
        "emded_policy_in_example_app"
        "compile_app"
        "get_measurement_of_trusted_app"

        "author_policy"
            # These sub-step fns are subsumed under author_policy()
            "construct_policyKey_platform_is_trusted"
            "produce_signed_claims_for_vse_policy_statement"
            "construct_policyKey_measurement_is_trusted"
            "combine_policy_stmts"
            "print_policy"
            "construct_platform_key_attestation_stmt_sign_it"
            "print_signed_claim"

        "build_simple_server"
        "mk_dirs_for_test"
        "provision_app_service_files"
        # 'setup' argument ends here.

        # 'run_test' argument starts from here:
        "start_certifier_service"
        "run_app_as_server_talk_to_Cert_Service"
        "run_app_as_client_talk_to_Cert_Service"
        "run_app_as_server_offers_trusted_service"
        "run_app_as_client_make_trusted_request"
)

Steps_OE=( "rm_non_git_files"

           # 'setup' argument starts from here:
           "show_env"
           "do_cleanup"
           "build_utilities"
           "gen_policy_and_self_signed_cert"
           "emded_policy_in_example_app"
           "compile_app"
           "get_measurement_of_trusted_app"

           # --------------------------------------------------------------
           # If user is running individual steps, they have to run
           #  - either manual_policy_generation_for_OE,
           #  - or     automated_policy_generation_for_OE
           "manual_policy_generation_for_OE"
              # These sub-step fns are subsumed under author_policy()
              "construct_policyKey_platform_is_trusted"
              "produce_signed_claims_for_vse_policy_statement"
              "combine_policy_stmts"
              "print_policy"

           "automated_policy_generation_for_OE"
              # These sub-step fns are subsumed under automated_policy_generation_for_OE()
              "edit_policy_file_OE"
              "build_policy_generator_OE"
              "run_policy_generator_OE"

           "build_simple_server"
           "mk_dirs_for_test"
           "provision_app_service_files"
           # 'setup' argument ends here.

           # Special-case interface to invoke automated_policy_generation_for_OE()"
           "setup_with_auto_policy_generation_for_OE"

           # 'run_test' argument starts from here:
           "start_certifier_service"
           "run_app_as_server_talk_to_Cert_Service"
           "run_app_as_client_talk_to_Cert_Service"
           "run_app_as_server_offers_trusted_service"
           "run_app_as_client_make_trusted_request"
)

# --------------------------------------------------------------------------
# Driver function to list steps for a given valid app name
function list_steps() {
    local app_name="$1"
    echo "List of individual steps you can execute for ${app_name}, in this order:"
    echo " "
    case "${app_name}" in
        "simple_app")
            list_steps_for_app "${Steps[@]}"
            ;;

        "simple_app_under_oe")
            list_steps_for_app "${Steps_OE[@]}"
            ;;

        "simple_app_under_gramine")
            list_steps_for_app "${Steps[@]}"
            ;;

        *)
            echo "${Me}:${LINENO} Unknown sample app name '${app_name}'."
            return
            ;;
    esac
}

# --------------------------------------------------------------------------
# Minion to print the contents of a step-array passed-in.
# Ref: https://askubuntu.com/questions/674333/how-to-pass-an-array-as-function-argument
function list_steps_for_app() {
    local steps_array=("$@")
    for str in "${steps_array[@]}"; do
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

    case "${SampleAppName}" in
        "simple_app")
            check_steps_for_app "${Steps[@]}"
            ;;

        "simple_app_under_oe")
            check_steps_for_app "${Steps_OE[@]}"
            ;;

        "simple_app_under_gramine")
            check_steps_for_app "${Steps[@]}"
            ;;

        *)
            echo "${Me}:${LINENO} Unknown sample app name '${SampleAppName}'."
            return
            ;;
    esac
}

function check_steps_for_app() {
    local steps_array=("$@")
    for i in "${!steps_array[@]}"; do
        if [ "${fn}" == "${steps_array[$i]}" ]; then
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
    echo " "
    This_fn="${FUNCNAME[1]}"
    if [ "${Prev_fn}" != "${This_fn}" ]; then
        echo "******************************************************************************"
        echo "${Me}: Running ${FUNCNAME[1]} "
        Prev_fn="${This_fn}"
    fi
    # Only execute the commands if --dry-run is OFF
    if [ ${DryRun} -eq 0 ]; then
        set -x

        "$@"

        set +x
    else
        # Print what would have been executed, so user can learn from this.
        echo "$@"
    fi
}

# ###########################################################################
# Wrappers around pushd / popd to also honor --dry-run mode, so user can
# inspect changes to dirs before running various commands.
# ###########################################################################
function run_pushd() {
    local todir="$1"
    if [ ${DryRun} -eq 0 ]; then
        pushd "${todir}" > /dev/null 2>&1
    else
        echo "pushd ${todir}"
    fi
}

function run_popd() {
    if [ ${DryRun} -eq 0 ]; then
        popd > /dev/null 2>&1
    else
        echo        # Blank-line for readability of commands in dry-run mode
        echo "popd"
    fi
}

# ###########################################################################
# Deep-clean the build-env to remove artifacts (e.g. generated files, binaries
# etc.) that may have been produced by other steps. We run this to ensure
# that this script will run successfully w/o any dependencies on executing
# some prior steps.
# ###########################################################################
function rm_non_git_files() {
    run_cmd
    run_pushd "${CERT_PROTO}"

    local MbedTLS_dir_exists=0
    # Use full dir-path so this works cleanly under --dry-run mode, too.
    if [ -d "${CERT_PROTO}/${Simple_App_under_gramine_MbedTLS_dir}" ]; then
        set -x
        mv "${CERT_PROTO}/${Simple_App_under_gramine_MbedTLS_dir}" /tmp
        set +x
        MbedTLS_dir_exists=1
    fi

    echo "${Me}: Delete all files not tracked by git"

    # shellcheck disable=SC2046
    run_cmd rm -rf $(git ls-files . --exclude-standard --others)

    echo "${Me}: Delete all files not tracked by git that are also ignored"
    # shellcheck disable=SC2046
    run_cmd rm -rf $(git ls-files . --exclude-standard --others --ignored)

    # Restore mbedtls/, if it was saved-off previously.
    if [ ${MbedTLS_dir_exists} -eq 1 ]; then
        set -x
        mv /tmp/${MbedTLS_dir} "${CERT_PROTO}"/${Simple_App_under_gramine_MbedTLS_dir}
        set +x
    fi
    run_popd
}

# ###########################################################################
function build_utilities() {
    run_cmd
    run_pushd "${CERT_PROTO}/utilities"

    clean_done=0
    for mkf in cert_utility.mak policy_utilities.mak;
    do
        if [ "${clean_done}" -eq 0 ]; then
            run_cmd make -f ${mkf} clean
            clean_done=1
        fi
        LOCAL_LIB=${Local_lib_path} run_cmd make -f ${mkf}
    done

    run_popd
}

# ###########################################################################
function gen_policy_and_self_signed_cert() {
    run_cmd
    run_pushd "${PROV_DIR}"

    if [ "${SampleAppName}" = "simple_app_under_gramine" ]; then
       run_cmd "$CERT_UTILS"/cert_utility.exe                       \
                   --operation=generate-policy-key                  \
                   --policy_key_output_file=policy_key_file.bin     \
                   --policy_cert_output_file=policy_cert_file.bin
    else
       run_cmd "$CERT_UTILS"/cert_utility.exe                       \
                   --operation=generate-policy-key-and-test-keys    \
                   --policy_key_output_file=policy_key_file.bin     \
                   --policy_cert_output_file=policy_cert_file.bin   \
                   --platform_key_output_file=platform_key_file.bin \
                   --attest_key_output_file=attest_key_file.bin
    fi

    run_popd
}

# ###########################################################################
function emded_policy_in_example_app() {
    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd "$CERT_UTILS"/embed_policy_key.exe   \
                --input=policy_cert_file.bin     \
                --output=../policy_key.cc

    run_popd
}

# ###########################################################################
# As this function is executed through a table of function names,
# caller cannot pass-in the sample-app-name. So, fall back to using
# a global variable.
function compile_app() {
    compile_"${SampleAppName}"
}

# ###########################################################################
function compile_simple_app() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd make -f example_app.mak clean
    run_cmd make -f example_app.mak

    run_popd
}

# ###########################################################################
function compile_simple_app_under_oe() {
    run_cmd
    run_pushd "${CERT_UTILS}"

    run_cmd rm -rf certifier.pb.cc
    cd ../include
    run_cmd rm -rf certifier.pb.h

    run_popd

    run_pushd "${EXAMPLE_DIR}"

    run_cmd make
    run_cmd make dump_mrenclave

    run_popd
}

# ###########################################################################
function compile_simple_app_under_gramine() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd cp -p "$HOME"/sgx.cert.der .
    run_cmd make -f gramine_example_app.mak clean
    run_cmd make -f gramine_example_app.mak app RA_TYPE=dcap

    # Gramine-app's Makefile target creates a differently-named app, but this
    # script expects a diff name. Create a soft-link to reconcile app-exe names.
    run_cmd rm -rf example_app.exe
    run_cmd ln -s gramine_example_app example_app.exe

    run_popd
}

# ###########################################################################
# Obtain the measurement of the trusted application for the security domain.
# The app-specific sub-functions generate the app's measurement in an output
# file, which will be used downstream to create the policy for the app.
#
# simple_app                : example_app.measurement
# simple_app_under_oe       : binary_trusted_measurements_file.bin
# simple_app_under_gramine  : example_app.measurement
#
# ###########################################################################
function get_measurement_of_trusted_app() {
    run_cmd
    get_measurement_of_trusted_"${SampleAppName}"
}

# ###########################################################################
function get_measurement_of_trusted_simple_app() {
    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd "$CERT_UTILS"/measurement_utility.exe    \
                --type=hash                          \
                --input=../example_app.exe           \
                --output=example_app.measurement

    run_popd
}

# ###########################################################################
function get_measurement_of_trusted_simple_app_under_oe() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

   # Grab mrenclave name from 'dump' output
    local mrenclave="some-hash-string-that-will-come-from-oesign-dump"
    if [ $DryRun -eq 0 ]; then
        set -x
        mrenclave=$(oesign dump --enclave-image=./enclave/enclave.signed \
                    | grep "^mrenclave" \
                    | cut -f2 -d'=')
        set +x
    fi

    run_popd

    run_pushd "${PROV_DIR}"

    run_cmd "$CERT_UTILS"/measurement_init.exe                   \
                --mrenclave="${mrenclave}"                       \
                --out_file=binary_trusted_measurements_file.bin

    run_popd
}

# ###########################################################################
function get_measurement_of_trusted_simple_app_under_gramine() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    # Grab mrenclave name from 'gramine-sgx-sign' output
    local mrenclave="some-hash-string-that-will-come-from-gramine-sgx-sign"

    # 'make' in compile_simple_app_under_gramine() has already run this utility
    # to produce a manifest.sgx output file that will be used elsewhere. We are
    # re-running this utility to grab the measurement. So, provide a tmp-output
    # file so as to not clobber something that has already been generated.
    local sgx_sign_tmp_outfile="gramine_example_app.manifest.sgx.tmp"
    if [ $DryRun -eq 0 ]; then
        set -x
        mrenclave=$(gramine-sgx-sign --manifest gramine_example_app.manifest    \
                                     --output ${sgx_sign_tmp_outfile} \
                        | grep -A2 -E "^Measurement:" | tail -1 | tr -d ' ')
        set +x
    fi
    run_popd

    run_pushd "${PROV_DIR}"

    run_cmd "$CERT_UTILS"/measurement_init.exe                   \
                --mrenclave="${mrenclave}"                       \
                --out_file=example_app.measurement

    run_popd
}

# ###########################################################################
# Author the policy for the security domain and produce the signed claims
# that the apps need. This is just a wrapper function to drive the execution
# of sub-steps, each of which is implemented by a minion function.
#
# If you make changes, verify that the changes apply for the following
# apps that share this function:
#   - simple_app
#   - simple_app_under_gramine
# ###########################################################################
function author_policy() {
    run_cmd
    run_pushd "${PROV_DIR}"

    construct_policyKey_platform_is_trusted

    produce_signed_claims_for_vse_policy_statement

    construct_policyKey_measurement_is_trusted

    combine_policy_stmts

    print_policy

    # RESOLVE: X-check v/s instructions. These steps seem to be n/a for Gramine App
    if [ "${SampleAppName}" = "simple_app" ]; then
        construct_platform_key_attestation_stmt_sign_it

        print_signed_claim
    fi

    run_popd
}

# ###########################################################################
# Step 7 in instructions.md: Manual policy generation
# You run either this step, or Step 8, below.
# Author the policy for the security domain and produce the signed claims
# that the apps need. This is just a wrapper function to drive the execution
# of sub-steps, each of which is implemented by a minion function.
# ###########################################################################
function manual_policy_generation_for_OE() {
    run_cmd
    run_pushd "${PROV_DIR}"

    construct_policyKey_platform_is_trusted

    produce_signed_claims_for_vse_policy_statement

    combine_policy_stmts

    print_policy

    run_popd
}

# ###########################################################################
# Construct policy key says platformKey is-trused-for-attestation
# ###########################################################################
function construct_policyKey_platform_is_trusted() {
    construct_policyKey_platform_is_trusted_"${SampleAppName}"
}

# ###########################################################################
function construct_policyKey_platform_is_trusted_simple_app() {
    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd "${CERT_UTILS}"/make_unary_vse_clause.exe    \
                --key_subject=platform_key_file.bin      \
                --verb="is-trusted-for-attestation"      \
                --output=ts1.bin

    run_cmd "${CERT_UTILS}"/make_indirect_vse_clause.exe \
                --key_subject=policy_key_file.bin        \
                --verb="says"                            \
                --clause=ts1.bin                         \
                --output=vse_policy1.bin

    run_popd
}

# ###########################################################################
function construct_policyKey_platform_is_trusted_simple_app_under_oe() {
    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd "${CERT_UTILS}"/make_unary_vse_clause.exe                       \
                --measurement_subject=binary_trusted_measurements_file.bin  \
                --verb="is-trusted"                                         \
                --output=ts1.bin

    run_cmd "${CERT_UTILS}"/make_indirect_vse_clause.exe \
                --key_subject=policy_key_file.bin        \
                --verb="says"                            \
                --clause=ts1.bin                         \
                --output=vse_policy1.bin

    run_popd
}

# ###########################################################################
function construct_policyKey_platform_is_trusted_simple_app_under_gramine() {
    run_cmd
    run_pushd "${PROV_DIR}"

    # The docs state that this certificate should exist at a known location.
    run_cmd cp -p "$HOME"/sgx.cert.der .
    run_cmd "${CERT_UTILS}"/make_unary_vse_clause.exe   \
                --cert-subject=sgx.cert.der             \
                --verb="is-trusted-for-attestation"     \
                --output=ts1.bin

    run_cmd "${CERT_UTILS}"/make_indirect_vse_clause.exe    \
                --key_subject=policy_key_file.bin           \
                --verb="says"                               \
                --clause=ts1.bin                            \
                --output=vse_policy1.bin
    run_popd
}

# ###########################################################################
function produce_signed_claims_for_vse_policy_statement() {
    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd "${CERT_UTILS}"/make_signed_claim_from_vse_clause.exe    \
                --vse_file=vse_policy1.bin                           \
                --duration=9000                                      \
                --private_key_file=policy_key_file.bin               \
                --output=signed_claim_1.bin

    run_popd
}

# ###########################################################################
# Construct policy key says measurement is-trusted
# ###########################################################################
function construct_policyKey_measurement_is_trusted() {
    run_cmd
    run_pushd "${PROV_DIR}"

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

    run_popd
}

# ###########################################################################
# Combine signed policy statements for Certifier Service use.
# ###########################################################################
function combine_policy_stmts() {
    run_cmd
    run_pushd "${PROV_DIR}"

    signed_claims="signed_claim_1.bin"
    case "${SampleAppName}" in
        "simple_app" | "simple_app_under_gramine")
            signed_claims="${signed_claims},signed_claim_2.bin"
            ;;
    esac
    run_cmd "${CERT_UTILS}"/package_claims.exe       \
                --input=${signed_claims}             \
                --output=policy.bin

    run_popd
}

# ###########################################################################
# Print the policy (Optional)
# ###########################################################################
function print_policy() {
    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd "${CERT_UTILS}"/print_packaged_claims.exe --input=policy.bin

    run_popd
}

# ###########################################################################
# Construct statement:
# "platform-key says attestation-key is-trusted-for-attestation"
# and sign it
# ###########################################################################
function construct_platform_key_attestation_stmt_sign_it() {
    run_cmd
    run_pushd "${PROV_DIR}"

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

    run_popd
}

# ###########################################################################
# Print signed claim (Optional)
# ###########################################################################
function print_signed_claim() {
    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd "${CERT_UTILS}"/print_signed_claim.exe      \
                --input=platform_attest_endorsement.bin

    run_popd
}

# ###########################################################################
# Step 8 in instructions.md: Use Policy Generator
# You run either this or step (7).
# ###########################################################################
function automated_policy_generation_for_OE() {
    run_cmd
    run_pushd "${PROV_DIR}"

    edit_policy_file_OE
    build_policy_generator_OE
    run_policy_generator_OE

    run_popd
}

# ###########################################################################
# Edit the policy.json file to replace trusted measurements of the
# "measurements" property with expected measurements from
# 'make dump_mrenclave'
# ###########################################################################
function edit_policy_file_OE() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    policy_json_file="./oe_policy.json"
    local policy_json_file_old="${policy_json_file}.old"
    run_cmd cp -p ${policy_json_file} ${policy_json_file_old}

    if [ $DryRun -eq 0 ]; then
        # Grab the 'mrenclave' term from 'make' output
        local mrenclave=""
        set -x
        mrenclave=$(make dump_mrenclave | grep "^mrenclave" | cut -f2 -d'=')
        set +x

        # Update json file using 'jq' tool, to replace value of the
        # 'measurement' key with generic term 'mrenclave'. Then do a text
        # replacement of this with the mrenclave grabbed above.
        set -x
        Jq=$(command -v jq)
        ${Jq} '.measurements = [ "mrenclave" ]' "${policy_json_file}"   \
            | sed -e "s/mrenclave/${mrenclave}/g"                       \
            > ${policy_json_file}.tmp
        set +x
    fi

    # Update policy.json file with json.tmp file, created above.
    run_cmd mv ${policy_json_file}.tmp ${policy_json_file}

    run_popd
}

# ###########################################################################
function build_policy_generator_OE() {
    run_cmd
    run_pushd "${CERT_PROTO}/utilities"
    local mkf="policy_generator.mak"
    LOCAL_LIB=${Local_lib_path} run_cmd make -f ${mkf}
    run_popd
}

# ###########################################################################
function run_policy_generator_OE() {
    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd "${CERT_PROTO}"/utilities/policy_generator.exe                  \
                --policy_input=../oe_policy.json                            \
                --schema_input="${CERT_PROTO}"/utilities/policy_schema.json \
                --util_path="${CERT_PROTO}"/utilities

    run_popd
}

# ###########################################################################
# Build SimpleServer: You should have gotten the protobuf compiler (protoc)
# for Go, while installing 'go'. Otherwise, do:
#   $ go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
# ###########################################################################
function build_simple_server() {
    run_cmd
    run_pushd "${CERT_PROTO}"

    # Compiler the protobuf
    run_cmd cd certifier_service/certprotos
    run_cmd protoc                              \
                --go_opt=paths=source_relative  \
                --go_out=.                      \
                --go_opt=M=certifier.proto ./certifier.proto

    # Compile the oelib for OE host verification
    # Likely, user does not have OE SDK installed or does not want to enable OE:
    # This should produce a Go file for the certifier protobufs
    # called certifier.pb.go in certprotos.
    make_arg="dummy"
    if [ "${SampleAppName}" = "simple_app_under_oe" ]; then
        make_arg=""
    fi

    run_cmd cd "${CERT_PROTO}"/certifier_service/oelib
    # shellcheck disable=SC2086
    run_cmd make ${make_arg}

    if [ "${SampleAppName}" = "simple_app_under_gramine" ]; then
        make_arg=""
    fi
    run_cmd cd "${CERT_PROTO}"/certifier_service/graminelib
    # shellcheck disable=SC2086
    run_cmd make ${make_arg}

    # Now, build simpleserver:
    run_cmd cd "${CERT_PROTO}"/certifier_service
    run_cmd rm -rf simpleserver
    run_cmd go build simpleserver.go

    run_popd
}

# ###########################################################################
# Re-create dirs for app and service data
# ###########################################################################
function mk_dirs_for_test() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    # Do this w/o checking for dry-run, so mkdir will succeed.
    # Otherwise, other steps that need .../service/ sub-dir to exist will fail
    # to run when script is executed in --dry-run mode.
    set -x
    rm -rf ${Client_app_data} ${Srvr_app_data} service
    mkdir  ${Client_app_data} ${Srvr_app_data} service
    set +x

    run_popd
}

# ###########################################################################
# Provision the app and service files
# Note: These files are required for the "simulated-enclave" which cannot measure
# the example app and needs a provisioned attestation key and platform cert.
# On real hardware, these are not needed.
# ###########################################################################
function provision_app_service_files() {
    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd cp -p ./* "$EXAMPLE_DIR"/${Client_app_data}
    run_cmd cp -p ./* "$EXAMPLE_DIR"/${Srvr_app_data}

    run_cmd cp -p policy_key_file.bin policy_cert_file.bin policy.bin \
                    "$EXAMPLE_DIR"/service

    run_popd
}

# ###########################################################################
# Start the Certifier Service: This will need to be killed manually.
# ###########################################################################
function start_certifier_service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"/service

    echo " "
    outfile="${PROV_DIR}/cert.service.out"
    echo "$Me: Starting Certifier Service ..."
    echo "$Me: To see messages from Certifier Server: tail -f ${outfile}"

    run_cmd "${CERT_PROTO}"/certifier_service/simpleserver  \
                --policyFile=policy.bin                     \
                --readPolicy=true                           \
                > "${outfile}" 2>&1 &

    run_popd
    run_cmd sleep 5

    if [ $DryRun -eq 0 ]; then
        echo "$Me: Kill this server process when the test is completed."
        # shellcheck disable=SC2009
        ps -ef | grep simpleserver | grep -v grep

        SimpleServer_PID=$(pgrep simpleserver)
    fi
}

# ###########################################################################
# Run the app as server and get admission certificates from Certifier Service
# ###########################################################################
function run_app_as_server_talk_to_Cert_Service() {
    run_"${SampleAppName}"_as_server_talk_to_Cert_Service
}

# ###########################################################################
function run_simple_app_as_server_talk_to_Cert_Service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd "${EXAMPLE_DIR}"/example_app.exe                    \
                --data_dir="./${Srvr_app_data}/"                \
                --operation=cold-init                           \
                --measurement_file="example_app.measurement"    \
                --policy_store_file=policy_store                \
                --print_all=true

    run_cmd sleep 1

    run_cmd "${EXAMPLE_DIR}"/example_app.exe                    \
                --data_dir="./${Srvr_app_data}/"                \
                --operation=get-certifier                       \
                --measurement_file="example_app.measurement"    \
                --policy_store_file=policy_store                \
                --print_all=true

    run_popd
}

# ###########################################################################
function run_simple_app_under_oe_as_server_talk_to_Cert_Service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd ./host/host                             \
                enclave/enclave.signed              \
                cold-init                           \
                "${EXAMPLE_DIR}"/${Srvr_app_data}

    run_cmd sleep 1

    run_cmd ./host/host                             \
                enclave/enclave.signed              \
                get-certifier                       \
                "${EXAMPLE_DIR}"/${Srvr_app_data}

    run_popd
}

# ###########################################################################
# NOTE: The gramine-sgx utility may return some non-fatal warnings but continues
# to execute. However, it returns a non-zero $rc, which causes this script
# to fail. So, a pattern you will see, henceforth, is to execute this
# utility with "|| 0", which will w/a the non-zero $rc by returning success.
# ###########################################################################

function run_simple_app_under_gramine_as_server_talk_to_Cert_Service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd gramine-sgx gramine_example_app         \
                --data_dir="./${Srvr_app_data}/"    \
                --operation=cold-init               \
                --policy_store_file=policy_store    \
                --print_all=true || 0

    run_cmd sleep 1

    run_cmd gramine-sgx gramine_example_app         \
                --data_dir="./${Srvr_app_data}/"    \
                --operation=get-certifier           \
                --policy_store_file=policy_store    \
                --print_all=true || 0

    run_popd
}

# ###########################################################################
# Run the app as client and get admission certificates from Certifier Service
# In a manual demo: Open two new terminals (one for the app as a client and
# one for the app as a server):
# ###########################################################################
function run_app_as_client_talk_to_Cert_Service() {
    run_"${SampleAppName}"_as_client_talk_to_Cert_Service
}

# ###########################################################################
function run_simple_app_as_client_talk_to_Cert_Service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd "${EXAMPLE_DIR}"/example_app.exe                    \
                --data_dir="./${Client_app_data}/"              \
                --operation=cold-init                           \
                --measurement_file="example_app.measurement"    \
                --policy_store_file=policy_store                \
                --print_all=true

    run_cmd sleep 1

    run_cmd "${EXAMPLE_DIR}"/example_app.exe                    \
                --data_dir="./${Client_app_data}/"              \
                --operation=get-certifier                       \
                --measurement_file="example_app.measurement"    \
                --policy_store_file=policy_store                \
                --print_all=true

    run_popd
}

# ###########################################################################
function run_simple_app_under_oe_as_client_talk_to_Cert_Service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd ./host/host                             \
                enclave/enclave.signed              \
                cold-init                           \
                "${EXAMPLE_DIR}"/${Client_app_data}

    run_cmd sleep 1

    run_cmd ./host/host                             \
                enclave/enclave.signed              \
                get-certifier                       \
                "${EXAMPLE_DIR}"/${Client_app_data}

    run_popd
}

# ###########################################################################
function run_simple_app_under_gramine_as_client_talk_to_Cert_Service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd gramine-sgx gramine_example_app \
        --data_dir="./${Client_app_data}/"  \
        --operation=cold-init               \
        --policy_store_file=policy_store    \
        --print_all=true || 0

    run_cmd sleep 1

    run_cmd gramine-sgx gramine_example_app \
        --data_dir="./${Client_app_data}/"  \
        --operation=get-certifier           \
        --policy_store_file=policy_store    \
        --print_all=true || 0

    run_popd
}

# ###########################################################################
# Run the apps to test trusted services. This is a two-part exercise:
#  - run_app_as_server_trusted_service()
#  - run_app_as_client_make_trusted_request()
# ###########################################################################
function run_app_as_server_offers_trusted_service() {
    run_"${SampleAppName}"_as_server_offers_trusted_service
}

# ###########################################################################
function run_simple_app_as_server_offers_trusted_service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"
    sleep 1

    # Run app as a server: In app as a server terminal run the following:
    run_cmd "${EXAMPLE_DIR}"/example_app.exe        \
                --data_dir="./${Srvr_app_data}/"    \
                --operation=run-app-as-server       \
                --policy_store_file=policy_store    \
                --print_all=true &

    run_cmd sleep 5

    run_popd

    # Report this, for debugging on CI-machines
    echo " "
    echo "${Me}: $(TZ="America/Los_Angeles" date) $(pwd) Completed ${FUNCNAME[0]}"
}

# ###########################################################################
function run_simple_app_under_oe_as_server_offers_trusted_service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    # Run app as a server: In app as a server terminal run the following:
    run_cmd ./host/host                         \
                enclave/enclave.signed          \
                run-app-as-server               \
                "$EXAMPLE_DIR/${Srvr_app_data}" &

    run_cmd sleep 5

    run_popd

    # Report this, for debugging on CI-machines
    echo "${Me}: $(TZ="America/Los_Angeles" date) $(pwd): Completed ${FUNCNAME[0]}"
}

# ###########################################################################
function run_simple_app_under_gramine_as_server_offers_trusted_service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    # Run app as a server: In app as a server terminal run the following:
    run_cmd gramine-sgx gramine_example_app         \
                --data_dir=./"${Srvr_app_data}"/    \
                --operation=run-app-as-server       \
                --policy_store_file=policy_store    \
                --print_all=true || 0 &

    run_cmd sleep 5

    run_popd

    # Report this, for debugging on CI-machines
    echo "${Me}: $(TZ="America/Los_Angeles" date) $(pwd): Completed ${FUNCNAME[0]}"
}


# ###########################################################################
# Run the app-as-a-trusted client sending request to trusted server:
# ###########################################################################
function run_app_as_client_make_trusted_request() {
    run_"${SampleAppName}"_as_client_make_trusted_request
}

# ###########################################################################
function run_simple_app_as_client_make_trusted_request() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    # Run app as a client: In app as a client terminal run the following:
    run_cmd "${EXAMPLE_DIR}"/example_app.exe        \
                --data_dir="./${Client_app_data}/"  \
                --operation=run-app-as-client       \
                --policy_store_file=policy_store    \
                --print_all=true

    run_popd
    # Report this, for debugging on CI-machines
    echo " "
    echo "${Me}: $(TZ="America/Los_Angeles" date) Completed ${FUNCNAME[0]} ${DryRun_msg}."
}

# ###########################################################################
function run_simple_app_under_oe_as_client_make_trusted_request() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    # Run app as a client: In app as a client terminal run the following:
    run_cmd ./host/host                         \
                enclave/enclave.signed          \
                run-app-as-client               \
                "$EXAMPLE_DIR/${Client_app_data}"

    run_popd

    # Report this, for debugging on CI-machines
    echo "${Me}: $(TZ="America/Los_Angeles" date) Completed ${FUNCNAME[0]} ${DryRun_msg}."
}

# ###########################################################################
function run_simple_app_under_gramine_as_client_make_trusted_request() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    # Run app as a client: In app as a client terminal run the following:
    run_cmd gramine-sgx gramine_example_app         \
                --data_dir="./${Client_app_data}/"  \
                --operation=run-app-as-client       \
                --policy_store_file=policy_store    \
                --print_all=true || 0

    run_popd

    # Report this, for debugging on CI-machines
    echo "${Me}: $(TZ="America/Los_Angeles" date) Completed ${FUNCNAME[0]} ${DryRun_msg}."
}

# ###########################################################################
function show_env() {
    echo " "
    echo "**** Environment variables, script globals: ****"
    env | grep -E "CERT_PROTO|EXAMPLE_DIR"
    echo "LOCAL_LIB=${Local_lib_path}"

    echo " "
    uname -a
    # Likely, will fail on macOSX, so run in dry-run mode
    if [ $DryRun -eq 0 ]; then
        local numCPUs=0
        local cpuModel=0
        local cpuVendor=0
        local totalMemGB=0

        numCPUs=$(grep -c "^processor" /proc/cpuinfo)
        cpuModel=$(grep "model name" /proc/cpuinfo | head -1 | cut -f2 -d':')
        cpuVendor=$(grep "vendor_id" /proc/cpuinfo | head -1 | cut -f2 -d':')
        totalMemGB=$(free -g | grep "^Mem:" | awk '{print $2}')

        echo " "
        echo "${Me}: ${cpuVendor}, ${numCPUs} CPUs, ${totalMemGB} GB, ${cpuModel}"
        ping -4 -c 1 "$(uname -n | head -2)"

        echo " "
        lsb_release -a
    fi
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
    local app_name="$1"
    setup_"${app_name}" ""
}

# ###########################################################################
# Do initial setup of the sample app test-case
# As the sub-steps array has nested fn-calls, run a collection of steps
# to avoid re-running sub-fns nested under author_policy()
# ###########################################################################
function setup_simple_app() {
    run_cmd
    run_steps "show_env" "get_measurement_of_trusted_app"
    author_policy
    run_steps "build_simple_server" "provision_app_service_files"
}

# ###########################################################################
# For OE-app, we have two ways to manage policy generation.
# Default is manual step by running a collection of utility programs.
#
# Optionally, user can hand-edit policy.json file and stick-in the
# generated measurement. This is also automated under 'generate_policy' step.
# So, user can invoke this script as:
#   $ run_example.sh simple_app_under_oe setup_with_auto_policy_generation_for_OE
#
# If the 2nd arg is provided, manually execute that sub-step's function.
# ###########################################################################
function setup_simple_app_under_oe() {
    local setup_arg="$1"
    run_steps "show_env" "get_measurement_of_trusted_app"
    if [ "${setup_arg}" = "" ]; then
        manual_policy_generation_for_OE
    else
        ${setup_arg}
    fi
    run_steps "build_simple_server" "provision_app_service_files"
}

# ###########################################################################
# Run setup for OE-app, but manage policy by editing JSON file.
# ###########################################################################
function setup_with_auto_policy_generation_for_OE() {
    setup_simple_app_under_oe "automated_policy_generation_for_OE"
}

# ###########################################################################
function setup_simple_app_under_gramine() {
    run_cmd
    setup_MbedTLS
    run_steps "show_env" "get_measurement_of_trusted_app"
    author_policy
    run_steps "build_simple_server" "provision_app_service_files"
}

# ###########################################################################
# One-time special-case setup of MbedTLS libraries. We cannot do this outside
# this script as, for full e2e run, this script will run rm_non_git_files.
# That will clean-up the setup done by the configure script run below.
# ###########################################################################
function setup_MbedTLS() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd ./configureMbedTLS

    run_popd
}

# ###########################################################################
# After setup is done, run-the-test, setting up Cert Service etc.
# This should be common for all sample apps.
# ###########################################################################
function run_test() {
    run_steps "start_certifier_service" "run_app_as_client_make_trusted_request"
}

# ##################################################################
# main() begins here
# ##################################################################

# Simple command-line arg processing. Expect at least one arg, sample-app-name
if [ $# -eq 0 ]; then
    usage_brief
    exit 1
fi

if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    usage
    if [ $# -eq 2 ] && [ "$2" = "simple_app_under_oe" ]; then
        usage_OE
    fi
    exit 0
fi

if [ "$1" == "--list" ]; then
    if [ $# -eq 1 ]; then
        list_steps "${SampleAppName}"
    else
        # Assume 2nd arg is app name
        is_valid_app "$2"
        if [ "${Valid_app}" == "0" ]; then
            echo "${Me}: Sample program name '$2' is currently not supported."
            exit 1
        fi
        list_steps "$2"
    fi
    exit 0
fi

if [ "$1" == "--dry-run" ]; then
    echo " "
    echo "${Me}: ****************************************************"
    echo "${Me}: ******** Executing script in dry-run mode. *********"
    echo "${Me}: ****************************************************"
    echo " "
    DryRun=1
    DryRun_msg="in dry-run mode"
    shift
fi

if [ "$1" == "rm_non_git_files" ]; then
    $1
    exit 0
fi

is_valid_app "$1"
if [ "${Valid_app}" == "0" ]; then
    echo "${Me}: Sample program name '$1' is currently not supported."
    exit 1
fi

# ----------------------------------------------------------------
# Having established name of valid sample app, setup env variables
# and script globals that will be used downstream.
# Establish full dirpath where this script lives
# ----------------------------------------------------------------
SampleAppName="$1"
pushd "$(dirname "$0")" > /dev/null 2>&1
EXAMPLE_DIR=$(pwd)/${SampleAppName}; export EXAMPLE_DIR
popd > /dev/null 2>&1

PROV_DIR="${EXAMPLE_DIR}/provisioning"

CERT_UTILS="${CERT_PROTO}/utilities"

if [ $# -eq 2 ]; then

    # Execute a user-supplied name of a function implementing a step.
    # If a wrong name was supplied, we will error out.
    is_valid_step "$2"
    if [ "${Found_step}" == "0" ]; then
        echo "${Me}:${LINENO} Invalid step name, $2, provided for $1."
        exit 1
    fi

    # Else, it's a valid step / function name. Execute it.
    # shellcheck disable=SC2048
    $2 "${SampleAppName}"

    echo "${Me}: $(TZ="America/Los_Angeles" date) Completed $2 ${DryRun_msg} for $1."
    exit 0
fi

echo "${Me}: $(TZ="America/Los_Angeles" date) ${MeMsg} ${SampleAppName}"

if [ ! -d "${PROV_DIR}" ]; then mkdir "${PROV_DIR}"; fi

# Run through the list of steps as arranged in Steps[] sequence
# for str in "${Steps[@]}"; do
#     ${str}
# done

# For a full end2end run, also clean-up build-env of stale artifacts
rm_non_git_files

setup "${SampleAppName}"
run_test

# Cleanup running processes ...
trap "" ERR

# shellcheck disable=SC2086
if [ ${SimpleServer_PID} -ne 0 ]; then kill -9 "${SimpleServer_PID}"; fi

echo "${Me}: $(TZ="America/Los_Angeles" date) Completed ${DryRun_msg}."
