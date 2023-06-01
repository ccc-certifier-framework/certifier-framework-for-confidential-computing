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
DryRunTag=" "
DryRun_msg=""

RunTag=""           # Short description of which app is being tested

RunSudo=0           # Only some commands for SEV-app need to run as sudo

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

# Work-instructions for SEV-app need following files pre-populated by the user.
#
Platform_cert_files_SEV="ark_cert.der ask_cert.der vcek_cert.der"
Platform_data_files_SEV="sev_policy.json ${Platform_cert_files_SEV}"

# Normal usage (esp for testing) will be on simulated SEV-SNP environment
# Unknown env; will be determined later on.
CC_SIMULATED_SEV="${CC_SIMULATED_SEV:- -1}"

# In simulated-SEV env, pre-install setup of sev-snp-simulator/ would have
# installed this permission file. If it does not exist, that means the
# setup hasn't been done. (We will fail simulated-sev execution.)
CC_vcek_key_file_SIM_SEV="/etc/certifier-snp-sim/ec-secp384r1-pub-key.pem"

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
             "simple_app_under_sev"
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

# ---- SEV-SNP Enclave app-specific help/usage output
function usage_SEV() {
    echo " "
    echo "For simple_app_under_sev, you use this script "
    echo "to generate the policy supplying the measurement in the policy JSON file:"
    echo " "
    echo "-- (Default) In a SEV-SNP simulated platform, using the Automated Policy Generator:"
    echo "   - Build and install the SEV-SNP Simulator utility"
    echo "  To setup the example program        :      ./${Me} simple_app_under_sev setup"
    echo "  To run and test the example program : sudo ./${Me} simple_app_under_sev run_test"
    echo " "
    echo "-- On SEV-SNP enabled hardware platform:"
    echo "   Pre-populate simple_app_under_sev/platform_data/ with these required files:"
    echo "   ${Platform_data_files_SEV}"
    echo " "
    echo "  To setup the example program        :      ./${Me} simple_app_under_sev setup_with_auto_policy_generation_for_SEV"
    echo "  To run and test the example program : sudo ./${Me} simple_app_under_sev run_test"
    echo " "
    echo "  To cleanup after a run              : sudo ./cleanup.sh"
}

# ###########################################################################
# Dump the list of functions, one for each step, that user can invoke.
# Ref: https://www.freecodecamp.org/news/bash-array-how-to-declare-an-array-of-strings-in-a-bash-script/
# ###########################################################################
Steps=( "rm_non_git_files"

        # 'setup' argument starts from here:
        "show_env"
        # "do_cleanup"
        "build_utilities"
        "gen_policy_and_self_signed_cert"
        "embed_policy_in_example_app"
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
           "embed_policy_in_example_app"
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
              "build_policy_generator"
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

Steps_SEV=( "rm_non_git_files"

            # 'setup' argument starts from here:
            "show_env"
            "do_cleanup"
            "build_utilities"
            "gen_policy_and_self_signed_cert"
            "gen_certificates_for_simulated_SEV"
            "emded_policy_in_example_app"
            "compile_app"
            "get_measurement_of_trusted_app"

            # --------------------------------------------------------------
            # If user is running individual steps, they have to run
            #  - either manual_policy_generation_for_SEV (currently, unsupported),
            #  - or     automated_policy_generation_for_SEV
            "manual_policy_generation_for_SEV"
              # These sub-step fns are subsumed under author_policy()
               "construct_policyKey_platform_is_trusted"
               "produce_signed_claims_for_vse_policy_statement"
               "combine_policy_stmts"
               "print_policy"

            "automated_policy_generation_for_SEV"
              # These sub-step fns are subsumed under automated_policy_generation_for_SEV()
               "edit_policy_file_SEV"
               "build_policy_generator"
               "run_policy_generator_SEV"

            "build_simple_server"
            "mk_dirs_for_test"
            "provision_app_service_files"
            # 'setup' argument ends here.

            # Special-case interface to invoke automated_policy_generation_for_SEV()"
            "setup_with_auto_policy_generation_for_SEV"

            # Special-case interface to run on simulated SEV platform
            "setup_with_auto_policy_generation_for_simulated_SEV"

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

        "simple_app_under_sev")
            list_steps_for_app "${Steps_SEV[@]}"
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

        "simple_app_under_sev")
            check_steps_for_app "${Steps_SEV[@]}"
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
#
# Ref:
# How to find array-length for $@ passed as an array to a function
# https://stackoverflow.com/questions/16461656/how-to-pass-array-as-an-argument-to-a-function-in-bash
#
# ###########################################################################
function run_cmd() {
    echo " "
    This_fn="${FUNCNAME[1]}"
    if [ "${Prev_fn}" != "${This_fn}" ]; then
        echo "**************************************************************************************************************"
        echo "${Me}: ${RunTag}: Running${DryRunTag}${FUNCNAME[1]} "
        Prev_fn="${This_fn}"
    fi

    # For tracing, some functions simply invoke this run_cmd() with
    # no arguments. Just 'sudo' will fail, so side-step this usage 'issue'.
    local args_array=("$@")
    local array_len=0
    array_len=$((${#args_array[@]}))

    local echo_sudo=""
    local run_sudo=0
    if [ "${RunSudo}" -eq 1 ] && [ "${array_len}" -gt "1" ]; then
        echo_sudo="sudo "
        run_sudo=1
    fi

    # Only execute the commands if --dry-run is OFF
    if [ ${DryRun} -eq 0 ]; then

        if [ "${run_sudo}" -eq 1 ]; then
            set -x
            sudo "$@"
            set +x
        else
            set -x
            "$@"
            set +x
        fi
    else
        # Print what would have been executed, so user can learn from this.
        echo "${echo_sudo}$@"
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

    if [ "${SampleAppName}" = "simple_app_under_gramine" ] \
        || [ "${SampleAppName}" = "simple_app_under_sev" ];
    then
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

    # As we are drilling through generic Steps[] array, we need
    # to do a side-bar to handle simulated-SEV certificates.
    if [ "${CC_SIMULATED_SEV}" -eq 1 ]; then
        gen_certificates_for_simulated_SEV
    fi
}

# ###########################################################################
# Ggenerate an ARK, ASK and VCEK certificates that are compatible with the
# sev-snp-simulator keys.
# ###########################################################################
function gen_certificates_for_simulated_SEV() {
    # This step appears in the general list of steps for 'setup'.
    # Skip it, if we are not in a simulated SEV environment.
    if [ "${CC_SIMULATED_SEV}" -ne 1 ]; then
        return;
    fi

    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd "${CERT_UTILS}"/simulated_sev_key_generation.exe    \
             --ark_der=sev_ark_cert.der                         \
             --ask_der=sev_ask_cert.der                         \
             --vcek_der=sev_vcek_cert.der                       \
             --vcek_key_file="${CC_vcek_key_file_SIM_SEV}"

    # Save existing cert.der files as .old files
    for der in ${Platform_cert_files_SEV}
    do
        run_cmd cp -p "${der}" "${der}.old"
    done

    # cp over newly created sev*.der files as cert.der files
    for der in ${Platform_cert_files_SEV}
    do
        run_cmd cp -p sev_"${der}" "${der}"
    done

    run_popd
}

# ###########################################################################
function embed_policy_in_example_app() {
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
function compile_simple_app_under_sev() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd make -f sev_example_app.mak clean

    export CFLAGS="-DSEV_DUMMY_GUEST"
    run_cmd make -f sev_example_app.mak
    unset CFLAGS

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
# simple_app_under_sev      : example_app.measurement
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
function get_measurement_of_trusted_simple_app_under_sev() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    # Grab mrenclave as Measurement entry that is registered in default
    # policy.json file for this program. User is expected to have updated
    # that to specify the policy for the sev-snp platform being used.
    local policy_json_file="./sev_policy.json"
    local mrenclave="some-hash-string-that-will-grep-from-"${policy_json_file}

    if [ $DryRun -eq 0 ]; then
        set -x
        mrenclave=$(grep -A1 measurements ${policy_json_file}   \
                        | tail -1 | sed 's/"//g' | tr -d ' ')
        set +x
    fi

    run_popd

    run_pushd "${PROV_DIR}"

    run_cmd "$CERT_UTILS"/measurement_init.exe  \
            --mrenclave="${mrenclave}"          \
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
# Similar to author_policy() that is run for simple_app()
#
# Author the policy for the security domain and produce the signed claims
# that the apps need. This is just a wrapper function to drive the execution
# of sub-steps, each of which is implemented by a minion function.
#
# Step 7 in instructions.md: Manual policy generation
# You run either this step, or Step 8, below.
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
# RESOLVE: Fill this out.
function manual_policy_generation_for_SEV() {
    run_cmd
    run_pushd "${PROV_DIR}"

    echo "${Me}: Currently this method is unsupported for SEV-platform."
    exit 1

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
function construct_policyKey_platform_is_trusted_simple_app_under_sev() {
    run_cmd
    run_pushd "${PROV_DIR}"

    # The docs state that this certificate should exist at a known location.
    run_cmd "${CERT_UTILS}"/make_unary_vse_clause.exe   \
                --cert-subject=ark_cert.der             \
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
# Step 8 in instructions.md: Use Automated Policy Generator
# You run either this or step (7).
# ###########################################################################
function automated_policy_generation_for_OE() {
    run_cmd
    run_pushd "${PROV_DIR}"

    edit_policy_file_OE
    build_policy_generator
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
# Shared by OE- and SEV-app's steps
function build_policy_generator() {
    run_cmd

    run_pushd "${CERT_PROTO}/utilities"

    local mkf="policy_generator.mak"
    run_cmd make -f ${mkf} clean
    LOCAL_LIB=${Local_lib_path} run_cmd make -f ${mkf}

    run_popd
}

# ###########################################################################
function run_policy_generator_OE() {
    run_cmd
    run_policy_generator_for_app "../oe_policy.json"
}

# ###########################################################################
function run_policy_generator_SEV() {
    run_cmd

    # Set this env-var, so policy_generator.exe can find
    # nlohmann_json_schema_validator from known lib-path.
    # This is a CI-friendly w/a to instructions that require sudo to edit
    # /etc/ld.so.conf, and then to run 'ldconfig'.
    set -x
    LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-${Local_lib_path}}; export LD_LIBRARY_PATH
    set +x

    run_policy_generator_for_app "../sev_policy.json"
}

# ###########################################################################
# Shared function, receives JSON-policy file as input
# ###########################################################################
function run_policy_generator_for_app() {
    local policy_input_json="$1"
    run_cmd
    run_pushd "${PROV_DIR}"

    run_cmd "${CERT_PROTO}"/utilities/policy_generator.exe                  \
                --policy_input="${policy_input_json}"                       \
                --schema_input="${CERT_PROTO}"/utilities/policy_schema.json \
                --util_path="${CERT_PROTO}"/utilities
    run_popd
}

# ###########################################################################
# Step 8 in instructions.md: Use Automated Policy Generator
# You run either this or step (7).
# NOTE: This function executes both for SEV-SNP platform and for
#       simulated-SEV environment (on Linux VMs).
# ###########################################################################
function automated_policy_generation_for_SEV() {
    run_cmd
    run_pushd "${PROV_DIR}"

    # This does not exist, as we expect user to hand-edit and provide us a
    # JSON-policy file
    # edit_policy_file_SEV

    # Building policy_generator.exe is same command as for OE-app
    build_policy_generator
    run_policy_generator_SEV

    run_popd
}

# ###########################################################################
# Work-instructions, and this script, expect that the user has populated
# few required files in the platform_data/ sub-dir for SEV-app.
# If required files exist, distribute them to the appropriate sub-dirs
# so downstream steps find the right files as needed.
# ###########################################################################
function check_platform_data_files_SEV() {
    local fulldir=""
    local currdir=""

    run_pushd "${EXAMPLE_DIR}/platform_data"
    pwd

    fulldir=$(pwd)

    # shellcheck disable=SC2046
    currdir="$(basename $(dirname "${fulldir}"))/$(basename "${fulldir}")"

    nerrors=0
    for file in ${Platform_data_files_SEV}
    do
        if [ ! -f "${file}" ] && [ "${DryRun}" = 0 ]; then
            echo "${Me}:${LINENO}: Expected to find ${file} in ${currdir}"
            nerrors=$((nerrors + 1))
        fi
    done
    if [ "${nerrors}" -gt 0 ]; then
        exit 1
    fi

    run_cmd cp -p sev_policy.json ../
    run_cmd cp -p ./*.der "${PROV_DIR}"

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
    local make_arg="dummy"
    if [ "${SampleAppName}" = "simple_app_under_oe" ]; then
        make_arg=""
    fi

    run_cmd cd "${CERT_PROTO}"/certifier_service/oelib
    # shellcheck disable=SC2086
    run_cmd make ${make_arg}

    make_arg="dummy"
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

    if [ "${SampleAppName}" = "simple_app_under_sev" ]; then
        run_cmd cp -p ./*.der "$EXAMPLE_DIR"/service
    fi

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
function run_simple_app_under_sev_as_server_talk_to_Cert_Service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd "${EXAMPLE_DIR}"/sev_example_app.exe    \
                --data_dir="./${Srvr_app_data}/"    \
                --operation=cold-init               \
                --policy_store_file=policy_store    \
                --print_all=true

    run_cmd "${EXAMPLE_DIR}"/sev_example_app.exe    \
                --data_dir="./${Srvr_app_data}/"    \
                --operation=get-certifier           \
                --policy_store_file=policy_store    \
                --print_all=true

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

    run_cmd gramine-sgx gramine_example_app         \
                --data_dir="./${Client_app_data}/"  \
                --operation=cold-init               \
                --policy_store_file=policy_store    \
                --print_all=true || 0

    run_cmd sleep 1

    run_cmd gramine-sgx gramine_example_app         \
                --data_dir="./${Client_app_data}/"  \
                --operation=get-certifier           \
                --policy_store_file=policy_store    \
                --print_all=true || 0

    run_popd
}

# ###########################################################################
function run_simple_app_under_sev_as_client_talk_to_Cert_Service() {
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    run_cmd "${EXAMPLE_DIR}"/sev_example_app.exe    \
                --data_dir="./${Client_app_data}/"  \
                --operation=cold-init               \
                --policy_store_file=policy_store    \
                --print_all=true

    # Otherwise, we've seen ioctl I/O errors on SEV-SNP machine.
    run_cmd sleep 5

    run_cmd "${EXAMPLE_DIR}"/sev_example_app.exe    \
                --data_dir="./${Client_app_data}/"  \
                --operation=get-certifier           \
                --policy_store_file=policy_store    \
                --print_all=true
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
    run_app_by_name_as_server_offers_trusted_service "example_app.exe"
}

# ###########################################################################
# Shared method, takes app-name as a parameter
# ###########################################################################
function run_app_by_name_as_server_offers_trusted_service() {
    local app_name_exe="$1"
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    # Run app as a server: In app as a server terminal run the following:
    run_cmd "${EXAMPLE_DIR}/${app_name_exe}"        \
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
function run_simple_app_under_sev_as_server_offers_trusted_service() {
    run_app_by_name_as_server_offers_trusted_service "sev_example_app.exe"
}

# ###########################################################################
# Run the app-as-a-trusted client sending request to trusted server:
# ###########################################################################
function run_app_as_client_make_trusted_request() {
    run_"${SampleAppName}"_as_client_make_trusted_request
}

# ###########################################################################
function run_simple_app_as_client_make_trusted_request() {
    run_app_by_name_as_client_make_trusted_request "example_app.exe"
}

# ###########################################################################
function run_simple_app_under_sev_as_client_make_trusted_request() {
    run_app_by_name_as_client_make_trusted_request "sev_example_app.exe"
}

# ###########################################################################
# Shared method, takes app-name as a parameter
# ###########################################################################
function run_app_by_name_as_client_make_trusted_request() {
    local app_name_exe="$1"
    run_cmd
    run_pushd "${EXAMPLE_DIR}"

    # Run app as a client: In app as a client terminal run the following:
    run_cmd "${EXAMPLE_DIR}/${app_name_exe}"        \
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
    PATH="/home/rgerganov/go/bin:${PATH}"; export PATH

    echo "**** Environment variables, script globals: ****"
    env | grep -w -E "CERT_PROTO|EXAMPLE_DIR|PATH"
    echo "PROV_DIR=${PROV_DIR}"
    echo "LOCAL_LIB=${Local_lib_path}"
    echo "protoc-gen-go: " "$(command -v protoc-gen-go)"

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
#
# Default is manual step by running a collection of utility programs.
#
# Optionally, user can hand-edit policy.json file and stick-in the
# generated measurement. This is also automated under 'run_policy_generator*()'
# step, using the policy_generator.exe executable.
#
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
    RunTag="${RunTag} auto-policy generation"
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
# For SEV-app, we have two ways to manage policy generation (very similar
# to what is supported for OE-app).
#
# - Manual policy generation: By running a collection of utility programs.
#   Currently unsupported.
#
# - Automated policy generation: Optionally, user can hand-edit policy.json
#   file and stick-in the generated measurement. This is also automated under
#   'run_policy_generator*()' step, using the policy_generator.exe executable.
#
# So, user can invoke this script as:
#   $ run_example.sh simple_app_under_sev setup_with_auto_policy_generation_for_SEV
#
# Additionally, we can run the sample-app on:
#   1. Simulated SEV-enabled platform on any Linux machine (default).
#   2. Real SEV-enabled h/w platform
#
# If the 2nd arg is provided, manually execute that sub-step's function.
# ###########################################################################
function setup_simple_app_under_sev() {
    local setup_arg="$1"

    run_cmd

    # If user just said 'setup', assume they are running in simulated-SEV env
    if [ "${setup_arg}" = "" ]; then
        CC_SIMULATED_SEV=1
        RunTag="${RunTag} simulated-SEV"
        check_perm_files_simulated_SEV
    fi

    run_steps "show_env" "get_measurement_of_trusted_app"

    if [ "${setup_arg}" = "" ]; then
        automated_policy_generation_for_SEV
    else
        ${setup_arg}
    fi
    run_steps "build_simple_server" "provision_app_service_files"
}

# ###########################################################################
# Run setup for SEV-app, but use the user-specified policy from user-edited
# JSON-policy file. This method is meant to be used on a real SEV-platform.
# ###########################################################################
function setup_with_auto_policy_generation_for_SEV() {
    CC_SIMULATED_SEV=0
    check_platform_data_files_SEV
    RunTag="${RunTag} auto-policy generation"
    setup_simple_app_under_sev "automated_policy_generation_for_SEV"
}

# ###########################################################################
# Run setup for SEV-app, but use the user-specified policy from default
# JSON-policy file, in a simulated SEV environment.
# NOTE: Currently, this interface is not exposed, but retain this function
#       in case we ever support manual policy generation for SEV-app.
#       At that time, this function can be exposed to the end-user.
# ###########################################################################
function setup_with_auto_policy_generation_for_simulated_SEV() {
    check_perm_files_simulated_SEV
    CC_SIMULATED_SEV=1
    RunTag="${RunTag} simulated-SEV"
    setup_simple_app_under_sev "automated_policy_generation_for_SEV"
}

# ###########################################################################
# Work-instructions, and this script, expect that the user has done the
# build-and-setup of simulated SEV environment, using 'make' targets in
# the sev-snp-simulator/ dir. Check for its artifacts, and fail execution
# if the key permission file is not found.
# ###########################################################################
function check_perm_files_simulated_SEV() {

    run_cmd
    local file=${CC_vcek_key_file_SIM_SEV}
    local sim_dir="${CERT_PROTO}/sev-snp-simulator"

    if [ ! -f "${file}" ] && [ "${DryRun}" = 0 ]; then
        echo "${Me}:${LINENO}: Expected to find permission file: ${file}"
        echo "${Me} Please do the setup of simulated SEV environment using the scripts in ${sim_dir}, and re-try."
        exit 1
    fi
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
    if [ $# -eq 2 ]; then
        if [ "$2" = "simple_app_under_oe" ]; then
            usage_OE
        elif [ "$2" = "simple_app_under_sev" ]; then
            usage_SEV
        fi
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
    DryRun=1
    DryRunTag=" dry-run "
    DryRun_msg="in${DryRunTag}mode"
    shift
fi

if [ $# -ge 1 ]; then
    if [ "$1" == "rm_non_git_files" ]; then
        $1
        exit 0
    fi

    is_valid_app "$1"
    if [ "${Valid_app}" == "0" ]; then
        echo "${Me}: Sample program name '$1' is currently not supported."
        exit 1
    fi
    SampleAppName="$1"
fi

RunTag="${SampleAppName}"

# ----------------------------------------------------------------
# Having established name of valid sample app, setup env variables
# and script globals that will be used downstream.
# Establish full dirpath where this script lives
# ----------------------------------------------------------------
if [ "${DryRun}" = 1 ]; then
    echo " "
    echo "${Me}: **************************************************************************"
    echo "${Me}: ******** Executing script ${DryRun_msg} for $*"
    echo "${Me}: **************************************************************************"
    echo " "
fi

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

    # By the nature of the platform, commands for this app have to run
    # as 'root'.
    if [ "${SampleAppName}" = "simple_app_under_sev" ] \
        && [ "$2" = "run_test" ]; then
        RunSudo=1
    fi

    # Else, it's a valid step / function name. Execute it.
    # shellcheck disable=SC2048
    $2 "${SampleAppName}"

    echo "${Me}: $(TZ="America/Los_Angeles" date) Completed $2 ${DryRun_msg} for ${RunTag}."
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

echo "${Me}: $(TZ="America/Los_Angeles" date) Completed ${DryRun_msg} for ${RunTag}."
