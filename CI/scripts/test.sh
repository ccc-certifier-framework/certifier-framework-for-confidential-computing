#!/bin/bash
# ############################################################################
# test.sh: Driver script to run build-and-test for Certifier Framework s/w.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

# Establish dir-path for Certifier Framework's top-level root-dir.
pushd "$(dirname "$0")" > /dev/null 2>&1

cd ../..
CERT_ROOT="$(pwd)"

# Establish # of CPUs, so make -j<num threads> can be maximised
NumCPUs=1
if [ "$(uname -s)" = "Linux" ]; then
    NumCPUs=$(grep -c "^processor" /proc/cpuinfo)
fi
# Cap # of -j threads for make to 8
NumMakeThreads=${NumCPUs}
if [ "${NumMakeThreads}" -gt 8 ]; then NumMakeThreads=8; fi

# 'Globals' to track which test function is / was executing ...
This_fn=""

# -------------------------------------------------------------------------
# Symbol to track dependency of test-simple_app_python-with-warm-restart
# test-case on 'setup' done for simple_app_python. In CI, these two tests
# are run back-to-back, so this dependency is assured. If the user runs
# this test-case manually, we track this dependency via this global symbol
# -------------------------------------------------------------------------
Simple_app_python_setup_done="${FROM_CI_BUILD_YML:-0}"
Simple_app_setup_done="${FROM_CI_BUILD_YML:-0}"

# Symbol to track dependency of test-simple_app_python-with-warm-restart
# ###########################################################################
# Set trap handlers for all errors. Needs -E (-o errtrace): Ensures that ERR
# traps (see below) get inherited by functions, command substitutions, and
# subshell environments
# Ref: https://citizen428.net/blog/bash-error-handling-with-trap/
# ###########################################################################
function cleanup() {
    set +x
    echo " "
    echo "${Me}: **** Error **** Failed command, ${BASH_COMMAND}, at line $(caller) while executing function ${This_fn}"

    failed_test="test-build-and-install-sev-snp-simulator"
    if [ "${This_fn}" = "${failed_test}" ]; then
        echo " "
        echo "${Me}: To fix 'make insmod' failures, do the following:"
        echo "  pushd ./sev-snp-simulator"
        echo "  make rmmod"
        echo " "
        echo "Resume test execution using: ${Me} --from-test ${failed_test}"
    fi
}

trap cleanup ERR

# ##################################################################
# Array of test function names. If you add a new test_<function>,
# add it to this list, here, so that one can see it in --list output.
# ##################################################################
TestList=( "test-core-certifier-programs"
           "test-cert_framework-pytests"
           "test-mtls-ssl-client-server-comm-pytest"
           "unit-test-certlib-utility-programs"
           "test-run_example-help-list-args"
           "test-run_example-dry-run"
           "test-run_example-simple_app"
           "test-simple_app-with-crypto_algorithms"
           "test-run_example-simple_app_python"
           "test-simple_app_python-with-warm-restart"
           "test-build-and-setup-App-Service-and-simple_app_under_app_service"
           "test-run_example-multidomain_simple_app"
           "test-build-and-install-sev-snp-simulator"
           "test-sev-snp-simulator-sev-test"
           "test-certifier-build-and-test-simulated-SEV-mode"
           "test-simple_app_under_sev-simulated-SEV-mode"
           "test-simple_app_under_keystone-using-shim"
           "test-ISLET-SDK-shim_test"
           "test-run_example-simple_app_under_islet-using-shim"

           # This is the default target, to run all tests
           # "test_all"
         )

# ##################################################################
# Print help / usage
# ##################################################################
function usage() {

   # Computed elapsed hours, mins, seconds from total elapsed seconds
   echo "Usage: $Me [--help | --list] [ --from-test <test-function-name> ] [test_all]"
}

# --------------------------------------------------------------------------
# Driver function to list test functions available.
function list_tests() {
    echo "${Me}: List of test cases to execute:"
    list_items_for_array "${TestList[@]}"
}

function list_items_for_array() {
    local items_array=("$@")
    for str in "${items_array[@]}"; do
        echo "  ${str}"
    done
}

# #############################################################################
function test-core-certifier-programs() {
    echo "******************************************************************"
    echo "* Check that core certifier programs still compile and clear tests"
    echo "* (Also builds shared libraries for use by Python bindings.)"
    echo "******************************************************************"
    echo " "
    pushd "${CERT_ROOT}"/src > /dev/null 2>&1

    # ---------------------------------------------------------------------
    # Check that core certifier programs still compile and clear tests
    # ---------------------------------------------------------------------
    set -x
    make -f certifier.mak clean
    make -f certifier_tests.mak clean

    make -j${NumMakeThreads} -f certifier.mak

    # We need to clean here, otherwise make certifier_tests.mak will run
    # into some protobuf-related errors.
    make -f certifier.mak clean

    make -j${NumMakeThreads} -f certifier_tests.mak
    ./certifier_tests.exe

    # Rebuild both shared libraries as 'all' target does not build these.
    # Rebuild special-target which will invoke -fPIC flag during compilation.
    make -f certifier.mak --always-make -j${NumMakeThreads} sharedlib
    make -f certifier.mak --always-make -j${NumMakeThreads} swigpytestssharedlib
    make -f certifier_tests.mak --always-make -j${NumMakeThreads} sharedlib
    set +x

    popd > /dev/null 2>&1

    # Sanity check that the shared library was built correctly and can be loaded
    # python3 -c "import libcertifier_framework; help(libcertifier_framework)"
    # python3 -c "import libcertifier_tests; help(libcertifier_tests)"
}

# #############################################################################
# Depends on: test_core_certifier_programs
# #############################################################################
function test-cert_framework-pytests() {
    echo "**************************************************************"
    echo " Test Python bindings' to Certifier Framework shared library "
    echo "**************************************************************"
    echo " "

    PYTHONPATH=$(pwd); export PYTHONPATH

    pushd tests/pytests > /dev/null 2>&1

    # Run one case showing verbose outputs of each library's contents.
    # Run each py file separately as 'pytest -v' (on all files) craps out.
    set -x
    pytest --capture=tee-sys test_libcertifier_framework.py -k test_cfslib_getmembers_of_libcertifier_framework

    # Capture output from individual Certifier tests that are run
    PYTHONUNBUFFERED=TRUE pytest --capture=tee-sys -v test_libcertifier_tests.py

    PYTHONUNBUFFERED=TRUE pytest -v test_libcertifier_framework.py

    # NOTE: Some test cases in test_certifier_framework.py need the Certifier Service
    # to be up-and-running. That needs several build-and-setup steps which are part
    # of a simple_app execution test. Execution of those cases is hence moved downstream.
    PYTHONUNBUFFERED=TRUE pytest --capture=tee-sys -v -m "not needs_cert_service" \
         test_certifier_framework.py

    # Just run the basic case of this test to see classes created in generated Python module
    PYTHONUNBUFFERED=TRUE PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
         pytest --capture=tee-sys -v test_certifier_protobuf_interfaces.py \
             -k test_certifier_pb2_basic

    # Re-run entire test w/o capturing output
    PYTHONUNBUFFERED=TRUE PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
         pytest -v test_certifier_protobuf_interfaces.py

    # Exercise SWIG-Python bindings standalone unit-tests
    PYTHONUNBUFFERED=TRUE pytest --capture=tee-sys -v test_libswigpytests.py

    # Just run the basic case of this test to see classes created in generated Python module
    PYTHONUNBUFFERED=TRUE PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
    pytest --capture=tee-sys -v test_certifier_protobuf_interfaces.py -k test_certifier_pb2_basic

    # Re-run entire test w/o capturing output
    PYTHONUNBUFFERED=TRUE PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python \
    pytest -v test_certifier_protobuf_interfaces.py

    set +x
    popd > /dev/null 2>&1
}

# #############################################################################
function test-mtls-ssl-client-server-comm-pytest() {
    echo "**************************************************************"
    echo " Test Python Client-Server Secure channel communication"
    echo "**************************************************************"
    echo " "

    pushd tests > /dev/null 2>&1

    # Generates required PEM-cert and private-key files for client & server
    ./gen_client_server_certs_key_files.sh

    cd pytests

    # ----
    # Exercise client-server communication with self-signed certificates
    pytest --capture=tee-sys -v test_client_server_mtls.py -k test_server_process_with_mtls_self_signed_cert &

    sleep 5

    pytest --capture=tee-sys -v test_client_server_mtls.py -k test_client_app_with_mtls_self_signed_cert

    # ----
    # Basic test to exercise core certificate verification v/s root-CA-cert
    pytest --capture=tee-sys -v test_client_server_mtls.py -k test_verify_certs_versus_root_cert

    # ----
    # Exercise client-server communication with root-CA-signed certificates
    pytest --capture=tee-sys -v test_client_server_mtls.py \
            -k test_server_process_with_mtls_root_signed_cert_and_pvt_key_file &

    sleep 5

    pytest --capture=tee-sys -v test_client_server_mtls.py \
            -k test_client_app_with_mtls_root_signed_cert_and_pvt_key_file

    # ----
    # Exercise client-server communication with root-CA-signed certificates
    # using private-key written-to and read-from a temp-file, for certificate
    # verification.
    pytest --capture=tee-sys -v test_client_server_mtls.py \
            -k test_server_process_with_mtls_root_signed_cert_using_temp_pvt_key_file &

    sleep 5

    pytest --capture=tee-sys -v test_client_server_mtls.py \
            -k test_client_app_with_mtls_root_signed_cert_using_temp_pvt_key_file

    popd > /dev/null 2>&1
}

# #############################################################################
function unit-test-certlib-utility-programs() {
    echo "******************************************************************"
    echo "* Check core Certlib interfaces for utility programs"
    echo "******************************************************************"
    echo " "
    pushd utilities > /dev/null 2>&1

    # Build utilities
    make -j${NumMakeThreads} -f cert_utility.mak
    make -j${NumMakeThreads} -f policy_utilities.mak

    popd > /dev/null 2>&1

    pushd ./certifier_service/certlib/test_data > /dev/null 2>&1

    echo " "
    echo "---- Running utilities/cert_utility.exe ... ----"
    echo " "
    set -x
    ../../../utilities/cert_utility.exe                    \
        --operation=generate-policy-key-and-test-keys      \
        --policy_key_output_file=policy_key_file.bin       \
        --policy_cert_output_file=policy_cert_file.bin     \
        --platform_key_output_file=platform_key_file.bin   \
        --attest_key_output_file=attest_key_file.bin
    set +x

    set -x
    ./generate_policy.sh
    set +x

    popd > /dev/null 2>&1

    # Setup dummy libraries for Certifier Service to link with
    pushd ./certifier_service/ > /dev/null 2>&1

    cd ./graminelib/
    make dummy

    cd ../oelib
    make dummy

    cd ../isletlib/
    make dummy

    cd ../teelib
    make

    cd ../certprotos
    protoc --go_opt=paths=source_relative --go_out=. --go_opt=Mcertifier.proto= ./certifier.proto

    echo " "
    echo "---- Running certlib/go test ... ----"
    echo " "
    # Run certlib/ Go unit-tests, which use policy_key_file.bin policy_cert_file.bin
    # from test_data/ dir.
    cd ../certlib
    go test

    popd > /dev/null 2>&1

    echo " "
    echo "---- Running measurement_utility_test.sh ... ----"
    echo " "
    # Basic verification of measurement_utility.
    #
    ./tests/measurement_utility_test.sh

    # Above script will execute a utility which will generate policy_key.py
    git restore sample_apps/simple_app_python/policy_key.py

}

# #############################################################################
function test-run_example-help-list-args() {
    echo "******************************************************************"
    echo "* Exercise run_example with --help, --list arguments ..."
    echo "******************************************************************"
    echo " "
    pushd ./sample_apps > /dev/null 2>&1

    # Exercise help / usage / list options, for default simple_app
    ./run_example.sh -h
    ./run_example.sh --help
    ./run_example.sh --list
    ./run_example.sh --list simple_app

    # Re-run help / usage / list options, for simple_app_under_oe
    ./run_example.sh --help simple_app_under_oe
    ./run_example.sh --list simple_app_under_oe

    ./run_example.sh simple_app show_env
    ./run_example.sh simple_app_under_oe show_env

    # Re-run help / usage / list options, for simple_app_under_gramine
    ./run_example.sh --help simple_app_under_gramine
    ./run_example.sh --list simple_app_under_gramine

    # Re-run help / usage / list options, for simple_app_under_sev
    ./run_example.sh --help simple_app_under_sev
    ./run_example.sh --list simple_app_under_sev

    # Re-run help / usage / list options, for application_service
    ./run_example.sh --help application_service
    ./run_example.sh --list application_service

    # Re-run help / usage / list options, for simple_app_under_app_service
    ./run_example.sh --help simple_app_under_app_service
    ./run_example.sh --list simple_app_under_app_service

    ./run_example.sh --help simple_app_under_keystone
    ./run_example.sh --list simple_app_under_keystone

    ./run_example.sh --list simple_app_python

    ./run_example.sh --list multidomain_simple_app

    popd > /dev/null 2>&1
}

# #############################################################################
function test-run_example-dry-run() {
    # ---------------------------------------------------------------------
    # Exercise various interfaces in --dry-run mode. This will ensure that
    # script's execution logic will likely work for different sample apps,
    # when tested on the appropriate platform and environment.
    # ---------------------------------------------------------------------
    echo " "
    echo "******************************************************************"
    echo "* Exercise run_example with --dry-run argument ..."
    echo "******************************************************************"
    echo " "
    pushd ./sample_apps > /dev/null 2>&1

    ./run_example.sh --dry-run simple_app
    ./run_example.sh --dry-run simple_app setup
    ./run_example.sh --dry-run simple_app run_test

    ./run_example.sh --dry-run simple_app_under_oe
    ./run_example.sh --dry-run simple_app_under_oe setup
    ./run_example.sh --dry-run simple_app_under_oe run_test
    ./run_example.sh --dry-run simple_app_under_oe setup_with_auto_policy_generation_for_OE

    ./run_example.sh --dry-run simple_app_under_gramine
    ./run_example.sh --dry-run simple_app_under_gramine setup
    ./run_example.sh --dry-run simple_app_under_gramine run_test

    ./run_example.sh --dry-run simple_app_under_sev
    ./run_example.sh --dry-run simple_app_under_sev setup
    ./run_example.sh --dry-run simple_app_under_sev run_test
    ./run_example.sh --dry-run simple_app_under_sev setup_with_auto_policy_generation_for_SEV

    ./run_example.sh --dry-run application_service
    ./run_example.sh --dry-run application_service setup

    # Should do nothing but just emit usage messages
    ./run_example.sh --dry-run application_service run_test

    ./run_example.sh --dry-run simple_app_under_keystone

    ./run_example.sh --dry-run simple_app_under_islet
    ./run_example.sh --dry-run simple_app_under_islet setup
    ./run_example.sh --dry-run simple_app_under_islet run_test

    ./run_example.sh --dry-run simple_app_python

    ./run_example.sh --dry-run multidomain_simple_app
    ./run_example.sh --dry-run multidomain_simple_app setup
    ./run_example.sh --dry-run multidomain_simple_app run_test

    popd > /dev/null 2>&1
}

# #############################################################################
function test-run_example-simple_app() {
    echo "******************************************************************"
    echo "* Test: Execute script to compile, build and run simple_app."
    echo "******************************************************************"
    echo " "
    pushd ./sample_apps > /dev/null 2>&1

    ./cleanup.sh

    set -x
    # shellcheck disable=SC2009
    ps -ef | grep -E 'simpleserver|example_app.exe|run_example.sh|app_service.exe'
    set +x

    ./run_example.sh simple_app

    # Just exec app exe to produce usage info
    ./simple_app/example_app.exe

    # cp'over some certificate / policy / measurement bin files that were provisioned
    # for running the simple_app. The test cases in below test need these files to
    # invoke (& verify) the steps under the 'get-certified' target.
    pytest_data_dir="../tests/pytests/data/"

    for binfile in attest_key_file.bin \
                   policy_cert_file.bin \
                   platform_attest_endorsement.bin \
                   example_app.measurement
    do
        set -x
        cp -p simple_app/provisioning/${binfile} ${pytest_data_dir}
        set +x
    done

    # Rebuild shared library that pytest needs
    pushd ../src > /dev/null 2>&1
    NO_ENABLE_SEV=1 make -f certifier.mak --always-make -j${NumMakeThreads} sharedlib
    popd > /dev/null 2>&1

    ./cleanup.sh

    # Re-start Certifier Service as script, above, would have shut it down
    ./run_example.sh simple_app start_certifier_service

    pgrep simple

    # Run Python test, in which some test cases need Certifier Service to be up.
    pushd ../ > /dev/null 2>&1

    set -x
    PYTHONUNBUFFERED=TRUE PYTHONPATH=./ \
        pytest --capture=tee-sys -v -m needs_cert_service tests/pytests/test_certifier_framework.py
    set +x

    popd > /dev/null 2>&1

    ./cleanup.sh

    popd > /dev/null 2>&1
}

# #############################################################################
function test-simple_app-with-crypto_algorithms() {
    echo "******************************************************************"
    echo "* Test: Execute script to compile, build and run simple_app."
    echo "******************************************************************"
    echo " "
    pushd ./sample_apps > /dev/null 2>&1

    ./cleanup.sh

    if [ "${Simple_app_setup_done}" = 0 ]; then
        ./run_example.sh simple_app setup
    fi
    ./run_example.sh simple_app run_test-crypto_algorithms
    ./cleanup.sh

    popd > /dev/null 2>&1
}

# #############################################################################
# Depends on: test-run_example-simple_app
# #############################################################################
function test-run_example-simple_app_python() {
    echo "*******************************************************************"
    echo "* Test: Execute script to compile, build and run simple_app_python."
    echo "*******************************************************************"
    echo " "
    pushd ./sample_apps > /dev/null 2>&1

    ./cleanup.sh

    set -x
    # shellcheck disable=SC2009
    ps -ef | grep -E 'simpleserver|example_app.exe|run_example.sh|app_service.exe'
    set +x

    pushd "${CERT_ROOT}"/src > /dev/null 2>&1

    # Do this, so this test target can be run standalone w/o prior dependencies
    # -B to re-gen protobuf files and remake shared libs w/o errors
    make -f certifier.mak -j${NumMakeThreads} -B sharedlib

    popd > /dev/null 2>&1

    # Need to run this using setup / run_test; otherwise the script will
    # delete non-Git files. That will rm the certifier_framework Py module and
    # shared libraries that was just recently built, above.
    ./run_example.sh simple_app_python setup
    ./run_example.sh simple_app_python run_test

    ./cleanup.sh
    popd > /dev/null 2>&1
}

# #############################################################################
# Test the scenario that once certified, the server-process and client-app
# can be re-started multiple times, without need for the Certifier Service.
# Re-starting the server-process will re-load the trust data from the
# policy-store. It will no longer need to contact the Certifier Service
# to get re-certified.
#
# Then, you can re-start the client-app, to talk to this now-certified
# server-process directly through secure SSL channel.
# The following sequence of steps validate this workflow and verify that
# the client and server can communicate through this secure channel.
# #############################################################################
function test-simple_app_python-with-warm-restart() {
    echo " "
    echo "*******************************************************************"
    echo "* Test Variation: Re-start server-process and client-app after shutting down the Certifier Service ..."
    echo "*******************************************************************"
    echo " "

    pushd ./sample_apps > /dev/null 2>&1

    # If this test case is being run on its own (outside of CI), we have to
    # first go through setup and then run the test. This will get the
    # server/client-apps 'certified'. After that, the meat of this test-case;
    # i.e., re-run with warm-restart can be run.
    set -x
    if [ "${Simple_app_python_setup_done}" = 0 ]; then
        ./run_example.sh rm_non_git_files
        ./run_example.sh simple_app_python setup
        ./run_example.sh simple_app_python run_test

        # This will stop the Certifier Service.
        ./cleanup.sh
    fi
    set +x

    # This invokes the 'run-app-as-server' operation in example_app.py
    # which does a warm_restart() to re-load trust data from the policy-store.
    ./run_example.sh simple_app_python run_app_as_server_offers_trusted_service

    # This invokes the 'run-app-as-client' operation in example_app.py
    # which does a warm_restart() to re-load trust data from the policy-store.
    # There is assert code way-deep-down in example_app.py that verifies that
    # the client gets an expected 'Hello' message from the server, through this
    # exchange.
    ./run_example.sh simple_app_python run_app_as_client_make_trusted_request

    popd > /dev/null 2>&1
}

# #############################################################################
function test-build-and-setup-App-Service-and-simple_app_under_app_service() {
    echo "***************************************"
    echo "* Build-and-setup Application Service "
    echo "***************************************"
    echo " "
    pushd ./sample_apps > /dev/null 2>&1

    ./run_example.sh application_service setup

    echo " "
    echo "*************************************************************"
    echo "* Build-and-setup simple_app_under_app_service/ and run_test"
    echo "*************************************************************"
    echo " "

    echo " "
    echo "---- simple_app_under_app_service/ setup ----"
    echo " "
    ./run_example.sh --no-make-clean simple_app_under_app_service setup

    # Start Certifier Service & Application Service together first.
    ./run_example.sh --no-cleanup application_service start

    # Allow some time for App Service to get Certified ...
    sleep 10

    # Once Application Service has been certified, we no longer need
    # this Certifier Service. Kill it, so app itself can start its
    # own Certifier Service.
    pgrep simpleserver

    set -x
    set +e
    kill -9 "$(pgrep simpleserver)"
    set -e
    set +x

    echo " "
    echo "---- simple_app_under_app_service run_test ----"
    echo " "

    # Now, run the test for simple_app_under_app_service
    ./run_example.sh simple_app_under_app_service run_test

    sleep 2

    # Check for 'Hi" messages from Application Service
    set -x
    tail -30 ../application_service/provisioning/appln.service.out
    set +x

    sudo ./cleanup.sh
    popd > /dev/null 2>&1

    echo " "
    echo "**** Check for any stale left-over processes ****"
    # shellcheck disable=SC2009
    ps -ef | grep -v -E 'root|^sys'
    echo " "
}

# #############################################################################
function test-run_example-multidomain_simple_app() {
    echo "************************************************************************"
    echo "* Test: Execute script to compile, build and run multidomain_simple_app."
    echo "************************************************************************"
    echo " "
    pushd ./sample_apps > /dev/null 2>&1

    ./cleanup.sh

    set -x
    # shellcheck disable=SC2009
    ps -ef | grep -E 'simpleserver|example_app.exe|run_example.sh|app_service.exe'
    set +x

    ./run_example.sh multidomain_simple_app

    ./cleanup.sh

    popd > /dev/null 2>&1
}

# #############################################################################
function test-build-and-install-sev-snp-simulator() {
    echo "*************************************************************************************"
    echo "* Build and install SEV-SNP simulator, to run Cert tests with simulated SEV-enabled."
    echo "*************************************************************************************"
    echo " "
    echo "****** WARNING! Skipped due to open issue #242, Fails on Ubuntu 22.04.4"
    echo " "
    return

    pushd ./sev-snp-simulator > /dev/null 2>&1

    make clean
    make
    make keys

    make insmod

    popd > /dev/null 2>&1
}

# #############################################################################
function test-sev-snp-simulator-sev-test() {
    echo "******************************************************************"
    echo "* Run sev-snp-simulator sev-test ... "
    echo "******************************************************************"
    echo " "
    echo "****** WARNING! Skipped due to open issue #242, Fails on Ubuntu 22.04.4"
    echo " "
    return
    pushd ./sev-snp-simulator/test > /dev/null 2>&1

    make sev-test
    sudo ./sev-test

    popd > /dev/null 2>&1
}

# #############################################################################
function test-certifier-build-and-test-simulated-SEV-mode() {
    echo "******************************************************************"
    echo "* Check that Certifier tests run clean with simulated SEV-enabled."
    echo "******************************************************************"
    echo " "
    pushd src > /dev/null 2>&1

    make -f certifier_tests.mak clean
    ENABLE_SEV=1 make -j${NumMakeThreads} -f certifier_tests.mak
    sudo ./certifier_tests.exe --print_all=true

    echo " "
    echo "******************************************************************"
    echo "* Check that Certifier builds with simulated SEV-enabled."
    echo "******************************************************************"
    echo " "
    make -f certifier.mak clean
    make -f certifier_tests.mak clean
    ENABLE_SEV=1 make -j${NumMakeThreads} -f certifier.mak

    popd > /dev/null 2>&1

    # Run script that will setup s/w required to build Policy Generator for SEV-app
    ./CI/scripts/setup-JSON-schema-validator-for-SEV-apps.sh
}

# #############################################################################
function test-simple_app_under_sev-simulated-SEV-mode() {
    echo "******************************************************************"
    echo "* Run simple_app_under_sev in simulated-SEV environment."
    echo "******************************************************************"
    echo " "
    echo "****** WARNING! Skipped due to open issue #242, Fails on Ubuntu 22.04.4"
    echo " "
    return
    pushd ./sample_apps > /dev/null 2>&1

    ./run_example.sh rm_non_git_files
    ./run_example.sh simple_app_under_sev setup
    sudo ./run_example.sh simple_app_under_sev run_test

    sudo ./cleanup.sh

    popd > /dev/null 2>&1

    cd "${CERT_ROOT}"/sev-snp-simulator

    # On CI this is not needed, but you may need this in your dev-box
    # so that you can re-run tests and not run into failures from 'insmod'
    make rmmod

    cd "${CERT_ROOT}"
}

# #############################################################################
function test-simple_app_under_keystone-using-shim() {
    echo "********************************************"
    echo "* Run simple_app_under_keystone using shim"
    echo "********************************************"
    echo " "
    pushd ./sample_apps > /dev/null 2>&1

    ./run_example.sh rm_non_git_files
    ./run_example.sh simple_app_under_keystone setup
    ./run_example.sh simple_app_under_keystone run_test

    ./cleanup.sh
    popd > /dev/null 2>&1
}

# #############################################################################
function test-ISLET-SDK-shim_test() {
    echo "**********************************************************"
    echo "* Download ISLET SDK, build the library and run shim_test"
    echo "**********************************************************"
    echo " "

    pushd src/islet > /dev/null 2>&1

    ../../third_party/islet/setup.sh

    echo " "
    set -x
    cd islet_test/
    make clean
    make shim_test

    echo " "
    make attest_seal_test
    set +x
    echo " "

    popd > /dev/null 2>&1
}

# #############################################################################
function test-run_example-simple_app_under_islet-using-shim() {
    echo "***********************************************************************************"
    echo "* Test: Execute script to compile, build and run simple_app_under_islet using shim"
    echo "***********************************************************************************"
    echo " "

    pushd ./sample_apps > /dev/null 2>&1

    ./cleanup.sh

    ./run_example.sh rm_non_git_files

    # Break it up into setup / run_test, to verify that the run_test phase
    # also correctly establishes LD_LIBRARY_PATH internally.
    ./run_example.sh simple_app_under_islet setup
    ./run_example.sh simple_app_under_islet run_test

    ./cleanup.sh

    popd > /dev/null 2>&1
}

# #############################################################################
function test_case_template() {
    echo " "
}

# #############################################################################
function run_test() {
    test_fnname=$1
    echo "${Me}: $(TZ="America/Los_Angeles" date) Executing ${test_fnname} ..."
    echo " "
    ${test_fnname}
}

# #############################################################################
# Run through the list of test-cases in TestList[] and execute each one.
# #############################################################################
function test_all() {
    from_test=$1
    msg="Certifier Framework test execution"
    if [ "${from_test}" = "" ]; then
        exec_msg="Started ${msg}"
    else
        exec_msg="Resumed ${msg} from ${from_test}"
    fi

    echo "${Me}: $(TZ="America/Los_Angeles" date) ${exec_msg} ..."
    echo " "

    start_seconds=$SECONDS
    for str in "${TestList[@]}"; do

        # Skip tests if we are resuming test execution using --from-test
        if [ "${from_test}" != "" ] && [ "${from_test}" != "${str}" ]; then
            continue
        fi
        This_fn="${str}"
        # shellcheck disable=SC2086
        run_test $str

        from_test=""    # Reset, so we can continue w/next test.
    done
   # Computed elapsed hours, mins, seconds from total elapsed seconds
   total_seconds=$((SECONDS - start_seconds))
   el_h=$((total_seconds / 3600))
   el_m=$((total_seconds % 3600 / 60))
   el_s=$((total_seconds % 60))

   echo " "
   echo "${Me}: $(TZ="America/Los_Angeles" date) Completed ${msg}: ${total_seconds} s [ ${el_h}h ${el_m}m ${el_s}s ]"

}
# ##################################################################
# main() begins here
# ##################################################################

if [ $# -eq 1 ]; then
    if [ "$1" == "--help" ]; then
        usage
        exit 0
    elif [ "$1" == "--list" ]; then
        list_tests
        exit 0
    fi
fi

# ------------------------------------------------------------------------
# Fast-path execution support. You can invoke this script specifying the
# name of one of the functions to execute a specific set of tests.
# This way, one can debug script changes to ensure that test-execution
# still works.
# ------------------------------------------------------------------------
if [ $# -ge 1 ]; then

    if [ "$1" == "--from-test" ]; then
        if [ $# -eq 1 ]; then
            echo "${Me}: Error --from-test needs the name of a test-function to resume execution from."
            exit 1
        fi
        # Resume test execution from named test-function
        # shellcheck disable=SC2048,SC2086
        test_all $2
        exit 0
    fi

    This_fn=$1
    # shellcheck disable=SC2048,SC2086
    run_test $*
    exit 0
fi

test_all ""
