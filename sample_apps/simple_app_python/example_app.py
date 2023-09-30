#!/usr/bin/env python3
################################################################################
# main.py
################################################################################
"""
Python simple-app to demonstrate use of Certifier Framework APIs.
"""
import sys
import os
import argparse

import policy_key
import certifier_framework as cfm

###############################################################################
# Global Variables: Used in multiple places. List here for documentation
###############################################################################

# Resolves to: <Certifier-Root>/sample_apps/simple_app_python
THIS_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# Script defaults
ATTEST_KEY_FILE                 = 'attest_key_file.bin'
APP_DATA_DIR                    = './app1_data/'
EXAMPLE_MEASUREMENT             = 'example_app.measurement'
APP_OP_TYPES                    = 'cold-init, get-certified, run-app-as-client, run-app-as-server'
PLATFORM_ATTEST_ENDORSEMENT     = 'platform_attest_endorsement.bin'
PLATFORM_CERT_FILE              = 'platform_file.bin'
POLICY_STORE                    = 'store.bin'
POLICY_HOST                     = 'localhost'
POLICY_HOST_PORT                = 8123
SERVER_APP_HOST                 = 'localhost'
SERVER_APP_PORT                 = 8124

###############################################################################
# main() driver
###############################################################################
def main():
    """
    Shell to call do_main() with command-line arguments.
    """
    do_main(sys.argv[1:])

###############################################################################
def do_main(args) -> bool:
    """
    Main driver for parsing arguments and run the simple-app client / server
    components.
    """
    parsed_args = parseargs(args)

    attest_key_file         = parsed_args.attest_key_file
    app1_data_dir           = parsed_args.app1_data_dir.rstrip('/')
    measurement             = parsed_args.measurement
    operation               = parsed_args.operation
    pf_attest_endorsement   = parsed_args.pf_attest_endorsement
    pf_file_name            = parsed_args.pf_file_name
    policy_host             = parsed_args.policy_host
    policy_port             = parsed_args.policy_port
    policy_store_file       = parsed_args.policy_store_file
    server_app_host         = parsed_args.server_app_host
    server_app_port         = parsed_args.server_app_port
    print_all               = parsed_args.print_all

    if print_all:
        print('INITIALIZED_CERT_SIZE = ', policy_key.INITIALIZED_CERT_SIZE)
        print('INITIALIZED_CERT[] size = ', len(policy_key.INITIALIZED_CERT))

    purpose = 'authentication'
    enclave_type = 'simulated-enclave'
    store_file = app1_data_dir + '/' + policy_store_file

    cctm = cfm.cc_trust_manager(enclave_type, purpose, store_file)

    # -------------------------------------------------------------------------
    # Open the Certificate binary file for reading
    with open(app1_data_dir + '/policy_cert_file.bin', 'rb') as cert_file:
        cert_bin = cert_file.read()

    if print_all:
        print('Size of bytes() array =', len(bytes(policy_key.INITIALIZED_CERT)))

    # result = cctm.init_policy_key(cert_bin)
    result = cctm.init_policy_key(bytes(policy_key.INITIALIZED_CERT))
    assert result is True

    # -------------------------------------------------------------------------
    # Open hard-coded key / platform endorsement & app-measurement files
    # and read-in data as a bytestream.
    attest_key_file_name = app1_data_dir + '/' + attest_key_file
    with open(attest_key_file_name, 'rb') as attest_key_file_fh:
        attest_key_bin = attest_key_file_fh.read()

    measurement_file_name = app1_data_dir + '/' + measurement
    with open(measurement_file_name, 'rb') as measurement_fh:
        example_app_measurement = measurement_fh.read()

    attest_endorsement_file_name = app1_data_dir + '/' + pf_attest_endorsement
    with open(attest_endorsement_file_name, 'rb') as attest_endorsement_fh:
        platform_attest_endorsement_bin = attest_endorsement_fh.read()

    if print_all:
        print('attest_key_file_name         =', attest_key_file_name,
              ', attest_key_bin len =', len(attest_key_bin))

        print('measurement_file_name        =', measurement_file_name,
              ', measurement len = ', len(example_app_measurement))

        print('attest_endorsement_file_name =', attest_endorsement_file_name,
              ', pf_attest_endorsement_bin =', len(platform_attest_endorsement_bin))
        print(' ');

    result = cctm.python_initialize_simulated_enclave(attest_key_bin,
                                                      example_app_measurement,
                                                      platform_attest_endorsement_bin)
    assert result is True

    public_key_alg = "rsa-2048"
    symmetric_key_alg = "aes-256-cbc-hmac-sha256"

    # -------------------------------------------------------------------------
    # Should succeed with valid key algorithm names, after policy key has been
    # initialized
    if operation == 'cold-init':
        result = cctm.cold_init(public_key_alg, symmetric_key_alg,
                                'simple-app-home_domain',
                                policy_host, policy_port,
                                server_app_host, server_app_port)
        assert result is True

    elif operation == 'get-certified':
        result = cctm.warm_restart()
        assert result is True

        result = cctm.certify_me()
        assert result is True

    return result

###############################################################################
# Argument Parsing routine
def parseargs(args):
    """
    Command-line argument parser. Use './example_app.py --help' to get usage info.
    """
    # ======================================================
    # Start of argument parser, with inline examples text
    # Create 'parser' as object of type ArgumentParser
    # ======================================================
    parser  = argparse.ArgumentParser(description='Certifier Framework: Simple App',
                                      formatter_class=argparse.RawDescriptionHelpFormatter,
                                      epilog=r'''Examples:
- Basic usage:

  simple_app_python/example_app.py
''')

    # Define arguments supported by this script
    parser.add_argument('--attest_key_file', dest='attest_key_file'
                        , metavar='<attest-key-file-name>'
                        , default=ATTEST_KEY_FILE
                        , help='Attestation key file name, default: ' + ATTEST_KEY_FILE)

    parser.add_argument('--data_dir', dest='app1_data_dir'
                        , metavar='<app-data-dir>'
                        , default=APP_DATA_DIR
                        , help='Directory for application data, default: ' + APP_DATA_DIR)

    parser.add_argument('--measurement_file', dest='measurement'
                        , metavar='<example-app-measurement>'
                        , default=EXAMPLE_MEASUREMENT
                        , help='Sample app measurement file, default: ' + EXAMPLE_MEASUREMENT)

    parser.add_argument('--operation', dest='operation'
                        , metavar='<operation-type>'
                        , help='Operation to perform, one of: ' + APP_OP_TYPES)

    parser.add_argument('--platform_attest_endorsement', dest='pf_attest_endorsement'
                        , metavar='<attest-endorsement-bin-file>'
                        , default=PLATFORM_ATTEST_ENDORSEMENT
                        , help='Platform endorsement of attest key, default: '
                                + PLATFORM_ATTEST_ENDORSEMENT)

    parser.add_argument('--platform_file_name', dest='pf_file_name'
                        , metavar='<platform-certificate-file>'
                        , default=PLATFORM_CERT_FILE
                        , help='Platform certificate file name, default: '
                                + PLATFORM_CERT_FILE)

    parser.add_argument('--policy_host', dest='policy_host'
                        , metavar='<policy-host-address>'
                        , default=POLICY_HOST
                        , help='Address for policy server, default: '
                                + POLICY_HOST)

    parser.add_argument('--policy_port', dest='policy_port'
                        , metavar='<port-number>'
                        , default=POLICY_HOST_PORT
                        , help='Port number for policy server, default: '
                                + str(POLICY_HOST_PORT))

    parser.add_argument('--policy_store_file', dest='policy_store_file'
                        , metavar='<policy-store>'
                        , default=POLICY_STORE
                        , help='Policy store file, default: ' + POLICY_STORE)

    parser.add_argument('--server_app_host', dest='server_app_host'
                        , metavar='<server-app-host>'
                        , default=SERVER_APP_HOST
                        , help='Address for app server, default: '
                                + SERVER_APP_HOST)

    parser.add_argument('--server_app_port', dest='server_app_port'
                        , metavar='<port-number>'
                        , default=SERVER_APP_PORT
                        , help='Port number for server app server, default: '
                                + str(SERVER_APP_PORT))

    parser.add_argument('--print-all', dest='print_all'
                        , action='store_true'
                        , default=False
                        , help='Verbose print for diagnostics, default: False')

    # ======================================================================
    # Debugging support
    parser.add_argument('--debug', dest='debugScript'
                        , action='store_true'
                        , default=False
                        , help='Turn on debugging for script\'s execution')

    parsed_args = parser.parse_args(args)

    if parsed_args is False:
        parser.print_help()

    return parsed_args

###############################################################################
# Start of the script: Execute only if run as a script
###############################################################################
if __name__ == "__main__":
    main()
