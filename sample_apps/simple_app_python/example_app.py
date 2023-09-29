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
POLICY_HOST                     = 'localhost'
POLICY_HOST_PORT                = 8123
POLICY_STORE                    = 'store.bin'
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
    print('INITIALIZED_CERT_SIZE = ', policy_key.INITIALIZED_CERT_SIZE)
    print('INITIALIZED_CERT[] size = ', len(policy_key.INITIALIZED_CERT))

    parsed_args = parseargs(args)
    return True

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
                        , help='Platform endorsement of attest key, default: '
                                + PLATFORM_ATTEST_ENDORSEMENT)

    parser.add_argument('--platform_file_name', dest='pf_file_name'
                        , metavar='<platform-certificate-file>'
                        , help='Platform certificate file name, default: '
                                + PLATFORM_CERT_FILE)

    parser.add_argument('--policy_host', dest='policy_host'
                        , metavar='<policy-host-address>'
                        , help='Address for policy server, default: '
                                + POLICY_HOST)

    parser.add_argument('--policy_port', dest='policy_port'
                        , metavar='<port-number>'
                        , help='Port number for policy server, default: '
                                + str(POLICY_HOST_PORT))

    parser.add_argument('--policy_store_file', dest='policy_store_file'
                        , metavar='<policy-store>'
                        , help='Policy store file, default: ' + POLICY_STORE)

    parser.add_argument('--server_app_host', dest='server_app_host'
                        , metavar='<server-app-host>'
                        , help='Address for app server, default: '
                                + SERVER_APP_HOST)

    parser.add_argument('--server_app_port', dest='server_app_port'
                        , metavar='<port-number>'
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
