#!/usr/bin/env python3
################################################################################
# main.py
################################################################################
"""
Python simple-app to demonstrate use of Certifier Framework APIs.
"""
import sys
import os
import ssl
import socket
import argparse
from inspect import currentframe

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
PROVISIONING_DIR                = './provisioning'
EXAMPLE_MEASUREMENT             = 'example_app.measurement'
APP_OP_TYPES                    = 'cold-init, get-certified, run-app-as-client, run-app-as-server'
PLATFORM_ATTEST_ENDORSEMENT     = 'platform_attest_endorsement.bin'
PLATFORM_CERT_FILE              = 'platform_file.bin'
POLICY_STORE                    = 'store.bin'
POLICY_HOST                     = 'localhost'
POLICY_HOST_PORT                = 8123
SERVER_APP_HOST                 = '127.0.0.1'
SERVER_APP_PORT                 = 8124

# ------------------------------------------------------------------------------
# Script global symbols to app-data dirs.
SERVER_APP_DATA='app2_data'
PROVISIONING_DIR='./provisioning'

# Basenames for output files created to persist certificates and keys
APPLN_CERT_SIGNED_BY_ROOT_CA = 'appln.PEM.cert'
APPLN_KEYF_SIGNED_BY_ROOT_CA = 'appln.PEM.key'
ROOT_CA_POLICY_CERT          = 'ca_root.PEM.cert'

###############################################################################
# main() driver
###############################################################################
def main():
    """
    Shell to call do_main() with command-line arguments.
    """
    do_main(sys.argv[1:])

###############################################################################
# pylint: disable=too-many-locals
# pylint: disable=too-many-statements
# pylint: disable=too-many-branches
def do_main(args) -> bool:
    """
    Main driver for parsing arguments and run the simple-app client / server
    components.
    """
    parsed_args = parseargs(args)

    attest_key_file         = parsed_args.attest_key_file
    # Will vary when invoked by client (app1_data) v/s server (app2_data)
    appln_data_dir          = parsed_args.appln_data_dir.rstrip('/')
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
        print('pf_file_name = ', pf_file_name)
        print('appln_data_dir = ', appln_data_dir)

    purpose = 'authentication'
    enclave_type = 'simulated-enclave'
    store_file = os.path.join(appln_data_dir, policy_store_file)

    cctm = cfm.cc_trust_manager(enclave_type, purpose, store_file)

    if print_all:
        print('Size of bytes() array =', len(bytes(policy_key.INITIALIZED_CERT)))

    # -------------------------------------------------------------------------
    # Convert policy_key certificate to a byte-stream
    result = cctm.init_policy_key(bytes(policy_key.INITIALIZED_CERT))
    if result is False:
        print(fnl(), 'Cannot init policy key\n')
        sys.exit(1)

    # -------------------------------------------------------------------------
    # Open hard-coded key / platform endorsement & app-measurement files
    # and read-in data as a bytestream.
    attest_key_file_name = os.path.join(appln_data_dir, attest_key_file)
    with open(attest_key_file_name, 'rb') as attest_key_file_fh:
        attest_key_bin = attest_key_file_fh.read()

    measurement_file_name = os.path.join(appln_data_dir, measurement)
    with open(measurement_file_name, 'rb') as measurement_fh:
        example_app_measurement = measurement_fh.read()

    attest_endorsement_file_name = os.path.join(appln_data_dir, pf_attest_endorsement)
    with open(attest_endorsement_file_name, 'rb') as attest_endorsement_fh:
        platform_attest_endorsement_bin = attest_endorsement_fh.read()

    if print_all:
        print('attest_key_file_name         =', attest_key_file_name,
              ', attest_key_bin len =', len(attest_key_bin))

        print('measurement_file_name        =', measurement_file_name,
              ', measurement len = ', len(example_app_measurement))

        print('attest_endorsement_file_name =', attest_endorsement_file_name,
              ', pf_attest_endorsement_bin =', len(platform_attest_endorsement_bin))
        print(' ')

    result = cctm.python_initialize_simulated_enclave(attest_key_bin,
                                                      example_app_measurement,
                                                      platform_attest_endorsement_bin)
    if result is False:
        print(fnl(), 'Cannot initialize enclave of type', enclave_type,
                     'for purpose of', purpose, '\n')
        sys.exit(1)

    public_key_alg = "rsa-2048"
    symmetric_key_alg = "aes-256-cbc-hmac-sha256"
    whoami = 'unknown'

    # -------------------------------------------------------------------------
    # Should succeed with valid key algorithm names, after policy key has been
    # initialized
    if operation == 'cold-init':
        result = cctm.cold_init(public_key_alg, symmetric_key_alg,
                                'simple-app-home_domain',
                                policy_host, policy_port,
                                server_app_host, server_app_port)
        if result is False:
            print(fnl(), 'cold-init failed\n')
            sys.exit(1)

    elif operation == 'get-certified':
        result = cctm.warm_restart()
        if result is False:
            print(fnl(), 'warm_restart() failed\n')
            sys.exit(1)

        result = cctm.certify_me()
        if result is False:
            print(fnl(), 'certify_me() failed\n')
            sys.exit(1)

        # Server will persist required files upon certification.
        if appln_data_dir.endswith(SERVER_APP_DATA):
            whoami = 'server'
            # Persist cert-and-key files in the provisioning dir.
            write_cert_pvt_key_to_files(cctm, whoami, PROVISIONING_DIR, print_all)

    # -------------------------------------------------------------------------
    elif operation == 'run-app-as-server':
        print(operation)

        result = cctm.warm_restart()
        if result is False:
            print(fnl(), 'warm_restart() failed\n')
            sys.exit(1)

        result = server_dispatch(PROVISIONING_DIR,
                                 server_app_host, server_app_port)
        if result is False:
            print(fnl(), 'server_dispatch() failed\n')
            sys.exit(1)

    # -------------------------------------------------------------------------
    elif operation == 'run-app-as-client':
        print(operation)
        result = cctm.warm_restart()
        if result is False:
            print(fnl(), 'warm_restart() failed\n')
            sys.exit(1)

        result = cctm.cc_auth_key_initialized_ and cctm.cc_policy_info_initialized_
        if result is False:
            print(fnl(), 'Trust data is not initialized\n')
            sys.exit(1)

        result = cctm.primary_admissions_cert_valid_
        if result is False:
            print(fnl(), 'Primary admisison cert is not valid\n')
            sys.exit(1)

        result = client_dispatch(PROVISIONING_DIR,
                                 server_app_host, server_app_port)
        if result is False:
            print(fnl(), 'client_dispatch() failed\n')
            sys.exit(1)

    return result

###############################################################################
def write_cert_pvt_key_to_files(cctm, whoami, data_dir, print_all):
    """
    Persist certificate(s) and private-keys that have been established as
    part of certification. Data from cc_trust_manager{} is written to disk,
    so that, later, Python interfaces requiring certificates can use this
    data from file(s).
    """
    assert whoami == 'server'

    print('cc_auth_key_initialized_ = ', cctm.cc_auth_key_initialized_)
    print('primary_admissions_cert_valid_ = ', cctm.primary_admissions_cert_valid_)

    cert_outfile = os.path.join(data_dir, APPLN_CERT_SIGNED_BY_ROOT_CA)
    pkey_outfile = os.path.join(data_dir, APPLN_KEYF_SIGNED_BY_ROOT_CA)

    ca_root_outfile = os.path.join(data_dir, ROOT_CA_POLICY_CERT)
    dump_cert_to_file(cctm.serialized_primary_admissions_cert_,
                      cert_outfile, print_all)

    dump_private_key_to_file(cctm, pkey_outfile, print_all)

    dump_cert_to_file(cctm.serialized_policy_cert_, ca_root_outfile, print_all)

###############################################################################
def server_dispatch(data_dir, server_app_host, server_app_port):
    """
    Start a server process listening on a SSL socket waiting for client input.
    """
    print(fnl(), 'Start server process ...\n')

    # Server needs to authenticate the client; hence 'Purpose.CLIENT_AUTH'
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED

    cert_outfilename = os.path.join(data_dir, APPLN_CERT_SIGNED_BY_ROOT_CA)
    key_outfilename  = os.path.join(data_dir, APPLN_KEYF_SIGNED_BY_ROOT_CA)
    context.load_cert_chain(certfile = cert_outfilename, keyfile = key_outfilename)

    ca_root_outfilename = os.path.join(data_dir, ROOT_CA_POLICY_CERT)
    context.load_verify_locations(cafile = ca_root_outfilename)

    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bindsocket.bind((server_app_host, server_app_port))
    bindsocket.listen(10)
    print('\n', fnl(), 'Waiting for client ...')

    new_socket, fromaddr = bindsocket.accept()
    print('\n', fnl(), 'Client connected: ', fromaddr[0], ":", fromaddr[1])

    secure_sock = context.wrap_socket(new_socket, server_side=True)

    try:
        data = secure_sock.recv(1024)
        print('\n', fnl(), 'Received from client: ', str(data, 'UTF-8'))

        ret_hdr = 'Return back to client: '
        print('\n', fnl(), 'Return message back to client:', ret_hdr + str(data, 'UTF-8'))
        secure_sock.write(bytes(ret_hdr, 'UTF-8') +  data)
    finally:
        secure_sock.close()
        bindsocket.close()

    return True

###############################################################################
def client_dispatch(data_dir, server_app_host, server_app_port):
    """
    Start a client app that sends a message via secure SSL connection.
    """
    print(fnl(), 'Start client application process ...\n')

    # Client needs to authenticate the server; hence 'Purpose.SERVER_AUTH'
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED

    cert_outfilename = os.path.join(data_dir, APPLN_CERT_SIGNED_BY_ROOT_CA)
    key_outfilename  = os.path.join(data_dir, APPLN_KEYF_SIGNED_BY_ROOT_CA)
    context.load_cert_chain(certfile = cert_outfilename, keyfile = key_outfilename)

    ca_root_outfilename = os.path.join(data_dir, ROOT_CA_POLICY_CERT)
    context.load_verify_locations(cafile = ca_root_outfilename)

    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.setblocking(1)
    bindsocket.connect((server_app_host, server_app_port))

    secure_sock = context.wrap_socket(bindsocket, server_side=False,
                                      server_hostname=server_app_host)

    send_msg = 'hello'
    try:
        secure_sock.send(bytes(send_msg, 'UTF-8'))

        recv_data = secure_sock.recv(1024)
        recv_data_str = str(recv_data, 'UTF-8')

        print('\n', fnl(), 'Received message from server:', recv_data_str)

        # Server should have prepended this to our message and returned it
        assert recv_data_str == 'Return back to client: ' + send_msg
    finally:
        secure_sock.close()
        bindsocket.close()
    return True

###############################################################################
def dump_cert_to_file(der_cert, outfile, print_all):
    """
    Dump an input certificate 'der_cert' in DER-format to an output file in a
    known hard-coded provisioning dir. This helper routine exists to exchange
    in-memory certificate(s) to invoke SSL interfaces that need a file-handle
    to get a certificate.
    """
    pem_cert = ssl.DER_cert_to_PEM_cert(bytes(der_cert, encoding='utf-8',
                                               errors = 'surrogateescape'))

    with open(outfile, 'wt', encoding = 'UTF-8') as outf:
        outf.write(pem_cert)

    if print_all:
        print('\n**** Dumped certificate in PEM-format to:', outfile)

###############################################################################
def dump_private_key_to_file(cctm, outfile, print_all):
    """
    Dump in PEM-format the private key for the certificate.
    We invoke a trust-manager's method to externalize the private key
    to disk.
    NOTE: Here, we are writing out the private-key to a file on the file-system.
          This is being done just to get the end-to-end flow of this app
          working and demo'able. Exposing this private key is known to be
          a potential security hole, and is something that we will have to
          rework eventually.
    """
    result = cctm.write_private_key_to_file(outfile)
    if result is False:
        print(fnl(), 'Error writing out private-key to file', outfile)
        sys.exit(1)

    if print_all:
        print('\n**** Dumped private key in PEM-format to:', outfile)

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
                        , help='Attestation key file name, default: '
                                + ATTEST_KEY_FILE)

    parser.add_argument('--data_dir', dest='appln_data_dir'
                        , metavar='<app-data-dir>'
                        , default=APP_DATA_DIR
                        , help='Directory for application data, default: '
                                + APP_DATA_DIR)

    parser.add_argument('--measurement_file', dest='measurement'
                        , metavar='<example-app-measurement>'
                        , default=EXAMPLE_MEASUREMENT
                        , help='Sample app measurement file, default: '
                                + EXAMPLE_MEASUREMENT)

    parser.add_argument('--operation', dest='operation'
                        , metavar='<operation-type>'
                        , help='Operation to perform, one of: '
                                + APP_OP_TYPES)

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

    parser.add_argument('--print_all', dest='print_all'
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

# ------------------------------------------------------------------------------
def fnl():
    """
    Return calling function's brief-name and line number
    Ref: https://stackoverflow.com/questions/35701624/pylint-w0212-protected-access
    ... for why we need for use of pylint disable directive.
    """
    curr_fr = currentframe()
    # pylint: disable=protected-access
    fn_name = curr_fr.f_back.f_code.co_name
    # pylint: enable=protected-access
    line_num = curr_fr.f_back.f_lineno
    return fn_name + ':' + str(line_num)

###############################################################################
# Start of the script: Execute only if run as a script
###############################################################################
if __name__ == "__main__":
    main()
