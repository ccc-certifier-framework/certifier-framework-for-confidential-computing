Instructions

The code in this directory provides a web-like API that supports granular access
control to files over the sort of secure channel employed by the certifier.

It includes three seperate made artifacts: a google friendly test suite (compiled
into test_acl.exe), a library (acl_lib) and a standalone test that shows how to
use the API under certifier protection.  Access control (create, read, write)
permissions uses public key authentication (under an identity key hierarchy that
can be independent of the certifier trust heirearchy).

The current API is:

bool rpc_authenticate_me(const string& principal_name, const string& creds, string* output)
  input: name (string)  Note: verification algorithm determines crypt algorithm
         creds: serialized credentials
  output: status (bool), nonce(bytes)
bool rpc_verify_me(const string& principal_name, const string& signed_nonce)
  input: name-of-principal (string), signed_nonce (bytes)
  output: status (bool)
bool rpc_open_resource(const string& resource_name, const string& access_right)
  input: resource-name (string), access-right (string)
  output: status (bool)
bool rpc_read_resource(const string& resource_name, int num_bytes, string* bytes_read)
  input: resource-name (string), num-bytes (int32)
  output: status (bool), output (bytes)
bool rpc_write_resource(const string& resource_name, const string& bytes_to_write)
  input: resource-name (string), num-bytes (int32), buffer (bytes)
  output: status (bool)
bool rpc_close_resource(const string& resource_name)
  input: resource-name (string)
  output: status
bool rpc_add_access_right(const string& resource_name, const string& delegated_principal,
                          const string& right)

Later we should implement:
rpc_create_resource
rpc_delete_resource
rpc_add_principal

Check test_acl.cc for examples.  To run the test you should have two test directories
./test_data and ./test_data with two files: file_1 and file_2.

To build the google test in .:
  make clean -f standalone_acl_lib_test.mak
  make -f standalone_acl_lib_test.mak
  ./test_acl.exe [--print_all=true]

To build the acl_lib library (after the certifier library has been build):
  make clean -f acl_lib.mak
  make -f acl_lib.mak
You must also either copy certifier.proto (from $CERTIFIER_PROTOTYPE/certifier_service/certprotos)
into acl_lib OR create a symbolic link to it.

To build the standalone demonstration app:
  make clean -f standalone_app.mak
  make -f standalone_app.mak

To run the standalone app, you must prepare needed test files in the
test_data directory as follows:

Step 1
  First, create a policy key and cert (just as in the sample apps) by
  running the following command in ./test_data:
  export CERT_UTILS= CERTIFIER_PROTOTYPE/utilities
  $CERT_UTILS/cert_utility.exe --operation=generate-policy-key  \
                   --policy_key_output_file=policy_key_file.bin \
                   --policy_cert_output_file=policy_cert_file.bin

cd ..
The standalone app uses simulated certifier keys.  You could make
minor modifications in it to run in a certifier supported enclave.
Step 2:
  Make additional channel keys (auth keys and certs for channel):
    ./standalone_app.exe --operation=make_additional_channel_keys
  Make the identity keys, files and access policy:
    ./standalone_app.exe --operation=make_access_keys_and_files
  After all the required files are constucted, you can check all the input:
    ./standalone_app.exe --operation=test_constructed_keys_and_files
Step 3:
  Now you can start the channel:
  In one window, start the server:
    ./standalone_app.exe --operation=run_as_server
  In another window, start the client:
    ./standalone_app.exe --operation=run_as_client

