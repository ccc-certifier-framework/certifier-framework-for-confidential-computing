Warning and instructions

The code in this directory is EXPERIMENTAL.  It is included to illustrate
how one might provide a web-like API that supports granular access control to files
over the sort of secure channel employed by the certifier.  No other code relies
on this and it is not compiled into any other code here.  We plan to modify
the experimental code so that it can be compiled as a sub-library but we have
not yet done so.

If you try to link this code into the certifier right now, it will fail because
of duplicated symbols.  However, the "stand alone" tests work if you follow the
instructions below.

This is an experimental library that implements an API over a protected
channel implementing additional authentication of principals (say, an
organization) and implementing granular (file level for the prototype) access
control.  The main authentication mechanism is public key based.

The current API is:

bool rpc_authenticate_me(const string& principal_name, string* output)
  input: name (string)  Note: verification algorithm determines crypt algorithm
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

Check test_acl.cc for examples.  To run the test you should have a directory ./tmp with
two files: file_1 and file_2.

There are some duplicated certifier definitions in acl_lib.proto and there are duplicated
support functions in acl_support.cc.

You should make a directory for test data to run tests, in
CERTIFIER_PROTOTYPE/acl_lib/test_data:
  mkdir test_data
which shoulkd contain the files file_1 and file_2
To rest with the standalone_app, first generate certifier keys:
export CERT_UTILS=../../utilities
$CERT_UTILS/cert_utility.exe --operation=generate-policy-key  \
                   --policy_key_output_file=policy_key_file.bin \
                   --policy_cert_output_file=policy_cert_file.bin
cd ..

Make additional channel keys (auth keys and certs for channel):
./standalone_app.exe --operation=make_additional_channel_keys
Make the identity keys, files and access policy:
./standalone_app.exe --operation=make_access_keys_and_files
After all the required files are constucted, you can check all the input:
./standalone_app.exe --operation=test_constructed_keys_and_files
Now you can start the channel:
In one window, start the server:
./standalone_app.exe --operation=run_as_server
In another window, start the client:
./standalone_app.exe --operation=run_as_client

