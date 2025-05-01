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

One subtle issue is sidestepped by the standalone app.  An application must have a secure
way to establish trust in the identity root key. There are many ways to do this.  The
two simplest are: use the policy key as the identity root or embed the identity root
in the image.  Each application developer will have to decide this themselves based on
their needs..

Here are complete build instructions:

  As with certifier builds, let CERTIFIER_PROTOTYPE hold the name of the topmost certifier
  repository directory, something like:
     export CERTIFIER_PROTOTYPE = .../certifier-framework-for-confidential-computing/

  1.  ACL_LIB_DIR = $(CERTIFIER_PROTOTYPE/acl_lib/
  2.  Make sure $(ACL_LIB_DIR) has two sundirectories acl_test_data and test_data with the
      test files file_1 and file_2 and that there is either a copy certifier.proto
      (from $CERTIFIER_PROTOTYPE/certifier_service/certprotos) into acl_lib OR create
      a symbolic link to it.
  3.  cd $(ACL_LIB_DIR)
  4.  make clean -f standalone_acl_lib_test.mak
  5.  make -f standalone_acl_lib_test.mak
  6.  Run the test: ./test_acl.exe [--print_all=true]
  7.  Build acl_lib (We assume the certifier library has already been built). 
  8.  make clean -f acl_lib.mak  [It is important you do a clean make because
      test_acl uses a special define during comilation to allow the use of a 
      fake" channel" that is incompatible with actual use.
  8.  make -f acl_lib.mak  [This will build acl_lib.a.]
  9.  Build the standalone app.
  10. make clean -f standalone_app.mak
  11. make -f standalone_app.mak
  12. Build test keys and files.
  13. cd $(ACL_LIB_DIR)/test_data
  14. export CERT_UTILS= CERTIFIER_PROTOTYPE/utilities
  15. $CERT_UTILS/cert_utility.exe --operation=generate-policy-key  \
                    --policy_key_output_file=policy_key_file.bin \
                     --policy_cert_output_file=policy_cert_file.bin
      [This creates the policy key and policy cert.]
  16. cd $(ACL_LIB_DIR)
  17. Make additional channel keys (auth keys and certs for channel):
      ./standalone_app.exe --operation=make_additional_channel_keys
  18. Make the identity keys, files and access policy:
      ./standalone_app.exe --operation=make_access_keys_and_files
  19. After all the required files are constucted, you can check all the input:
      ./standalone_app.exe --operation=test_constructed_keys_and_files [--print_all=true]
      This displays the keys, certs and files the test uses.
  20. You can now start the test.  You should have two windows available.
  21. In one window, start the server:
      ./standalone_app.exe --operation=run_as_server
  22. In another window, start the client:
      ./standalone_app.exe --operation=run_as_client
You should see the message "client_application succeeded"

