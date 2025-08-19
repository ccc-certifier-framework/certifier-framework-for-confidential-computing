Description of cf_osutility


Here are the calling arguments for cf-utility which is a command line program.
cf_osutility uses gflags to manage command line arguments,so if
arguments are not specified, the defaults indicated below are used.

cf-osutility.exe
    --cf_utility_help=false
    --init_trust=false
    --reinit_trust=false
    --generate_symmetric_key=false
    --generate_public_key=false
    --get_item=false
    --put_item=false
    --print_cryptstore=true
    --save_cryptstore=false

    --enclave_type="sev-enclave"
    --policy_domain_name=datica_file_share_1
    --policy_key_file=policy_cert_file.policy_domain_name
    --policy_store_filename=MUST-SPECIFY-IF-NEEDED
    --encrypted_cryptstore_filename=MUST-SPECIFY
    --sealed_cryptstore_key_filename=MUST-SPECIFY
    --keyname="store_encryption_key_1"
    --symmetric_algorithm=aes-256-gcm
    --public_key_algorithm=rsa_2048

    --tag=MUST-SPECIFY-IF-NEEDED
    --entry_version=MUST-SPECIFY-IF-NEEDED
    --type=MUST-SPECIFY-IF-NEEDED

    --certifier_service_URL=MUST-BE-SPECIFIED-IF-NEEDED
    --service_port=port-for-certifier-service, MUST-BE-SPECIFIED-IF-NEEDED

    --output_format=key-message-serialized-protobuf
    --input_format=key-message-serialized-protobuf
    --input_file=in_1
    --output_file=out_1

    SEV enclave specific
    --ark_cert_file=./service/milan_ark_cert.der"
    --ask_cert_file=./service/milan_ask_cert.der"
    --vcek_cert_file=./service/milan_vcek_cert.der"

    Simulated enclave specific


--------------------------------------------------------------------------


Example scenarios


Use scenarios 1

Intitialze domain and generate and store a symmetric key for
protecting, for example, a local store.

This scenario uses the utility twice
on startup, The first call certifes the OS within the security domain.
The second generates, stores and outputs a symmetric key to protect a local
resource (like a dmverity or dmcrypt enables disk).  On restart (unless a
reinit is demanded), this utility is called only once to retrieve the relevant
key.

Command flow for first scenario.

mkdir cf_management_files  // do this if the directory doesn't exist yet
cd cf_management_files     // this is where you keep store, etc.
cp $(POLICY_CERT) ./policy_cert_file.bin
For the remainder, policy_domain_name is the name of the relevant security
(policy) domain. $(VM_OS_TOOLS_BIN) is the directory containing the utility.

$(VM_OS_TOOLS_BIN)/cf-osutility.exe
    --init_trust=true
    --policy_key_file=policy_store=policy_cert_file.policy_domain_name
    --policy_store_filename=policy_store.policy_domain_name
    --enclave_type="sev-enclave"
    --sealed_cryptstore_key-filename=sealed-crypstore-key.policy_domain_name
    --encrypted_cryptstore_filename=cryptstore.policy_domain_name
    --symmetric_algorithm=aes-256-gcm
    --public_key_algorithm=rsa_2048
    --print_cryptstore=true
    --certifier_service_URL=url-of-certifier-service
    --service_port=port-for-certifier-service

What this command does

If the OS has been initialized (as determined by the policy_store)
and registered in the security domain, the only effect of this
command is to print the cryptstore if indicated.

If not, and the cryptstore does not exist, it creates a sealed key which
is used to encrypt the cryptstore and saves it in the indicated file; if
the cryptstore already exists, it recovers the key and decrypts the existing
cryptstore for the security domain.  Next, it generates a public/private
keypair of the specified type for use as the authentication keys for the
OS in this domain, these are the keys used to open an authenticated secure
channel with other OS's in this policy domain.  It the contacts the certifier
service to obtain a signed certificate for the public key.  In
other words, it basically performs a "cold_init" for the OS in the indicated
security domain.  After certification, it stores the key and the certificate
in the cryptstore for later access.  The policy store is automatically
initialized in the customary way.  The cryptstore is reencrypted and saved.

If all this works it prints "succeeded" on the standard input; otherwise,
it prints "failed".

The --reinit command does the same thing but always reinitializes the keys
and recertifies EVEN if it has already done so.  The policy key file contains
the self-signed certificate for the policy key for this security domain.

Command 2:

$(VM_OS_TOOLS_BIN)/cf-osutility.exe
    --init_trust=false
    --policy_key_file=policy_store=policy_cert_file.policy_domain_name
    --enclave_type="sev-enclave"
    --sealed_cryptstore_key_filename=sealed-crypstore-key.policy_domain_name
    --encrypted_cryptstore_filename=cryptstore.policy_domain_name
    --tag=dmcrypt-key
    --type=MUST-SPECIFY-IF-NEEDED
    --get_item=false
    --put_item=false
    --print_cryptstore=true
    --generate_symmetric_key=true
    --keyname=dmcrypt-key
    --tag=dmcrypt-key
    --type=serialized-key-message
    --print_cryptstore=true
    --save_cryptstore=false
    --output_format=serialized-protobuf
    --output_filename=new-key.bin


What this command does

This generates a symmetric key of the named type, puts it in cryptstore and
writes the unencrypted key as a serialized protobuf of type key_message.
It saves the cryptstore.  Since the version is not specified, if the
key does not already exist, it will have version 1; otherwise, the version
will be one higher than the latest pre-existing version in the store.
Note that the tag (which is used to find the entry in cryptstore) and the
key-name (which is the name of the key in the key message) are the same.

If all this works it prints "succeeded" on the standard input; otherwise,
it prints "failed".

-------------------------------------------------------------------------------

Use scenario 2

Retrieve an existing symmetric key from cryptstore for protecting, for
example, a local store.  This only requires one call.

cd cf_management_files

Command

$(VM_OS_TOOLS_BIN)/cf-osutility.exe
    --init_trust=false
    --policy_key_file=policy_store=policy_cert_file.policy_domain_name
    --enclave_type="sev-enclave"
    --sealed_cryptstore_key_filename=sealed-crypstore-key.policy_domain_name
    --encrypted_cryptstore_filename=cryptstore.policy_domain_name
    --print_cryptstore=true
    --get_item=true
    --keyname=dmcrypt-key
    --tag=dmcrypt-key
    --output_format=key_message_serialized-protobuf
    --print_cryptstore=true
    --save_cryptstore=false
    --output_format=serialized-protobuf
    --output_filename=existing-key.bin

What this command does

It searches the cryptstore for an entry with tag "dmcrypt-key."
If found, it writes the associated protobuf for the key 
with the latest version (since we specified no version number).
into the output-file and prints "suceeded;" otherwise,
it prints "failed".

--------------------------------------------------------------------------------

Semantics for cryptstore

Unlike the policy store, all items in cryptstore have versions to simplify
key rotation.  In "get" operations if unspecified, the latest version of
the key is retrieved.  In "put" operations, if unspecified, the item will
have a version 1 higher than the largest pre-existing version in the store.
Version numbers must be positive.  "0" is unspecified.  If the version is
unspecified and there is no version of the key in the store, it will be
version 1.

--------------------------------------------------------------------------------

Important usage notes

Neither this utility nor the remainder of CF, imposes any additional
requirements on the OS configurer to protect the integrity or
confidentiality of the files it uses.  The OS can (but shouldn't)
delete any of these file or rollback the files.  Generally, rollback
is a denial of service attack interfering with the ability of the
OS to provide service but is not a security violation.

cf-osutility does rely on the OS to save the files it creates across
restarts (failure to do so is a denial of service attack).  Also,
note that, in response to invocations, cf-osutility places sensitive
data in unprotected files (the --input-file and the --output-file);
it is the responsibility of the OS policy to ensure these files are
never visible outside the OS, including, by way of illustration
and not limitation as a result of saving these files.  At a minimum,
these files should be deleted.

--------------------------------------------------------------------------------
