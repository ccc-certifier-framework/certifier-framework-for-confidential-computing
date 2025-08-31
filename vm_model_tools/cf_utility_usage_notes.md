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
    --data_dir=./cf_data
    --policy_domain_name=datica_file_share_1
    --policy_key_file=policy_cert_file.policy_domain_name
    --policy_store_filename=MUST-SPECIFY-IF-NEEDED
    --encrypted_cryptstore_filename=MUST-SPECIFY
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
    --ark_cert_file=./service/milan_ark_cert.der
    --ask_cert_file=./service/milan_ask_cert.der
    --vcek_cert_file=./service/milan_vcek_cert.der

    Simulated enclave specific


--------------------------------------------------------------------------

Use scenarios 1

Intitialze domain and generate and store a symmetric key for
protecting, for example, a local store.

This scenario uses the utility twice on startup, The first call certifes the VM
within the security domain.  The second generates, stores and outputs a
symmetric key to protect a local resource (like a dmverity or dmcrypt enables
disk).  On restart (unless a reinit is demanded), this utility is called only
once to retrieve the relevant key.

For detailed instructions, see examples/scenario1/instructions.md

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
