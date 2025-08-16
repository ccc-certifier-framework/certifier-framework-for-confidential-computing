
This directory contains additional tools and libraries to make a newly supported
security model easy to implement using the Certifier.


Discussion of VM security models

Previous examples in the Certifier Framework ("CF") focused on an app-centric security model.
The app, not the OS, was the focus of isolation, the trust model and certifier artifacts.

Previously, for example, there were two such trust models for security rooted in SEV.

The simplest model is illustrated in simple_example_under_sev.  There, a single application,
usually shipped with the VM in ramdisk, is the sole user of the CF.  Since it needed access
to the SEV primitives, which are accessible via a device driver that can only be opened
by a privileged user, it was run as root.   The underlying measurement was that of the VM
kernel and the ramdisk containing the application, so, while the application was included (and
hence verifiable via Attest), the scope of the measurement was really vm-wide.  The program (app)
itself is programmed has a Linux process boundary isolating it from other applications and
it is the job of the OS to ensure that this is the only such app that runs (in the example case).

The more sophisticate model is illustrated in simple_app_under_app_service.  There, a privileged
daemon, is the only program that accesses the underlying hardware.  The service is certified
in the role of attestation, that is, it provided CC-like services (e.g. - Attest, Seal, Unseal)
for individual apps, each app is measured and certified separately, each app has its own keys, etc
and acts independantly.  Each app is isolated from other apps (trusted or not) by the OS, usually,
Linux.  Apps in this model should not be able ti interfere with each other and every such app
has independant privileges and policy, again this is apps centric.

In both of these models, the protected app does not trust any storaage except the ramdisk; all
other IO is untrusted.  New or updated apps can be run from network download or an untrusted
storage device if the OS allows it but the CF guarentees the security of each app indepentantly.

We are introducing another use model called "VM-centric" protection.  Here the OS policy still
controls what apps run at all but the SEV primitives are available to all apps.  The only
(possible) restriction, dictated by OS policy, is whether the SEV device driver is restricted
in use to privileged applications.  In this model, it the job of OS configuration and not the
CF framework to decide what apps are trusted and it must prevent untrusted apps from running
and accessing CC services.  In other words, the security policy is rooted in the OS, not the apps.
The  CF still authenticates the OS and the OS has "OS-wide" policy certified keys but the OS as
a whole is the trust boundary.  To achieve a security goal, the person that configures the OS,
might only run programs from designated integrity controlled mounted disks and only rely on
sensitive data in disks encrypted with keys protected by the CF.  This model can be useful
when a few related standard apps run especially if a goal is that they should run without
modification.  IT may also be useful in offering some additional protection to existing VM
workloads (but be careful!).

To support this model, we provide a few utilities that can be run on command line.

The most important utility has two functions:

First, it uses the CF framework to authenticate the VM, generate OS wide keys and obtain
certificates that allow mutually authenticated, encrypted and integrity protected channels
between two VM's in the same "security domain" (i.e.-VM's with trusted measurements certified by
the certifier service).  The trust model is based on the whole VM measurement (including configuration
information, and in-OS policy).

Second, it offers protected storage for these and other important keys.  For example, a program
might request access to the VM authentication keys from this utility to open secure channels.
A very simple, but important, application is to maintain protected keys that the OS uses to
ensure OS properties.  For exmaple, at startup, the OS could generate keys that are used to
provide integrity and or confidentiality properties for storage (e.g.-dmverity or dmcrypt protected
devices).  The OS generates them for initialization on first use but protects them between
activations using storage protected by the CF.  In this case, the utility simply returns unencrypted
versions of these keys.  The VM itself can actually be in multiple policy domains (identified by a
policy key just as for apps in the foregoing model).  Protected items associated with a policy domain
should use independant secure stores. These stores are managed using an (CF-encrypted) table of
keys and sensitive material under a key-storage model, called cryptstore  under the utility.

Typically, cryptstore will be used to store:
  1.  Symmetric keys (as for dmverify or dmcrypt or other storage deveices).
  2.  Private keys used as trust anchors (whose public keys have been "certified" using the CF
      just as with applications.   SSH and TLS keys are common here.
  3.  Cerificates and Certificate chains (for things like SSH and TLS) that are needed by applications or
      OS wide.

The cryptstore is very simple.  Each entry consists of a tag (like tha name of the key) which can be used
to locate the right entry, a type, which is the format of the binary string in the entry value and a
version which can be used for keys which are subsequently rotated with newly generated keys.  The type 
usually indicates type of the serialized protobuf in the value although there are other types like
X509-certificate which is just the DER encoded X509 certificate.

In the first version, the OS calls the utility and the utility either does initialization, adds a new
key or certificate to the store or retrieves and returns (in a file) the unencrypted object that was
stored. cryptstore is encrypted with a key protected by seal and must be decrypted for use.

Note that since the OS policy and associaated stores are critical to the security model, they are
included (using virtee) in the OS measurement.  These optional properties can include, for example,
  --ovmf PATH           OVMF file to calculate hash from
  --kernel PATH         Kernel file to calculate hash from
  --initrd PATH         Initrd file to calculate hash from (use with --kernel)
  --append CMDLINE      Kernel command line to calculate hash from (use with --kernel)
See the use instruction in the examples in this directory.


Here are the calling arguments.  Utility uses gflags so if not specified,
indicated defaults are used.

cf-osutility.exe
    --init-trust=true
    --reinit-trust=false
    --policy_key_file=policy_store=policy_cert_file.policy_domain_name
    --enclave_type="sev-enclave"
    --output-format=serialized-protobuf
    --input-format=serialized-protobuf
    --policy-store-filename=MUST-SPECIFY-IF-Neded
    --encrypted-cryptstore-filename=MUST-SPECIFY
    --sealed-cryptstore-key-filename=MUST-SPECIFY
    --symmetric_algorithm=aes-256-gcm
    --public_key_algorithm=_rsa_2048
    --generate-symmetric-key=false
    --generate-public-key=false
    --keyname=MUST-SPECIFY-IF-NEEDED
    --tag=MUST-SPECIFY-IF-NEEDED
    --version=MUST-SPECIFY-IF-NEEDED
    --type=MUST-SPECIFY-IF-NEEDED
    --get-item=false
    --put-item=false
    --print-cryptstore=true
    --save-cryptstore=true  // this can be false for "get" operations.
    --certifier_service_URL=MUST-BE-SPECIFIED-IF-NEEDED
    --output-format=MUST-BE-SPECIFIED-IF-NEEDED
    --input-format=MUST-BE-SPECIFIED-IF-NEEDED
    --service-port=MUST-BE-SPECIFIED-IF-NEEDED


Instructions for building and using the utility are in build.md,
you should be able to just copy and paste each step.  The subdirectory
"src" has the source code for cf-osutility and the example directories
have examples on using it and setting up the OS security domain (this
parrallels the same procedures in "simple-example".

--------------------------------------------------------------------------

Use scenarios 1

Intitialze domain and generate and store a symmetric key for
protecting, for example, a local store.

This scenario uses the utility twice
on startup, The first call certifes the OS within the security domain.
The second generates, stores and outputs a symmetric key to protect a local
resource (like a dmverity or dmcrypt enables disk).  On restart (unless a
reinit is demanded), this utility is called only once to retrieve the relevant
key.

Command flow for first

mkdir cf_management_files          // do this if the directory doesn't exist yet
cd cf_management_files
cp $(POLICY_CERT) ./policy_cert_file.bin
For the remainder, policy_domain_name is the name of the relevant security
(policy) domain. $(VM_OS_TOOLS_BIN) is the directory containing the utility.

$(VM_OS_TOOLS_BIN)/cf-osutility.exe
    --init-trust=true
    --policy_key_file=policy_store=policy_cert_file.policy_domain_name
    --policy-store-filename=policy_store.policy_domain_name
    --enclave_type="sev-enclave"
    --sealed-cryptstore-key-filename=sealed-crypstore-key.policy_domain_name
    --encrypted-cryptstore-filename=cryptstore.policy_domain_name
    --symmetric_algorithm=aes-256-gcm
    --public_key_algorithm=rsa_2048
    --print-cryptstore=true
    --certifier_service_URL=url-of-certifier-service
    --service-port=port-for-certifier-service

What this command does

If the OS has been initialized (as determined by the policy_store)
and resgistered in the security domain, the only effect of this
command is to print the cryptstore if indicated.

If not, and the cryptstore does not exist, it creates a sealed key which
is used to encrypt the cryptstore and saves it in the indicated file; if
the cryptstore already exists, it recovers the key and decrypts the existing
cryptstore for the security domain.  Next, it generates a public/private
keypair of the specified type for use as the authentication keys for the
OS in this domain, these are the keys used to open an authenticated secure
channel with other OS's in this policy domain.  It the contacts the certifier
service to obtain a signed certificate for the public key.  Basically performing
a "cold_init".  It stores the key and the certificate in the cryptstore for
later access.  The policy store is automatically initialized in the customary
way.  The cryptstore is reencrypted and saved.

If all this works it prints "succeeded" on the standard input; otherwise,
it prints "failed".

The --reinit command does the same thing but always reinitializes the keys
and recertifies EVEN if it has already done so.  The policy key file contains
the self-signed certificate for the policy key for this security domain.

Command 2:

$(VM_OS_TOOLS_BIN)/cf-osutility.exe
    --init-trust=false
    --policy_key_file=policy_store=policy_cert_file.policy_domain_name
    --enclave_type="sev-enclave"
    --sealed-cryptstore-key-filename=sealed-crypstore-key.policy_domain_name
    --encrypted-cryptstore-filename=cryptstore.policy_domain_name
    --tag=dmcrypt-key
    --type=MUST-SPECIFY-IF-NEEDED
    --get-item=false
    --put-item=false
    --print-cryptstore=true
    --generate-symmetric-key=true
    --keyname=dmcrypt-key
    --tag=dmcrypt-key
    --type=serialized-key-message
    --print-cryptstore=true
    --save-cryptstore=true  // this can be false for "get" operations.
    --output-format=serialized-protobuf
    --output-filename=new-key.bin


What this command does

This generates a symmetric key of the named type, puts it in cryptstore and
writes the unencrypted key as a serialized protobuf of type key_message.
It saves the cryptstore.  Since the version is not specified, it the
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
    --init-trust=false
    --policy_key_file=policy_store=policy_cert_file.policy_domain_name
    --enclave_type="sev-enclave"
    --sealed-cryptstore-key-filename=sealed-crypstore-key.policy_domain_name
    --encrypted-cryptstore-filename=cryptstore.policy_domain_name
    --print-cryptstore=true
    --get-item=true
    --keyname=dmcrypt-key
    --tag=dmcrypt-key
    --output-format=serialized-protobuf
    --print-cryptstore=true
    --save-cryptstore=true  // this can be false for "get" operations.
    --output-format=serialized-protobuf
    --output-filename=existing-key.bin

What this command does

It searched the cryptstore for an entry with tag "dmcrypt-key."
If found, it writes the associated protobuf for the key 
with the latest version (since we specified no version number).
into the output-file and prints "suceeded;" ; otherwise,
it prints "failed".

--------------------------------------------------------------------------------

Semantics for cryptstore

Inlike the policy store, all items have versions to simplify key rotation.  In "get"
operations if unspecified, the latest version of the key is retrieved.  In "put"
operations, if unspecified, the item will have a version 1 higher than the largest
pre-existing version in the store.  Version numbers must be positive.  "0" is
unspecified.  If the version is unspecified and there is no version of the key in
the store, it will be version 1.
