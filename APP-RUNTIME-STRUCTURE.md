# Supporting files, keys and shell scripts for runing applications

Every use of the Cerfifier Framework, requires enclave support.  For "real
hardware," like SEV, this involves obtaining enclave keys and authorization
like the ARK and ASK certificates for the hardware family and the VCEK
certificate for the platform attestation keys.  Given these, one can
write certifier policy for the certifier service, save the policy store
in a standard place for restart and generally maintain the application.
We also try to create a parrallel infrastructure for non-hardware based
enclaves like the simulated-enclave, which can be used for testing and
development, and the application-enclave, which can present an enclave like
"isolated" environment for processes in Linux inside a parent enclave (like
SEV).

## Running sample applications

Generallly, for an application in the directory $EXAMPLE_DIR, there's a
shell script, prepare-test.sh, that creates the supporting infrastructure,
keys, policy and runtime environment to run the application (like the
sample_apps).  This supporting infrastructure consists of several files
and directories:

  The $EXAMPLE_DIR/provisioning directory is where an application deployer
  creates all the required keys, rules and certificates for an application.
  This includes policy keys and certificates as well as generated keys and
  certificates for the simulated-enclave to take the place of keys normally
  embedded in hardware like the attestation key and the platform key.
  The "platform key" is the trust anchor for the vendor.  The vendor provides
  a self-signed certificate (like the ARK certificate for SEV) with the
  public key used to sign other certificates.  For the simulated-enclave
  the corresponding private key is in platform_key_file.bin and
  the corresponding certificate is in platform_key_cert.bin.  The platform
  key (or possibly a sub key signed by the platform key, like the ASK key
  for SEV) signs a statement or certificate for the platform attestation key
  which signifies that the named public key in the certificate is the valid
  attestation key for this hardware (this corresponds to the "VCEK"
  certificate in SEV).  For the simulated-enclave, the private key must be
  available to the enclave for simulated attestation.  This key is in
  attest_key_file.bin for the simulated enclave and the corresponding
  signed endorsement is in platform_attest_endorsement.bin; the can be an
  x509 certificate (like the VCEK) or a vse signed statement.  For the case
  of the simulated enclave, it is a platform key signed vse statement. In the
  case of the application enclave, the attest key is endorsed by the
  attestation policy key and its corresponding certificate is stored in
  "attestation_endorsement.bin."  The application enclave private key is
  of course, never available outside the service program. For the simulated
  enclave, the simulated measurement needs to also be available in a file
  called, for example, example_app.measurement.

  The $EXAMPLE_DIR/service directory is where all the files required by the
  certifier-service are stored.

  Most applications also store support files in a directory called something
  like $EXAMPLE_DIR/app_data, or, in the case of the application enclave,
  $EXAMPLE_DIR/service_data.  The policy key certificate should be available
  to anyone and is stored in a file called policy_cert_file.$DOMAIN_NAME
  where DOMAIN_NAME is a variable containing the actual name of the domain.
  The default domain name for most of the sample apps is "datica-test" but
  you can specify any domain name when you call prepare-test.sh.

  Most of these are intended to be used with the new api.  Most applications
  are also implemented with the old api too to preserve backward compatibility
  but a lot of this doesn't apply to the old api infrastructure.

  ## Examples


    For simple_app, after the provisioning step, the directories contain the
    following:

      .../simple_app/service:
        policy_key_file.dom0
          This is the private policy key for the domain called "dom0".  It is
          needed by the certifier service to sign admissions certificates.
        policy_cert_file.dom0
          This is the corresponding self signed certificate for the policy key.
        policy.bin
          This is the file containing signed rules that determine the policy for
          evidence (including attestations) required for domain admission.

      .../simple_app/app1_data (This is for the sample client side)
          policy_cert_file.dom0
            This is the self signed certificate for the policy key.
          attest_key_file.bin
            This is the attest private key for the simulated enclave.
          platform_key_cert.bin
            This is the vendor self-signed trust anchor.
          example_app.measurement
            This is the measurement of the application.
          platform_attest_endorsement.bin
            This is the signed statement that "The plaform-key says the
            attestation-key is-trusted-for-attestation
      .../simple_app/app2_data
         This has the same files as app1_data, but for the server application.

    The policy stores for app1 and app2 are stored in
      $EXAMPLE_DIR/app1_data/policy_store.$DOMAIN_NAME for app1 (the client)
      $EXAMPLE_DIR/app2_data/policy_store.$DOMAIN_NAME for app2 (the server)


    For simple_app_under_sev, after the provisioning step, the directories contain the
    following:

      .../simple_app_under_sev/service:
        policy_key_file.dom0
          This is the private policy key for the domain called "dom0".  It is
          needed by the certifier service to sign admissions certificates.
        policy_cert_file.dom0
          This is the corresponding self signed certificate for the policy key.
        sev-policy.bin
          This is the file containing signed rules that determine the policy for
          evidence (including attestations) required for domain admission.

      .../simple_app_under_sev/app1_data (This is for the sample client side)
          policy_cert_file.dom0
            This is the self signed certificate for the policy key.
          ark-cert.der
            This is thee "platform cert" for SEV.
          ask-cert.der
            This is a cert that means "The ark-key says the ask-key
              is-trusted-for-attestation"
          vcek-cert.der
            This is a cert that means "The ask-key says the vcek-key
              is-trusted-for-attestation"
      .../simple_app_under_sev/app2_data
         This has the same files as app1_data, but for the server application.

    The policy stores for app1 and app2 are stored in
      $EXAMPLE_DIR/app1_data/policy_store.$DOMAIN_NAME for app1 (the client)
      $EXAMPLE_DIR/app2_data/policy_store.$DOMAIN_NAME for app2 (the server)


    For cf_utility, after the provisioning step, the directories contain the
    following:

      .../cf_utility/service:
        policy_key_file.dom0
          This is the private policy key for the domain called "dom0".  It is
          needed by the certifier service to sign admissions certificates.
        policy_cert_file.dom0
          This is the corresponding self signed certificate for the policy key.
        sev-policy.bin
          This is the file containing signed rules that determine the policy for
          evidence (including attestations) required for domain admission.

      .../cf_utility/cf_data (for SEV)
          policy_cert_file.dom0
            This is the self signed certificate for the policy key.
          ark-cert.der
            This is thee "platform cert" for SEV.
          ask-cert.der
            This is a cert that means "The ark-key says the ask-key
              is-trusted-for-attestation"
          vcek-cert.der
            This is a cert that means "The ask-key says the vcek-key
              is-trusted-for-attestation"

      .../cf_utility/cf_data (for simulated enclave)
        policy_cert_file.dom0
          This is the self signed certificate for the policy key.
        attest_key_file.bin
          This is the attest private key for the simulated enclave.
        platform_key_cert.bin
          This is the vendor self-signed trust anchor.
        example_app.measurement
          This is the measurement of the application.
        platform_attest_endorsement.bin
          This is the signed statement that "The plaform-key says the
          attestation-key is-trusted-for-attestation

    For both enclave types, the policy store and cryptstore are in
      $EXAMPLE_DIR/cf_data/policy_store.$DOMAIN_NAME
      $EXAMPLE_DIR/cf_data/cryptstore.$DOMAIN_NAME


    For application_service, after the provisioning step, the directories contain the
    following:

      .../application_service/service:
        policy_key_file.dom0
          This is the private policy key for the domain called "dom0".  It is
          needed by the certifier service to sign admissions certificates.
        policy_cert_file.dom0
          This is the corresponding self signed certificate for the policy key.
        policy.bin  (or sev-policy.bin for sev)
          This is the file containing signed rules that determine the policy for
          evidence (including attestations) required for domain admission.

      .../application_service/service_data
          policy_cert_file.dom0
            This is the self signed certificate for the policy key.

          Application data required for simulated-enclave and sev as appropriate.
          Like ark-cert.der or platform_attest_endorsement.bin

          policy_store.$DOMAIN_NAME
            This is the policy store.

          service_attest_endorsement.bin will appear after certification.
            This is the certificate for the service attest key.

To provision and build all this infrastructure use prepare-test.sh.  To run the tests,
use run-test.sh.

Example for simple_app:

cd $CERTIFIER_ROOT/sample_apps/simple_app

  ./prepare-test.sh fresh dom0
  ./prepare-test.sh all dom0
  ./run-test.sh fresh dom0
  ./prepare-test.sh run dom0

The arguments to prepare-test.sh and run-test.sh vary slightly depending on
the application.  To check call them with no arguments and they will print
out the required arguments.

## Writing programs with the Certifier Framework

The certifier framework is a library and utilities to simplify and accelerate
writing programs protected by Confidential Computing ("CC") technology.
It also makes these programs portable across different CC platforms.

For the following, let $CERTIFIER_ROOT be the top level directory for the
downloaded repository.

The library a library, certifier.a, can be built as follows:

```
  cd $CERTIFIER_ROOT/src
  make clean -f certifier.mak
  make -f certifier.mak
```

The certifier uses four principal tools: protobuf, for serialization and
deserialization of program data, openssl, for crypto implementations and
basic TLS functionality, gflags to simplify specifying program arguments
at the shell level and gtes for testing.

The certifier provides many routines to simplify programming.  You can see
the full list of callable functions in
$CERTIFIER_ROOT/include/certifier_utilities.h, and
$CERTIFIER_ROOT/include/certifier_framework.h.  However, most programmer
interaction involves the two C++ classes:

```
cc_trust_manager
secure_authenticated_channel.
```

The first class handles all the paraphenalia of interacting with CC.
It automatically save CC program data securely and performs "certification."
Certification is the process of collecting signed evidence, including
attestations, contacting and providing this evidence to an policy authority, or
domain manager (a program called the Certifier Service) and retrieving
a signed certificate, called a certification, proving that the program
possessing the private key corrresponding to the public key in the certificate,
has the program "measurement" named in the certificate. The second class,
secure_authenticated_channel allows two programs to use their certification
certificates (sometimes called admissions certificates) and their
corresponding private keys, to open a mutually authenticated, encrypted,
integrity protected channel between them.  Each program is assured that the
correspondent follows all domain policy, as proved via certification.  Thus
the connection, essentially, extends the program trust boundary of
one program in a domain to other "trusted" programs.

Each policy authority controls a "security domain," identified by a public
policy keyand associated "domain name".  Each participating program has an
unforegeable copy of the key (often ist is part of the "program measurement."
The certification is signed by a key that chains to the policy-key.
A program presenting this certificate to another member of the security
domain can use the certified public key to "prove" it is part of the domain,
complies with domain rules, and while it has access to the corresponding
private key, is under the protection of a domain approved CC platform.

The protobufs used by the Certifier are defined in

```
 $CERTIFIER_ROOT/certifier_service/certprotos
```

A simple certification service implementation is in:

```
 $CERTIFIER_ROOT/certifier_service/simpleserver.go
```

There is a description there of the rules, proofs and mechanisms used by the
policy authority to verify domain compliance.  However, here we focus on the
applications programmer's task.  Importantly, the application programmer
is freed from the mechanics of both the individual CC platform and the possibly
(but hopefully not) complex domain rules.  She just has to focus on writing
a safe program.

The use of these two classes is rather simple.  Consider the sequence of calls
below, which form the backbone of any Certifier Framework program.  In fact,
its almost all that's needed most of the time, using this new api.

````

  // Call 1
  cc_trust_manager* trust_mgr =  new cc_trust_manager(enclave_type, purpose, store_file);

  // Call 2
  if (!trust_mgr->initialize_enclave(n, params)) {
     ...error processing
  }

  // Call 3
  if (!trust_mgr->initialize_store()) {
     ...error processing
  }

  // Call 4
  trust_mgr->print_trust_data()

  // Call 5
  if (!trust_mgr->initialize_keys(public_key_alg, symmetric_key_alg, false)) {
     ...error processing
  }

  // Call 6
  string serialized_policy_cert;
  serialized_policy_cert.assign((char *)initialized_cert,
                                initialized_cert_size);
  if (!trust_mgr->initialize_existing_domain(FLAGS_domain_name)) {
   ...error processing
  }

  // Call 7
  string purpose("authentication");
  if (!trust_mgr->initialize_new_domain(FLAGS_domain_name,
             purpose, serialized_policy_cert,
             FLAGS_policy_host, FLAGS_policy_port)) {
     ...error processing
  }

  // Call 8
  if (!trust_mgr.certify(FLAGS_domain_name) {
     ...error processing
  }

  // Call 9
  string my_role("client");
  secure_authenticated_channel channel(my_role);
  if (!channel.init_client_ssl(FLAGS_domain_name,
         FLAGS_server_app_host, FLAGS_server_app_port, *trust_mgr)) {
     ...error processing
  }

  // Call 10
  const char *msg = "Hi from your secret client\n";
  channel.write(strlen(msg), (byte *)msg);
````

Call 1 instantiates the trust manager; the arguments are all C++
string.

    enclave_type is the enclave type, for example,

    string enclave_type("sev");
    purpose specifies the use of the certifiered key, there are two: "authentication,"
      described above, where the key is used to authenticate a program and share secrets
      and "attestation," where the key is used to attest for other programs (see the
      application enclave)
    store_file is the name of the file that hold the "secure store" used by the certifier.
      The secure store is only accessible to the measured program under CC using Seal and
      Unseal.

Call 2 initializes the enclave.  Each enclave type has different parameters for initialization
like the name of the files containing certificates it needs.   Each enclave we support has a
"helper" function which collects these parameters.


Call 3  initializes the secure store, retrieving an secure store established by the program earlier,
if it exists.

Call 4 prints all the data in the trust manager. (This is optional)

Call 5 generates the keys needed by the progam or retrieves then from the store if already initialized.
public_key_alg is the name of the public key algorithm used by the program (e.g.- RSA-4096)
symmetric_key_alg is the name of the symmetric key algorithm the program uses (e.g., aes256-gcm).
The final argument can force generating new keys even if old ones exist.

Call 6 specifies pocicy cert (which can, fore example, be embedded in the program in the byte array
initialized_cert.  initialize_existing_domain(FLAGS_domain_name) retrives the parameters (admissions
certificates, keys, host url, host port) for a domain. FLAGS_domain_name is the domain name associated
with the policy authority.

Call 7 (only needed if Call 6 fails) initializes domain parameters for a new domain (or changes
them for an existing domain).

Call 8 certifies the domain with the indicated domain name byt contacting a certification service
as described above.

Call 9 intializes and establishes, a secure channel with the indicated mode (the other is "server").

Call 10 show a write to the channel.

After call 10, you can send and receive messages over the channel with channel.write and channel.read.
Once the channel is established, channel.peer_cert_ retrieves you peer's measurement,
if you need it.

That's it!

As mentioned above, there are number of example applications in:
    $CERTIFIER_ROOT/sample_apps/simple_app
    $CERTIFIER_ROOT/sample_apps/simple_app_under_sev
    $CERTIFIER_ROOT/sample_apps/simple_app_under_gramine (sgx)
    $CERTIFIER_ROOT/sample_apps/simple_app_under_app_service

simple_app uses a "simulated enclave" which is very useful for development and
simple_app_under_app_service uses a system deamon (in, say, a CC protected VM)
to provide CC services for individual processes in the VM.
