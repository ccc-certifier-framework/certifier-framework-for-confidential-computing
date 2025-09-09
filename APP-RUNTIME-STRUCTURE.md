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
