# Important concepts in real deployments


The "simple_app" family of examples is intended to carefully take
you through every step of building and deploying applications, in
sufficient detail to allow a thorough understanding of every
design feature of the Certifier Framework.  Thorough enough to make
a detailed security assessment and develop a clear understanding
of the security implications of each and every component.

However, for real use there will be several important differences.

First, the detailed instructions in "instructions.md" while intended
for "copy and paste" learning will, almost certainly, be replaced
by a very few shell scripts.  For example,
[run_example.sh](./run_example.sh), in the sample_apps directory,
performs this "one step" provisioning for all the applications.  If
you're not a shell programming guru, you can simply turn the
instructions.md (or script file) into a shell script to build
everything automatically.  Second, the subdirectories provisioning/,
service/, app1_data/ and app2_data/ are not generally distributed
and must be stored, with care.

Deploying an application (or VM) consists merely of distributing
the compiled application or service in the VM.  One common way to
do this, for a VM is to put the apps and/or service in `initramfs`,
then all the applications and shared libraries are measured as part
of "Direct Boot."

The subdirectories created when you build the applications and
Certifier Service, in the examples, are used as follows in deployment:

-   The provisioning directory is a staging directory.  It is used
    on a single machine to
    prepare for deployment.  It is not distributed with either the
    Certifier Service OR the application, ever.

-   The service directory is distributed with the Certifier Service.
    The only files needed are
    - `policy.bin` - which contains the signed policy, and
    - the policy key file, if you run your Certifier Service with
       un-encrypted policy_key provisioning (which is NOT recommended
       -- see the certifier_in_tee example).

-   The app storage directories (app1_data/ and app2_data/) are
    similarly never distributed.

-   A cardinal rule of the design is that NO file except the apps are
    security critical so none of those files should be distributed,
    nor should they require a secure storage capability.  Those
    files can (and should) be stored in a network accessible location
    which is NOT part of any measurement; they should definitely
    not be in `intiramfs` if you do direct boot.

    Simulated_enclave
    is an exception, since its attestation and platform keys are
    kept there.  Indeed, because the app directories contain files
    that differ between platforms on the very same hardware type,
    measuring these would mean that the "app measurement" varied
    from one SEV platform to another which is a disaster for
    scalability and app management.  ONLY the app need be distributed.
    As a convenience, platform certs are stored in these directories
    and they should NOT be distributed as they will vary among
    hardware of the same type.  Again, platform certificates should
    be downloaded from a network service.

    AMD SEV-SNP and Intel SGX can actually
    retrieve these certificates from the hardware, so the measurements
    don't change and when possible, these will be fetched automatically;
    however, support varies from platform to platform and may rely
    on features of the VMM so this is not illustrated currently in
    the "simple_apps."

As a first aid, remember that, unlike the exhaustively explained
simple_app run on a development machine, to help speed development,
actual deployment requires deploying very few files: only the app
(e.g., example_app.exe) on the application machines, none of the
provisioning directory files and only two of the files in the service
directory.

Consult the documentation for more detail.

