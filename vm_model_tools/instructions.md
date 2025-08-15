
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


Here is the calling arguments:

cf-osutility.exe
    --init-trust
    --enclave-type=type
    --policy-store-name=filename
    --encrypted-cryptstore-filename=filename
    --cryptstore-name=filename
    --sealed-key-filename=filename
    --symmetric_algorithm=name
    --public_key_algorithm=name
    --generate-and-save-key
    --get-item
        --tag=xxx
        --version=xxx
        --type=xxx
    --put-item==name of file with value
        --tag=xxx
        --version=xxx
        --type=xxx
    --output-file=filename
    --output-format=format
    --input-format=format
    --print-cryptstore
    --earliest-version
        --tag=xxx
        --type=xxx
    --latest-version
        --tag=xxx
        --type=xxx
    --save-cryptstore

Instructions for building and using the utility are in build.md,
you should be able to just copy and paste each step.

