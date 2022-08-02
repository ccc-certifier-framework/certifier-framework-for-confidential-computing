Application Service
===================

The Application Service is an example of recursively providing Confidential
Computing support, in this case the parent, protected by an encrypted
virtual machine, recursively provides Confidential Computing support, through
the Certifier API to individual applications (processes) on a *nix VM.

The application service runs as a system (root) daemon at startup.  It accepts
requests to run applications.   When a request is received, the application is
run as a child of the service and they share a pair of pipes over which they
request services (like Seal, Unseal, Attest).  Children DO NOT run as root.

Children have the same certifier interface and their own Certifier Service
platform support, so programming them is exactly the same as other enclaves
except they have full access to the *nix API so porting programs is easy.

The enclave type for an application enclave is "application-enclave" and every
application enclave has a parent enclave.

As a result, an encrypted virtual machine can support many independant Confidential
Computing programs running as independent applications.  This is useful for
Kubernetes container management and encrypted virtual machines running related
trustworthy services.

