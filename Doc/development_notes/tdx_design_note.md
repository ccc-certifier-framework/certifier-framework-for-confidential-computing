# Design note: Implementing Certifier for TDX


The current public TDX VM support in Linux does not seem to provide access to
seal / unseal functionality which is a critical element of a fully compliant
Confidential Computing platform.  This VM apparently supports a version of
TDX available to only a limited number of customers*.

There is a workaround for Certifier Framework implementations which wish to
use this incomplete functionality, as follows:

1. We write a keystore for programs in a security domain and run it on a
platform with full Confidential Computing functionality (SEV, SGX, CCA,
Keystone) or on custom hardware that allows secure recovery of a protection
key on cold start.  The keystore is a confidential computing platform and is
certified by the Certifier Service as usual and acquires an admissions
certificate.  The keystore generates a sealing/unsealing key (or other keys)
for each program when it is contacted for the first time (based on the program
measurement).

2. Every time a program starts on a reduced funtionality platform, it does a
cold_init and gets certified.  It contacts the keystore (with its admissions
certificate) over a secure channel and retrieves its sealing key (and/or
other keys).

3. The program can now do a warm restart and proceed as normally either with
the stored authentication key (from the store) or freshly generated one.
Processing then proceeds normally.

This solution is scarely ideal since it adds latency, reduces availability
(since every start depends on contacting a working certifier service AND
keystore), and increases the key management responsibilities of the service
deployed.  However, it seems like the best solution possible and preserves
programming compatibility among platforms.  Hopefully, future TDX implementations
will fully support the Confidential Computing capabilities, which would
obviate this issue.


*Security week mentions Microsoft, IBM, Google and Alibaba.
