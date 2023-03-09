To run the tests, you must have a policy_key_file.bin with the policy private key.
You can either generate it of copy it form other test directories.  Next, run
./generate_policy.sh.  This will generate the Sev keys and certificates and build
policy.bin.

The SEV keys and certs are:

sev_ark_key.bin: Private ARK key
sev_ask_key.bin: Private ASK key
sev_vcek_key.bin: Private VCEK key
sev_ark_cert.der: ARK cert
sev_ask_cert.der: ASK cert
sev_vcek_cert.der: VCEK cert
