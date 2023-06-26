# Certifier Library Unit-tests

To run the tests, you must have a policy_key_file.bin with the policy private key.
You can either generate it using the utility: (Or copy it from other test directories.)

```shell
cd $CERTIFIER_PROTOTYPE/certifier_service/certlib/test_data

$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe          \
      --operation=generate-policy-key-and-test-keys      \
      --policy_key_output_file=policy_key_file.bin       \
      --policy_cert_output_file=policy_cert_file.bin     \
      --platform_key_output_file=platform_key_file.bin   \
      --attest_key_output_file=attest_key_file.bin
```

Next, run `$ ./generate_policy.sh`

This will generate the Sev keys and certificates and build policy.bin.

The SEV keys and certs are:

- sev_ark_key.bin: Private ARK key
- sev_ask_key.bin: Private ASK key
- sev_vcek_key.bin: Private VCEK key
- sev_ark_cert.der: ARK cert
- sev_ask_cert.der: ASK cert
- sev_vcek_cert.der: VCEK cert
