To run the tests, you need to initialize the test files.  You can
generate them using the utility:

$CERTIFIER_PROTOTYPE/utilities/cert_utility.exe --operation=generate-policy-key-and-test-keys \
    --policy_key_output_file=policy_key_file.bin --policy_cert_output_file=policy_cert_file.bin \
    --platform_key_output_file=platform_key_file.bin --attest_key_output_file=attest_key_file.bin

To run the platfrom tests for sev, you should also look at the instructions in ./test_data.
