#
UTILITIES=../utilities
TEST_DATA=./test_data

# Policy
#   1. "policyKey is-trusted"
#   2: "The policyKey says the ARK-key is-trusted-for-attestation"
#   3: "policyKey says measurement is-trusted"
#   4. "policyKey says platform[amd-sev-snp, no-debug, no-migrate, api-major >= 0, api-minor >= 0]
#          has-trusted-platform-property"

$UTILITIES/make_property.exe --property_name=debug --property_type='string' comparator="=" --string_value=no --output=$TEST_DATA/property1.bin
$UTILITIES/make_property.exe --property_name=migrate --property_type='string' comparator="=" --string_value=no --output=$TEST_DATA/property2.bin
$UTILITIES/make_property.exe --property_name='api-major' --property_type=int --comparator=">=" --int_value=0 --output=$TEST_DATA/property3.bin
$UTILITIES/make_property.exe --property_name='api-minor' --property_type=int --comparator=">=" --int_value=0 --output=$TEST_DATA/property4.bin
$UTILITIES/combine_properties.exe --in=$TEST_DATA/property1.bin,$TEST_DATA/property2.bin,$TEST_DATA/property3.bin,$TEST_DATA/property4.bin --output=$TEST_DATA/properties.bin

$UTILITIES/make_platform.exe --platform_type=amd-sev-snp --properties_file=$TEST_DATA/properties.bin --output=$TEST_DATA/platform.bin
$UTILITIES/make_unary_vse_clause.exe --platform_subject=$TEST_DATA/platform.bin --verb="has-trusted-platform-property" --output=$TEST_DATA/isplatform.bin
$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/isplatform.bin

$UTILITIES/make_environment.exe --platform_file=$TEST_DATA/platform.bin --measurement_file=$TEST_DATA/meas.hex --output=$TEST_DATA/environment.bin
$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/isenvironment.bin

$UTILITIES/make_unary_vse_clause.exe --environment_subject=$TEST_DATA/environment.bin --verb="is-environment" --output=$TEST_DATA/isenvironment.bin

$UTILITIES/make_unary_vse_clause.exe --cert_subject=$TEST_DATA/ark.der --verb="is-trusted-for-attestation" --output=$TEST_DATA/ark.bin
$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin --verb="says" --clause=$TEST_DATA/ark.bin --output=$TEST_DATA/policy_ark.bin 
$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/policy_ark.bin

$UTILITIES/make_unary_vse_clause.exe --cert_subject=$TEST_DATA/ask.der --verb="is-trusted-for-attestation" --output=$TEST_DATA/ask.bin
$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin --verb="says" --clause=$TEST_DATA/ask.bin --output=$TEST_DATA/policy_ask.bin 
$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/policy_ask.bin

$UTILITIES/measurement_init.exe --mrenclave=$TEST_DATA/meas.hex --out_file=$TEST_DATA/meas.bin
$UTILITIES/make_unary_vse_clause.exe --measurement_subject=$TEST_DATA/meas.bin --verb="is-trusted" --output=$TEST_DATA/measurement.bin
$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin --verb="says" --clause=$TEST_DATA/measurement.bin --output=$TEST_DATA/policy_measurement.bin 
$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/policy_measurement.bin

$UTILITIES/make_unary_vse_clause.exe --cert_subject=$TEST_DATA/vcek.der --verb="is-trusted-for-attestation" --output=$TEST_DATA/vcek.bin
$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/vcek.bin
$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin --verb="says" --clause=$TEST_DATA/vcek.bin --output=$TEST_DATA/policy_vcek.bin 
$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/policy_vcek.bin

$UTILITIES/make_signed_claim_from_vse_clause.exe   --vse_file=$TEST_DATA/isplatform.bin --duration=9000 \
  --private_key_file=$TEST_DATA/policy_key_file.bin --output=$TEST_DATA/signed_isplatform.bin
$UTILITIES/make_signed_claim_from_vse_clause.exe   --vse_file=$TEST_DATA/policy_ark.bin --duration=9000 \
  --private_key_file=$TEST_DATA/policy_key_file.bin --output=$TEST_DATA/signed_policy_ark.bin
$UTILITIES/make_signed_claim_from_vse_clause.exe   --vse_file=$TEST_DATA/policy_ask.bin --duration=9000 \
  --private_key_file=$TEST_DATA/policy_key_file.bin --output=$TEST_DATA/signed_policy_ask.bin
$UTILITIES/make_signed_claim_from_vse_clause.exe   --vse_file=$TEST_DATA/policy_vcek.bin --duration=9000 \
  --private_key_file=$TEST_DATA/policy_key_file.bin --output=$TEST_DATA/signed_policy_vcek.bin
$UTILITIES/make_signed_claim_from_vse_clause.exe   --vse_file=$TEST_DATA/policy_measurement.bin --duration=9000 \
  --private_key_file=$TEST_DATA/policy_key_file.bin --output=$TEST_DATA/signed_policy_measurement.bin

$UTILITIES/package_claims.exe --input=$TEST_DATA/signed_policy_ark.bin,$TEST_DATA/signed_policy_measurement.bin,$TEST_DATA/signed_isplatform.bin,$TEST_DATA/signed_policy_ask.bin,$TEST_DATA/signed_policy_vcek.bin --output=$TEST_DATA/policy.bin
$UTILITIES/print_packaged_claims.exe --input=$TEST_DATA/policy.bin

// ./certifier_tests.exe --policy_file_name=./test_data/policy.bin --policy_key_file_name=./test_data/policy_key_file.bin \
// --ark_key_file_name=./test_data/policy_ark.bin --ask_key_file_name=./test_data/policy_ask.bin --vcek_key_file_name=./test_data/policy_vcek.bin

// cert_utility.exe --operation=generate-key --key_type=rsa-2048 --key_name=ARKKey --key_output_file=ark_key_file.bin --cert_output_file=ark_certcert_file.bin
