
export CERTIFIER_PROTOTYPE=../../..
export UTILITIES=$CERTIFIER_PROTOTYPE/utilities
export TEST_DATA=.

# Policy
#    0. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] is-trusted
#    1. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
#        Key[rsa, platformKey, cdc8112d97fce6767143811f0ed5fb6c21aee424] is-trusted-for-attestation
#    2. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
#        Measurement[0001020304050607...] is-trusted
#    3. Key[rsa, policyKey, d240a7e9489e8adc4eb5261166a0b080f4f5f4d0] says
#        platform has-trusted-platform-property


$UTILITIES/make_unary_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin \
--verb="is-trusted" --output=$TEST_DATA/gramine_policykeyistrusted.bin

$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin \
--verb="says" --clause=$TEST_DATA/gramine_policykeyistrusted.bin --output=$TEST_DATA/gramine_sayspolicykeyistrusted.bin

$UTILITIES/make_unary_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin \
--verb="is-trusted" --output=$TEST_DATA/gramine_platformKeyistrusted.bin

$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin \
--verb="says" --clause=$TEST_DATA/gramine_platformKeyistrusted.bin \
--output=$TEST_DATA/gramine_saysplatformKeyistrusted.bin

$UTILITIES/measurement_init.exe --mrenclave=\
010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708 \
--out_file=$TEST_DATA/meas.bin

$UTILITIES/make_unary_vse_clause.exe --measurement_subject=$TEST_DATA/meas.bin \
--verb="is-trusted" --output=$TEST_DATA/gramine_measurement.bin

$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin \
--verb="says" --clause=$TEST_DATA/gramine_measurement.bin --output=$TEST_DATA/gramine_saysmeasurement.bin

$UTILITIES/make_property.exe --property_name=debug --property_type='string' comparator="=" \
--string_value=no --output=$TEST_DATA/property1.bin

$UTILITIES/make_property.exe --property_name=X64 --property_type='string' comparator="=" \
--string_value=yes --output=$TEST_DATA/property2.bin

$UTILITIES/make_property.exe --property_name='cpusvn' --property_type=int --comparator="=" \
--int_value=1374454427414364160 --output=$TEST_DATA/property3.bin

$UTILITIES/make_property.exe --property_name='quoting-enclave-sv' --property_type=int --comparator="=" \
--int_value=0x03 --output=$TEST_DATA/property4.bin

$UTILITIES/make_property.exe --property_name='provisioning-enclave-sv' --property_type=int --comparator="=" \
--int_value=0x13 --output=$TEST_DATA/property5.bin

$UTILITIES/combine_properties.exe \
--in=$TEST_DATA/property1.bin,$TEST_DATA/property2.bin,$TEST_DATA/property3.bin,$TEST_DATA/property4.bin,$TEST_DATA/property5.bin \
--output=$TEST_DATA/properties.bin

$UTILITIES/make_platform.exe --platform_type=sgx \
--properties_file=$TEST_DATA/properties.bin --output=$TEST_DATA/gramine_platform.bin

$UTILITIES/make_unary_vse_clause.exe --platform_subject=$TEST_DATA/gramine_platform.bin \
--verb="has-trusted-platform-property" --output=$TEST_DATA/gramine_isplatform.bin

$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin \
--verb="says" --clause=$TEST_DATA/gramine_isplatform.bin --output=$TEST_DATA/gramine_saysisplatform.bin

# Signed claims

$UTILITIES/make_signed_claim_from_vse_clause.exe --vse_file=$TEST_DATA/gramine_sayspolicykeyistrusted.bin \
--duration=9000 --private_key_file=$TEST_DATA/policy_key_file.bin \
--output=$TEST_DATA/gramine_signed_sayspolicykeyistrusted.bin

$UTILITIES/make_signed_claim_from_vse_clause.exe --vse_file=$TEST_DATA/gramine_saysplatformKeyistrusted.bin \
--duration=9000 --private_key_file=$TEST_DATA/policy_key_file.bin \
--output=$TEST_DATA/gramine_signed_platform_key.bin

$UTILITIES/make_signed_claim_from_vse_clause.exe --vse_file=$TEST_DATA/gramine_saysmeasurement.bin \
--duration=9000 --private_key_file=$TEST_DATA/policy_key_file.bin \
--output=$TEST_DATA/gramine_signed_saysmeasurement.bin

$UTILITIES/make_signed_claim_from_vse_clause.exe --vse_file=$TEST_DATA/gramine_saysisplatform.bin \
--duration=9000 --private_key_file=$TEST_DATA/policy_key_file.bin \
--output=$TEST_DATA/gramine_signed_saysisplatform.bin

$UTILITIES/package_claims.exe \
--input=$TEST_DATA/gramine_signed_sayspolicykeyistrusted.bin,$TEST_DATA/gramine_signed_platform_key.bin,$TEST_DATA/gramine_signed_saysmeasurement.bin,$TEST_DATA/gramine_signed_saysisplatform.bin \
--output=$TEST_DATA/gramine_policy.bin 

$UTILITIES/print_packaged_claims.exe --input=$TEST_DATA/gramine_policy.bin
