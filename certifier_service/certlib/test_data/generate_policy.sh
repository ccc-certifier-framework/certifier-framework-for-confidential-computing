
export CERTIFIER_PROTOTYPE=../../..
export UTILITIES=$CERTIFIER_PROTOTYPE/utilities
export TEST_DATA=.

# generate sev certs
$CERTIFIER_PROTOTYPE/utilities/sample_sev_key_generation.exe --ark_der=./sev_ark_cert.der --ask_der=./sev_ask_cert.der \
--vcek_der=./sev_vcek_cert.der --sev_attest=./sev_attest.bin --policy_key_file=./policy_key_file.bin


# Policy
#   1. "policyKey is-trusted"
#   2: "The policyKey says the ARK-key is-trusted-for-attestation"
#   3: "policyKey says measurement is-trusted"
#   4. "policyKey says platform[amd-sev-snp, no-debug, no-migrate, api-major >= 0, api-minor >= 0]
#          has-trusted-platform-property"

$UTILITIES/make_property.exe --property_name=debug --property_type='string' comparator="=" \
--string_value=no --output=$TEST_DATA/property1.bin

$UTILITIES/make_property.exe --property_name=migrate --property_type='string' comparator="=" \
--string_value=no --output=$TEST_DATA/property2.bin

$UTILITIES/make_property.exe --property_name=smt --property_type='string' comparator="=" \
--string_value=no --output=$TEST_DATA/property5.bin

$UTILITIES/make_property.exe --property_name='api-major' --property_type=int --comparator=">=" \
--int_value=0 --output=$TEST_DATA/property3.bin

$UTILITIES/make_property.exe --property_name='api-minor' --property_type=int --comparator=">=" \
--int_value=0 --output=$TEST_DATA/property4.bin

$UTILITIES/make_property.exe --property_name='tcb-version' --property_type=int --comparator="=" \
--int_value=0x03000000000008115 --output=$TEST_DATA/property6.bin

$UTILITIES/combine_properties.exe \
--in=$TEST_DATA/property1.bin,$TEST_DATA/property2.bin,$TEST_DATA/property3.bin,$TEST_DATA/property4.bin,$TEST_DATA/property5.bin,$TEST_DATA/property6.bin \
--output=$TEST_DATA/properties.bin

$UTILITIES/make_platform.exe --platform_type=amd-sev-snp \
--properties_file=$TEST_DATA/properties.bin --output=$TEST_DATA/platform.bin

$UTILITIES/make_unary_vse_clause.exe --platform_subject=$TEST_DATA/platform.bin \
--verb="has-trusted-platform-property" --output=$TEST_DATA/vse_isplatform.bin

$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin \
--verb="says" --clause=$TEST_DATA/vse_isplatform.bin --output=$TEST_DATA/vse_saysisplatform.bin

$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/vse_saysisplatform.bin

# get ark key from cert
$CERTIFIER_PROTOTYPE/utilities/make_unary_vse_clause.exe --cert_subject=sev_ark_cert.der \
--verb="is-trusted-for-attestation" --output=vse_arkistrusted.bin

$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin \
--verb="says" --clause=$TEST_DATA/vse_arkistrusted.bin \
--output=$TEST_DATA/vse_saysarkistrusted.bin

$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/vse_saysarkistrusted.bin

$UTILITIES/measurement_init.exe --mrenclave=\
010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708 \
--out_file=$TEST_DATA/meas.bin

$UTILITIES/make_unary_vse_clause.exe --measurement_subject=$TEST_DATA/meas.bin \
--verb="is-trusted" --output=$TEST_DATA/vse_measurement.bin

$UTILITIES/make_indirect_vse_clause.exe --key_subject=$TEST_DATA/policy_key_file.bin \
--verb="says" --clause=$TEST_DATA/vse_measurement.bin --output=$TEST_DATA/vse_saysmeasurement.bin

$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/vse_saysmeasurement.bin

$UTILITIES/make_environment.exe --platform_file=$TEST_DATA/platform.bin \
--measurement_file=$TEST_DATA/meas.hex --output=$TEST_DATA/environment.bin

$UTILITIES/make_unary_vse_clause.exe --environment_subject=$TEST_DATA/environment.bin \
--verb="is-environment" --output=$TEST_DATA/vse_saysisenvironment.bin

$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/vse_saysisenvironment.bin

$UTILITIES/make_signed_claim_from_vse_clause.exe --vse_file=$TEST_DATA/vse_saysisplatform.bin \
--duration=9000 --private_key_file=$TEST_DATA/policy_key_file.bin \
--output=$TEST_DATA/signed_isplatform.bin

$UTILITIES/make_signed_claim_from_vse_clause.exe --vse_file=$TEST_DATA/vse_saysarkistrusted.bin \
--duration=9000 --private_key_file=$TEST_DATA/policy_key_file.bin \
--output=$TEST_DATA/signed_policy_ark.bin

$UTILITIES/make_signed_claim_from_vse_clause.exe --vse_file=$TEST_DATA/vse_saysmeasurement.bin \
--duration=9000 --private_key_file=$TEST_DATA/policy_key_file.bin \
--output=$TEST_DATA/signed_policy_measurement.bin

$UTILITIES/package_claims.exe \
--input=$TEST_DATA/signed_policy_ark.bin,$TEST_DATA/signed_policy_measurement.bin,$TEST_DATA/signed_isplatform.bin \
--output=$TEST_DATA/sev_policy.bin 

$UTILITIES/print_packaged_claims.exe --input=$TEST_DATA/sev_policy.bin
