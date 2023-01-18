#
UTILITIES=../utilities
TEST_DATA=./test_data

# Policy
#   1. "policyKey is-trusted"
#   2: "The policyKey says the ARK-key is-trusted-for-attestation"
#   3: "policyKey says measurement is-trusted"
#   4. "policyKey says platform[amd-sev-snp, no-debug, no-migrate, api-major >= 0, api-minor >= 0]
#          has-trusted-platform-property"

$UTILITIES/make_property.exe --property_name=debug --property_type='string' comparator="=" --string_value=no_debug --output=$TEST_DATA/property1.bin
$UTILITIES/make_property.exe --property_name=migrate --property_type='string' comparator="=" --string_value=no_migrate --output=$TEST_DATA/property2.bin
$UTILITIES/make_property.exe --property_name='api-major' --property_type=int --comparator=">=" --int_value=0 --output=$TEST_DATA/property3.bin
$UTILITIES/make_property.exe --property_name='api-minor' --property_type=int --comparator=">=" --int_value=0 --output=$TEST_DATA/property4.bin
$UTILITIES/combine_properties.exe --in=$TEST_DATA/property1.bin,$TEST_DATA/property2.bin,$TEST_DATA/property3.bin,$TEST_DATA/property4.bin --output=$TEST_DATA/properties.bin

$UTILITIES/make_platform.exe --platform_type=amd-sev-snp --properties_file=$TEST_DATA/properties.bin --output=$TEST_DATA/platform.bin
$UTILITIES/make_unary_vse_clause.exe --platform_subject=$TEST_DATA/platform.bin --verb="has-trusted-platform-property" --output=$TEST_DATA/isplatform.bin
$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/isplatform.bin

$UTILITIES/make_environment.exe --platform_file=$TEST_DATA/platform.bin --measurement_file=$TEST_DATA/meas.hex --output=$TEST_DATA/environment.bin
$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/isenvironment.bin

$UTILITIES/make_unary_vse_clause.exe --environment_subject=$TEST_DATA/environment.bin --verb="is-environment" --output=$TEST_DATA/isenvironment.bin


