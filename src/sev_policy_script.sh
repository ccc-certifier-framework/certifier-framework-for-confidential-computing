#
UTILITIES=../utilities
TEST_DATA=./test_data

$UTILITIES/make_property.exe --property_name=debug --property_type='string' comparator="=" --string_value=no_debug --output=$TEST_DATA/property1.bin
$UTILITIES/make_property.exe --property_name=migrate --property_type='string' comparator="=" --string_value=no_migrate --output=$TEST_DATA/property2.bin
$UTILITIES/make_property.exe --property_name='api-major' --property_type=int --comparator=">=" --int_value=0 --output=$TEST_DATA/property3.bin
$UTILITIES/make_property.exe --property_name='api-minor' --property_type=int --comparator=">=" --int_value=0 --output=$TEST_DATA/property4.bin
$UTILITIES/combine_properties.exe --in=$TEST_DATA/property1.bin,$TEST_DATA/property2.bin,$TEST_DATA/property3.bin,$TEST_DATA/property4.bin --output=$TEST_DATA/properties.bin

$UTILITIES/make_platform.exe --platform_type=amd-sev-snp --properties_file=$TEST_DATA/properties.bin --output=$TEST_DATA/platform.bin
$UTILITIES/make_unary_vse_clause.exe --platform_subject=$TEST_DATA/platform.bin --verb="is-platform" --output=$TEST_DATA/isplatform.bin
$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/isplatform.bin

#$UTILITIES/make_environment.exe --platform_file=$TEST_DATA/platform.bin --measurement_file=$TEST_DATA/meas.hex --output=$TEST_DATA/environment.bin
#$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/isenvironment.bin

#$UTILITIES/print_vse_clause.exe --input=$TEST_DATA/isplatform.bin
#$UTILITIES/make_unary_vse_clause.exe --environment_subject=$TEST_DATA/environment.bin --verb="is-environment" --output=$TEST_DATA/isenvironment.bin

#$UTILITIES/make_unary_vse_clause.exe --key_subject=platform3.bin --verb="is-trusted-platform" --output=istrustedplatform.bin
#$UTILITIES/make_indirect_vse_clause.exe --key_subject=policy_key_file.bin --verb="says" --clause=istrustedplatform.bin --output=policy_key_says.bin

