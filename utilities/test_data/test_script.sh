../make_property.exe --property_name=no-debug --property_type='string' comparator="=" --string_value=no_debug --output=property1.bin
../make_property.exe --property_name=no-migrate --property_type='string' comparator="=" --string_value=no_migrate --output=property2.bin
../combine_properties.exe --in=property1.bin,property2.bin --output=properties.bin
../make_platform.exe --platform_type=amd-sev-snp --properties_file=properties.bin --output=platform.bin
../make_unary_vse_clause.exe --platform_subject=platform.bin --verb="is-platform" --output=isplatform.bin
../print_vse_clause.exe --input=isplatform.bin
../make_unary_vse_clause.exe --environment_subject=environment.bin --verb="is-environment" --output=isenvironment.bin
../print_vse_clause.exe --input=isenvironment.bin
../make_simple_vse_clause.exe --environment_subject=environment.bin --platform_object=platform.bin --verb="contains" --output=simple.bin
../print_vse_clause.exe --input=simple.bin
../make_environment.exe --platform_file=platform.bin --measurement_file=meas.hex --output=environment.bin

../make_property.exe --property_name='api-major' --property_type=int --comparator=">=" --int_value=5 --output=property3.bin

../make_platform.exe --platform_type=any --output=platform2.bin

# policy-key says platform(type, property-class)) platform-is-trusted
../make_property.exe --property_name='api-major' --property_type=int --comparator=">=" --int_value=0 --output=property4.bin
../make_property.exe --property_name='api-minor' --property_type=int --comparator=">=" --int_value=0 --output=property5.bin
../combine_properties.exe --in=property1.bin,property2.bin,property4.bin,property5.bin --output=properties.bin

../make_platform.exe --platform_type=amd-sev-snp --properties_file=properties.bin --output=platform3.bin
../make_environment.exe --platform_file=platform3.bin --measurement_file=meas.hex --output=environment2.bin
../make_unary_vse_clause.exe --platform_subject=platform3.bin --verb="is-trusted-platform" --output=istrustedplatform.bin

../make_indirect_vse_clause.exe --key_subject=policy_key_file.bin --verb="says" --clause=istrustedplatform.bin --output=policy_key_says.bin

# Key[rsa, policyKey, a5fc2b7e629fbbfb04b056a993a473af3540bbfe] says
#     Platform[amd-sev-snp, no-debug, no-migrate, api-major >= 0, api-minor >= 0] is-trusted-platform
