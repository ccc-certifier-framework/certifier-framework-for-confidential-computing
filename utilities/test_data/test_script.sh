../make_property.exe --property_name=no-debug --property_type='string' comparator="=" --string_value=no_debug --output=property1.bin
../make_property.exe --property_name=no-migrate --property_type='string' comparator="=" --string_value=no_migrate --output=property2.bin
../combine_properties.exe --in=property1.bin,property2.bin --output=properties.bin
../make_platform.exe --platform_type=amd-sev-snp --properties_file=properties.bin --output=platform.bin
../make_unary_vse_clause.exe --platform_file=platform.bin --verb="is-platform" --output=isplatform.bin
../print_vse_clause.exe --input=isplatform.bin
../make_unary_vse_clause.exe --environment_subject=environment.bin --verb="is-environment" --output=isenvironment.bin
../print_vse_clause.exe --input=isenvironment.bin
../make_simple_vse_clause.exe --environment_subject=environment.bin --platform_object=platform.bin --verb="contains" --output=simple.bin
../print_vse_clause.exe --input=simple.bin
../make_environment.exe --platform_file=platform.bin --measurement_file=meas.hex --output=environment.bin

../make_property.exe --property_name='api-major' --property_type=int --comparator=">=" --int_value=5 --output=property3.bin

