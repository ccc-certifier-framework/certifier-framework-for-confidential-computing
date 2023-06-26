# Utilities - Quick Reference Manual

  1. measurement_utility.exe --type=hash --input=input-file --output=output-file
  2. make_simple_vse_clause.exe --key_subject=file --measurement_subject=file --verb="speaks-for" \
    --key_object=file --measurement_object=file --output=output-file-name
  3. make_indirect_vse_clause.exe --key_subject=file --measurement_subject=file --verb="says" --clause=file --output=output-file-name
  4. make_unary_vse_clause.exe --key_subject=file --measurement_subject=file --verb="is-trusted" --output=output-file-name
  5. print_vse_clause.exe --input=filename
  6. print_signed_claim.exe --input=filename
  7. package_claims.exe --input=file1,file2,... --output-file=filename
  8. print_packaged_claims.exe --input=input-file
  9. make_signed_claim_from_vse_clause.exe --vse_file=file --duration=hours --private_key_file=key=key-file --output=output-file-name
  // Note:  Only "says" clauses can be signed
  10. embed_policy_key.exe takes a file containing an asn1 encoded cert and produces   
      an include file for an application that has a byte array, initialized_cert,
      initialized to it with variable `initialized_cert_size` equal to the array size.


## Examples

```shell
  ./measurement_utility.exe --type=hash --input=measurement_utility.exe \
      --output=measurement_utility.exe.measurement

  ./make_unary_vse_clause.exe --key_subject=policy_key_file.bin --measurement_subject="" \
      --verb="is-trusted" --output=unary_clause.bin
  ./print_vse_clause.exe --input=unary_clause.bin
  
  ./make_indirect_vse_clause.exe --key_subject=policy_key_file.bin --verb="says" \
      --clause=unary_clause.bin --output=indirect_clause.bin
  ./print_vse_clause.exe --input=indirect_clause.bin

  ./make_simple_vse_clause.exe --key_subject=policy_key_file.bin --verb="speaks-for" \
     --measurement_object=measurement_utility.exe.measurement --output=simple_clause.bin
  ./print_vse_clause.exe --input=simple_clause.bin

  ./make_signed_claim_from_vse_clause.exe --vse_file=indirect_clause.bin --duration=9000 \
     --private_key_file=policy_key_file.bin --output=first_signed_claim.bin
  ./print_signed_claim.exe --input=first_signed_claim.bin

  ./package_claims.exe --input=first_signed_claim.bin,first_signed_claim.bin --output=signed_claims.bin

  ./print_packaged_claims.exe --input=signed_claims.bin

  ./embed_policy_key.exe --input=asn1.bin --output=../policy_key.cc
```