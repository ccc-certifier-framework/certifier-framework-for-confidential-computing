#!/bin/bash
# ############################################################################
# build-policy.sh: Script to build policy on the deployment machine
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../../.. > /dev/null
  CERTIFIER_ROOT=$(pwd) > /dev/null
  popd
fi
EXAMPLE_DIR=$(pwd) > /dev/null

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [ $ARG_SIZE == 0 ] ; then
fi

if [[ $ARG_SIZE != 1 && $ARG_SIZE != 2 && $ARG_SIZE != 3  ]] ; then
  echo "Wrong number of arguments"
  echo "Must call, as follows:"
  echo "  ./run-test.sh fresh"
  echo "  ./run-test.sh fresh domain-name"
  echo "  ./run-test.sh run  (se | sev)"
  echo "  ./run-test.sh run  (se | sev) domain-name"
  exit
fi

if [[ $ARG_SIZE == 1 && $1 == "fresh" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE="none"
fi
if [[ $ARG_SIZE == 2  && $1 == "fresh" ]] ; then
  DOMAIN_NAME=$2
  ENCLAVE_TYPE="none"
fi

if [[ $ARG_SIZE == 2  && $1 == "run" ]] ; then
  DOMAIN_NAME="datica-test"
  ENCLAVE_TYPE=$2
fi
if [[ $ARG_SIZE == 3 && $1 == "run" ]] ; then
  DOMAIN_NAME=$3
  ENCLAVE_TYPE=$2
fi

echo "Domain name: $DOMAIN_NAME"
echo "Enclave type: $ENCLAVE_TYPE"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "Policy key file name: $POLICY_KEY_FILE_NAME"
echo "Policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
CRYPTSTORE_NAME="cryptstore.$DOMAIN_NAME"
echo "Policy store name: $POLICY_STORE_NAME"
echo "Cryptstore name: $CRYPTSTORE_NAME"

function do-make-policy() {
  echo "do-make-policy"

  if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi
  pushd $EXAMPLE_DIR/provisioning 
    echo " " 
    echo "For simulated enclave"
  
    $CERTIFIER_ROOT/utilities/measurement_utility.exe \
      --type=hash --input=$CERTIFIER_ROOT/vm_model_tools/src/cf_utility.exe \
      --output=cf_utility.measurement
  
    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
      --key_subject="platform_key_file.bin" --verb="is-trusted-for-attestation" --output=ts1.bin
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
      --key_subject=$POLICY_KEY_FILE_NAME --verb="says" \
      --clause=ts1.bin --output=vse_policy1.bin

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
      --measurement_subject="cf_utility.measurement" \
      --verb="is-trusted" --output=ts2.bin

    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
      --key_subject=$POLICY_KEY_FILE_NAME --verb="says" \
      --clause=ts2.bin --output=vse_policy2.bin

    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
      --vse_file=vse_policy1.bin --duration=9000 --private_key_file=$POLICY_KEY_FILE_NAME \
      --output=signed_claim_1.bin

    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
      --vse_file=vse_policy2.bin  --duration=9000  \
      --private_key_file=$POLICY_KEY_FILE_NAME --output=signed_claim_2.bin
  $CERTIFIER_ROOT/utilities/package_claims.exe \
      --input=signed_claim_1.bin,signed_claim_2.bin --output=policy.bin
    $CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=policy.bin

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
      --key_subject=attest_key_file.bin --verb="is-trusted-for-attestation" --output=tsc1.bin

    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
      --key_subject=platform_key_file.bin --verb="says" \
      --clause=tsc1.bin --output=vse_policy3.bin

    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
      --vse_file=vse_policy3.bin --duration=9000 \
      --private_key_file=platform_key_file.bin --output=platform_attest_endorsement.bin

    echo " "
    echo "For simulated enclave"

    $CERTIFIER_ROOT/utilities/measurement_init.exe  \
      --mrenclave=010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708  \
      --out_file=sev_cf_utility.measurement

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe --key_subject="" --cert-subject=ark_cert.der \
      --verb="is-trusted-for-attestation" --output=sev_ts1.bin
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe --key_subject=$POLICY_KEY_FILE_NAME \
      --verb="says" --clause=sev_ts1.bin --output=sev_vse_policy1.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
      --vse_file=sev_vse_policy1.bin --duration=9000 \
      --private_key_file=$POLICY_KEY_FILE_NAME --output=sev_signed_claim_1.bin

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe --key_subject="" \
      --measurement_subject=sev_cf_utility.measurement --verb="is-trusted" \
      --output=sev_ts2.bin
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe --key_subject=$POLICY_KEY_FILE_NAME \
      --verb="says" --clause=sev_ts2.bin --output=sev_vse_policy2.bin
   $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe --vse_file=sev_vse_policy2.bin \
      --duration=9000 --private_key_file=$POLICY_KEY_FILE_NAME --output=sev_signed_claim_2.bin

    $CERTIFIER_ROOT/utilities/make_property.exe --property_name=debug --property_type='string' comparator="=" \
      --string_value=no --output=sev_property1.bin
    $CERTIFIER_ROOT/utilities/make_property.exe --property_name=migrate --property_type='string' comparator="=" \
      --string_value=no --output=sev_property2.bin
    $CERTIFIER_ROOT/utilities/make_property.exe --property_name=smt --property_type='string' comparator="=" \
      --string_value=no --output=sev_property5.bin
    $CERTIFIER_ROOT/utilities/make_property.exe --property_name='api-major' --property_type=int --comparator=">=" \
      --int_value=0 --output=sev_property3.bin
    $CERTIFIER_ROOT/utilities/make_property.exe --property_name='api-minor' --property_type=int --comparator=">=" \
      --int_value=0 --output=sev_property4.bin
    $CERTIFIER_ROOT/utilities/make_property.exe --property_name='tcb-version' --property_type=int --comparator="=" \
      --int_value=0x03000000000008115 --output=sev_property6.bin
    $CERTIFIER_ROOT/utilities/combine_properties.exe \
      --in=sev_property1.bin,sev_property2.bin,sev_property3.bin,sev_property4.bin,sev_property5.bin,sev_property6.bin \
      --output=sev_properties.bin

    $CERTIFIER_ROOT/utilities/make_platform.exe --platform_type=amd-sev-snp \
      --properties_file=sev_properties.bin --output=sev_platform.bin
    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe --platform_subject=sev_platform.bin \
      --verb="has-trusted-platform-property" --output=sev_ts3.bin
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe --key_subject=$POLICY_KEY_FILE_NAME \
      --verb="says" --clause=sev_ts3.bin --output=sev_vse_policy3.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe --vse_file=sev_vse_policy3.bin \
      --duration=9000 --private_key_file=$POLICY_KEY_FILE_NAME --output=sev_signed_claim_3.bin

    $CERTIFIER_ROOT/utilities/package_claims.exe --input=sev_signed_claim_1.bin,sev_signed_claim_2.bin,sev_signed_claim_3.bin \
      --output=sev_policy.bin
    $CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=sev_policy.bin
  popd

  echo "do-make-policy done"
}

do-make-policy $DOMAIN_NAME
echo "Policy file name is sev_policy.bin"
echo ""
