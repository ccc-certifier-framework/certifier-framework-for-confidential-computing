#!/bin/bash

# ############################################################################
# build-policy.sh: Script to build policy on the deployment machine
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

source ./arg-processing.inc

# This script builds the policy employed by simpleserver to certify applications
# or VM's.  It uses the policy-key and measurements generated earlier as well
# as the (simulated or real) ark cert.

# ------------------------------------------------------------------------------------------

function do-make-policy() {
    echo "do-make-policy"

    if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
      mkdir $EXAMPLE_DIR/provisioning
    fi

    COMBINED_STATEMENTS=""
    pushd $EXAMPLE_DIR/provisioning 
    if [[ $DEPLOYMENT_ENCLAVE_TYPE = "simulated-enclave" || $DEPLOYED_ENCLAVE_TYPE = "simulated-enclave" ]]; then
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

        $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
          --vse_file=vse_policy1.bin --duration=9000 --private_key_file=$POLICY_KEY_FILE_NAME \
          --output=signed_claim_1.bin

        $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
          --measurement_subject="cf_utility.measurement" \
          --verb="is-trusted" --output=ts2.bin

        $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
          --key_subject=$POLICY_KEY_FILE_NAME --verb="says" \
          --clause=ts2.bin --output=vse_policy2.bin

        $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
          --vse_file=vse_policy2.bin  --duration=9000  \
          --private_key_file=$POLICY_KEY_FILE_NAME --output=signed_claim_2.bin

        $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
          --key_subject=attest_key_file.bin --verb="is-trusted-for-attestation" --output=tsc1.bin

        $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
          --key_subject=platform_key_file.bin --verb="says" \
          --clause=tsc1.bin --output=vse_policy3.bin

        $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
          --vse_file=vse_policy3.bin --duration=9000 \
          --private_key_file=platform_key_file.bin --output=platform_attest_endorsement.bin

    	COMBINED_STATEMENTS="signed_claim_1.bin,signed_claim_2.bin"
    fi

    if [[ $DEPLOYED_ENCLAVE_TYPE = "sev-enclave" ]]; then
        echo " "
        echo "For simulated enclave"

        $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe --key_subject="" \
	  --cert-subject=ark_cert.der \
          --verb="is-trusted-for-attestation" --output=sev_ts1.bin

        $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe --key_subject=$POLICY_KEY_FILE_NAME \
          --verb="says" --clause=sev_ts1.bin --output=sev_vse_policy1.bin

        $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe \
          --vse_file=sev_vse_policy1.bin --duration=9000 \
          --private_key_file=$POLICY_KEY_FILE_NAME --output=sev_signed_claim_1.bin

	if [[ $TEST_TYPE = "simulated" ]]; then
      		$CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe --key_subject="" \
       		--measurement_subject=sev_cf_utility.measurement --verb="is-trusted" \
               --output=sev_ts2.bin
        else
     		$CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe --key_subject="" \
      		--measurement_subject=Pauls_vm.measurement --verb="is-trusted" \
      		--output=sev_ts2.bin
    	fi

        $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe --key_subject=$POLICY_KEY_FILE_NAME \
          --verb="says" --clause=sev_ts2.bin --output=sev_vse_policy2.bin

        $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe --vse_file=sev_vse_policy2.bin \
          --duration=9000 --private_key_file=$POLICY_KEY_FILE_NAME --output=sev_signed_claim_2.bin

        $CERTIFIER_ROOT/utilities/make_property.exe --property_name=debug --property_type='string' \
	  --comparator="=" --string_value=no --output=sev_property1.bin

        $CERTIFIER_ROOT/utilities/make_property.exe --property_name=migrate --property_type='string' \
	  --comparator="=" --string_value=no --output=sev_property2.bin

        $CERTIFIER_ROOT/utilities/make_property.exe --property_name='api-major' \
	  --property_type=int --comparator=">=" --int_value=0 --output=sev_property3.bin

        $CERTIFIER_ROOT/utilities/make_property.exe --property_name='api-minor' \
	  --property_type=int --comparator=">=" --int_value=0 --output=sev_property4.bin

        $CERTIFIER_ROOT/utilities/make_property.exe --property_name='tcb-version' --property_type=int \
	  --comparator="=" --int_value=0x03000000000008115 --output=sev_property6.bin

        $CERTIFIER_ROOT/utilities/make_property.exe --property_name=smt --property_type='string' \
	  --comparator="=" --string_value=no --output=sev_property5.bin

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

        COMBINED_STATEMENTS="$COMBINED_STATEMENTS,sev_signed_claim_1.bin,sev_signed_claim_2.bin,sev_signed_claim_3.bin"
    fi

    $CERTIFIER_ROOT/utilities/package_claims.exe --input=$COMBINED_STATEMENTS \
      --output=$POLICY_FILE_NAME

    echo ""
    echo "Final policy"
    echo ""
    $CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=$POLICY_FILE_NAME
  popd

  echo ""
  echo "do-make-policy done"
}

# ---------------------------------------------------------------------------------------------------

echo "Processing arguments"
process-args
echo "Arguments processed"

if [[ $VERBOSE -eq 1 ]]; then                   
        print-variables                         
fi

do-make-policy
echo ""
