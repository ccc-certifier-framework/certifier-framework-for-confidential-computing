#!/bin/bash
# ############################################################################
# prepare-test.sh: Script to run build cf_utility test environment.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../../..
  CERTIFIER_ROOT=$(pwd)
  popd
fi
EXAMPLE_DIR=$(pwd)

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [[ $ARG_SIZE == 0 || $ARG_SIZE > 2 ]] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./prepare-test.sh fresh"
  echo "  ./prepare-test.sh all [domain name]"
  echo "  ./prepare-test.sh compile-utilities"
  echo "  ./prepare-test.sh make-keys [domain name]"
  echo "  ./prepare-test.sh compile-program"
  echo "  ./prepare-test.sh make-policy [domain name]"
  echo "  ./prepare-test.sh compile-certifier"
  echo "  ./prepare-test.sh copy-files [domain name]"
  exit
fi

if [[ $ARG_SIZE == 1 ]] ; then
  DOMAIN_NAME="datica-test"
else
  DOMAIN_NAME=$2
fi
echo "domain name: $DOMAIN_NAME"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "policy key file name: $POLICY_KEY_FILE_NAME"
echo "policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
CRYPTSTORE_NAME="cryptstore.$DOMAIN_NAME"
echo "policy store name: $POLICY_STORE_NAME"
echo "cryptstore name: $CRYPTSTORE_NAME"

function do-fresh() {
  echo " "
  echo "do-fresh"

  pushd $CERTIFIER_ROOT/utilities
    make clean -f cert_utility.mak
    make clean -f policy_utilities.mak
  popd

  pushd $CERTIFIER_ROOT/vm_model_tools/src
    make clean -f cf_utility.mak
  popd

  if [[ ! -d "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi
  pushd $EXAMPLE_DIR/provisioning
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/provisioning" ]] ; then
      echo " "
      echo "in $(pwd)"
      if [[ ! -z "$( ls -A '.' )" ]]; then
        rm ./*
      fi
      echo " "
    else
      echo "Wrong directory "
      exit
    fi
  popd

  if [[ ! -d "$EXAMPLE_DIR/service" ]] ; then
    mkdir $EXAMPLE_DIR/service
  fi
  pushd $EXAMPLE_DIR/service
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/service" ]] ; then
      echo " "
      echo "In $(pwd)"
      if [[ ! -z "$( ls -A '.' )" ]]; then
        rm ./*
      fi
      echo " "
    else
      echo "Wrong directory "
      exit
    fi
  popd

  pushd $EXAMPLE_DIR
    if [[ -e $POLICY_STORE_NAME  ]] ; then
      rm $POLICY_STORE_NAME
    fi
    if [[ -e $CRYPTSTORE_NAME  ]] ; then
      rm $CRYPTSTORE_NAME
    fi
  popd

  echo "Done"
  exit
}

function do-compile-utilities() {
  echo " "
  echo "do-compile-utilities"

  pushd $CERTIFIER_ROOT/utilities
    make -f cert_utility.mak
    make -f policy_utilities.mak
  popd

  echo "do-compile-utilities done"
}

function do-make-keys() {
  echo "do-make-keys"

  if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi
  pushd $EXAMPLE_DIR/provisioning
    $CERTIFIER_ROOT/utilities/cert_utility.exe  \
      --operation=generate-policy-key-and-test-keys  \
      --policy_key_output_file=$POLICY_KEY_FILE_NAME  \
      --policy_cert_output_file=$POLICY_CERT_FILE_NAME \
      --platform_key_output_file=platform_key_file.bin  \
      --attest_key_output_file=attest_key_file.bin

    $CERTIFIER_ROOT/utilities/simulated_sev_key_generation.exe            \
         --ark_der=sev_ark_cert.der                                        \
         --ask_der=sev_ask_cert.der                                        \
         --vcek_der=sev_vcek_cert.der                                      \
         --vcek_key_file=/etc/certifier-snp-sim/ec-secp384r1-pub-key.pem

    mv sev_ark_cert.der ark_cert.der
    mv sev_ask_cert.der ask_cert.der
    mv sev_vcek_cert.der vcek_cert.der
  popd

  echo "do-make-keys done"
}

function do-compile-program() {
  echo " "
  echo "do-compile-program"

  pushd $CERTIFIER_ROOT/vm_model_tools/src
  make -f cf_utility.mak
  popd

  echo "do-compile-program done"
}

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

function do-compile-certifier() {
  echo " "
  echo "do-compile-certifier"

  pushd $CERTIFIER_ROOT/certifier_service/certprotos
    if [[ ! -e "./certifier.proto.go" ]] ; then
      echo " "
      echo "making protobufs"
      protoc --go_opt=paths=source_relative --go_out=. --go_opt=M=certifier.proto ./certifier.proto
    fi
  popd

  pushd $CERTIFIER_ROOT/certifier_service
    pushd graminelib
      make dummy
    popd
   pushd oelib
     make dummy
   popd
    pushd isletlib
      make dummy
    popd
    pushd teelib
      make
    popd

    go build simpleserver.go
  popd

  echo "do-compile-certifier done"
}

function do-copy-files() {
  echo " "
  echo "do-copy-files"

  if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi
  if [[ ! -e "$EXAMPLE_DIR/service" ]] ; then
    mkdir $EXAMPLE_DIR/service
  fi
  pushd $EXAMPLE_DIR/provisioning
    cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/service
    cp -p sev_policy.bin ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/service
    cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME ..
  popd

  echo "do-copy-files done"
}

function do-all() {
  echo " "
  echo "do-all"

  do-compile-utilities
  do-make-keys $DOMAIN_NAME
  do-compile-program
  do-make-policy $DOMAIN_NAME
  do-compile-certifier
  do-copy-files $DOMAIN_NAME

  echo " "
  echo "do-all done"
}


if [ "$1" == "fresh" ] ; then
  echo " "
  do-fresh
  exit
fi

if [ "$1" == "all" ] ; then
  echo "Base name: $0"
  do-all
  exit
fi

if [ "$1" == "compile-utilities" ] ; then
  echo " "
  do-compile-utilities
  exit
fi

if [ "$1" == "make-keys" ] ; then
  echo " "
  do-make-keys
  exit
fi

if [ "$1" == "compile-program" ] ; then
  echo " "
  do-compile-program
  exit
fi

if [ "$1" == "make-policy" ] ; then
  echo " "
  do-make-policy
  exit
fi

if [ "$1" == "compile-certifier" ] ; then
  echo " "
  do-compile-certifier
  exit
fi

if [ "$1" == "copy-files" ] ; then
  echo " "
  do-copy-files
  exit
fi

echo " "
echo "Unknown option: $1"
