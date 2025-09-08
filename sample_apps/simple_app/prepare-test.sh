#!/bin/bash
# ############################################################################
# prepare-test.sh: Script to run build simple_app test environment.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [[ -v CERTIFIER_ROOT ]] ; then
  echo "CERTIFIER_ROOT already set."
else
  pushd ../..
  CERTIFIER_ROOT=$(pwd)
  popd
fi
EXAMPLE_DIR=$(pwd)

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [[ $ARG_SIZE == 0 ]] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./prepare-test.sh fresh [domain_name]"
  echo "  ./prepare-test.sh all [domain_name]"
  echo "  ./prepare-test.sh compile-utilities [domain_name]"
  echo "  ./prepare-test.sh make-keys [domain_name]"
  echo "  ./prepare-test.sh compile-program [domain_name]"
  echo "  ./prepare-test.sh make-policy [domain_name]"
  echo "  ./prepare-test.sh compile-certifier [domain_name]"
  echo "  ./prepare-test.sh copy-files [domain_name]"
  exit
fi

if [[ $ARG_SIZE == 1 ]] ; then
  DOMAIN_NAME="datica-test"
fi
if [[ $ARG_SIZE == 2 ]] ; then
  DOMAIN_NAME=$2
fi
echo "domain name: $DOMAIN_NAME"

POLICY_KEY_FILE_NAME="policy_key_file.$DOMAIN_NAME"
POLICY_CERT_FILE_NAME="policy_cert_file.$DOMAIN_NAME"
echo "policy key file name: $POLICY_KEY_FILE_NAME"
echo "policy cert file name: $POLICY_CERT_FILE_NAME"

POLICY_STORE_NAME="policy_store.$DOMAIN_NAME"
echo "policy store name: $POLICY_STORE_NAME"

function do-fresh() {
  echo "do-fresh"

  if [[ ! -v NO_COMPILE_UTILITIES ]] ; then
    pushd $CERTIFIER_ROOT/utilities
      make clean -f cert_utility.mak
      make clean -f policy_utilities.mak
    popd
  fi

  pushd $EXAMPLE_DIR
    make clean -f example_app.mak
  popd

  if [[ ! -d "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi
  if [[ ! -d "$EXAMPLE_DIR/service" ]] ; then
    mkdir $EXAMPLE_DIR/service
  fi
  if [[ ! -d "$EXAMPLE_DIR/app1_data" ]] ; then
    mkdir $EXAMPLE_DIR/app1_data
  fi
  if [[ ! -d "$EXAMPLE_DIR/app2_data" ]] ; then
    mkdir $EXAMPLE_DIR/app2_data
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

  pushd $EXAMPLE_DIR/service
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/service" ]] ; then
      echo " "
      echo "In $(pwd)"
      if [[ ! -z "$( ls -A '.' )" ]]; then
        rm ./*
      fi
    else
      echo "Wrong directory "
      exit
    fi
  popd

  pushd $EXAMPLE_DIR/app1_data
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/app1_data" ]] ; then
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

  pushd $EXAMPLE_DIR/app2_data
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/app2_data" ]] ; then
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

  echo "Done"
  exit
}

function do-compile-utilities() {
  echo "do-compile-utilities"

  echo "compiling utilities"
  if [[ ! -v NO_COMPILE_UTILITIES ]] ; then
    pushd $CERTIFIER_ROOT/utilities
      make -f cert_utility.mak
      make -f policy_utilities.mak
    popd
  else
    echo "not compiling utilities"
  fi

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
  popd

  echo "do-make-keys done"
}

function do-compile-program() {
  echo "do-compile-program"

  pushd $CERTIFIER_ROOT/sample_apps/simple_app
    pushd ./provisioning
    $CERTIFIER_ROOT/utilities/embed_policy_key.exe  \
      --input=$POLICY_CERT_FILE_NAME --output=../policy_key.cc
    popd

    make -f example_app.mak
  popd

  echo "do-compile-program done"
}

function do-make-policy() {
  echo "do-make-policy"

  pushd $EXAMPLE_DIR/provisioning

    echo " "

    $CERTIFIER_ROOT/utilities/measurement_utility.exe      \
      --type=hash --input=../example_app.exe --output=example_app.measurement

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
      --key_subject="platform_key_file.bin" --verb="is-trusted-for-attestation" --output=ts1.bin
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
      --key_subject=$POLICY_KEY_FILE_NAME --verb="says" \
      --clause=ts1.bin --output=vse_policy1.bin

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
      --key_subject="" --measurement_subject="example_app.measurement" \
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
  popd

  echo "do-make-policy done"
}

function do-compile-certifier() {

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
  echo "do-copy-files"

  pushd $EXAMPLE_DIR
    if [[ ! -e "$EXAMPLE_DIR/provisioning" ]] ; then
      mkdir $EXAMPLE_DIR/provisioning
    fi
    if [[ ! -e "$EXAMPLE_DIR/service" ]] ; then
      mkdir $EXAMPLE_DIR/service
    fi
    if [[ ! -e "$EXAMPLE_DIR/app1_data" ]] ; then
      mkdir $EXAMPLE_DIR/app1_data
    fi
    if [[ ! -e "$EXAMPLE_DIR/app2_data" ]] ; then
      mkdir $EXAMPLE_DIR/app2_data
    fi
  popd

  pushd $EXAMPLE_DIR/provisioning
  cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/service
  cp -p $POLICY_CERT_FILE_NAME example_app.measurement $EXAMPLE_DIR/app1_data
  cp -p $POLICY_CERT_FILE_NAME example_app.measurement $EXAMPLE_DIR/app2_data
  cp platform_attest_endorsement.bin attest_key_file.bin $EXAMPLE_DIR/app1_data
  cp platform_attest_endorsement.bin attest_key_file.bin $EXAMPLE_DIR/app2_data
  popd
}

function do-all() {
  echo " "
  echo "do-all"

  do-compile-utilities
  do-make-keys
  do-compile-program
  do-make-policy
  do-compile-certifier
  do-copy-files

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
