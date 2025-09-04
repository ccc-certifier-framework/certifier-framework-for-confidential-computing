#!/bin/bash
# ############################################################################
# prepare-test.sh: Script to run build simple_app test environment.
# ############################################################################

set -Eeuo pipefail
Me=$(basename "$0")

if [ -z "{$CERTIFIER_ROOT}+set" ] ; then
  echo " "
  CERTIFIER_ROOT=../../..
else
  echo " "
  echo "CERTIFIER_ROOT already set."
fi
EXAMPLE_DIR=$(pwd)

echo " "
echo "Certifier root: $CERTIFIER_ROOT"
echo "Example directory: $EXAMPLE_DIR"

ARG_SIZE="$#"

if [ $ARG_SIZE == 0 ] ; then
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
  CLIENT_DOMAIN_NAME="datica-test"
  SERVER_DOMAIN_NAME="datica-test"
fi
if [[ $ARG_SIZE == 2 ]] ; then
  CLIENT_DOMAIN_NAME=$2
  SERVER_DOMAIN_NAME="datica-test"
fi

CLIENT_POLICY_KEY_FILE_NAME="client_policy_key_file.$CLIENT_DOMAIN_NAME"
SERVER_POLICY_KEY_FILE_NAME="server_policy_key_file.$SERVER_DOMAIN_NAME"
CLIENT_POLICY_CERT_FILE_NAME="client_policy_cert_file.$CLIENT_DOMAIN_NAME"
SERVER_POLICY_CERT_FILE_NAME="server_policy_cert_file.$SERVER_DOMAIN_NAME"
CLIENT_POLICY_STORE_NAME="client_policy_store.$CLIENT_DOMAIN_NAME"
SERVER_POLICY_STORE_NAME="server_policy_store.$SERVER_DOMAIN_NAME"

echo "client policy key file name: $CLIENT_POLICY_KEY_FILE_NAME"
echo "server policy key file name: $SERVER_POLICY_KEY_FILE_NAME"
echo "client policy cert file name: $CLIENT_POLICY_CERT_FILE_NAME"
echo "server policy cert file name: $SERVER_POLICY_CERT_FILE_NAME"
echo "server policy store name: $SERVER_POLICY_STORE_NAME"
echo "client policy store name: $CLIENT_POLICY_STORE_NAME"

function do-fresh() {
  echo "do-fresh"

  pushd $CERTIFIER_ROOT/utilities > /dev/null
  make clean -f cert_utility.mak
  make clean -f policy_utilities.mak
  popd > /dev/null
  pushd $CERTIFIER_ROOT/vm_model_tools/src > /dev/null
  make clean -f cf_utility.mak
  popd > /dev/null

  mkdir $EXAMPLE_DIR/provisioning || true
  pushd $EXAMPLE_DIR/provisioning  > /dev/null

  if [[ "$(pwd)" == "${EXAMPLE_DIR}/provisioning" ]] ; then
    echo " "
    echo "in $(pwd)"
    rm ./* || true
    echo " "
  else
    echo "Wrong directory "
    exit
  fi
  popd > /dev/null

  mkdir $EXAMPLE_DIR/service || true
  pushd $EXAMPLE_DIR/service > /dev/null

  if [[ "$(pwd)" == "${EXAMPLE_DIR}/service" ]] ; then
    echo " "
    echo "In $(pwd)"
    rm ./* || true
    echo " "
  else
    echo "Wrong directory "
    exit
  fi
  popd > /dev/null

  mkdir $EXAMPLE_DIR/app1_data || true
  pushd $EXAMPLE_DIR/app1_data > /dev/null

  if [[ "$(pwd)" == "${EXAMPLE_DIR}/app1_data" ]] ; then
    echo " "
    echo "in $(pwd)"
    rm ./* || true
    echo " "
  else
    echo "Wrong directory "
    exit
  fi
  popd > /dev/null

  mkdir $EXAMPLE_DIR/app2_data || true
  pushd $EXAMPLE_DIR/app2_data > /dev/null
  if [[ "$(pwd)" == "${EXAMPLE_DIR}/app2_data" ]] ; then
    echo " "
    echo "in $(pwd)"
    rm ./* || true
    echo " "
  else
    echo "Wrong directory "
    exit
  fi
  popd > /dev/null

  echo "Done"

  exit
}

function do-compile-utilities() {
  echo "do-compile-utilities"

  pushd $CERTIFIER_ROOT/utilities > /dev/null
  make -f cert_utility.mak
  make -f policy_utilities.mak
  popd > /dev/null 2>&1

  echo "do-compile-utilities done"
}

function do-make-keys() {
  echo "do-make-keys"

  mkdir $EXAMPLE_DIR/provisioning || true
  pushd $EXAMPLE_DIR/provisioning > /dev/null

  $CERTIFIER_ROOT/utilities/cert_utility.exe            \
    --operation=generate-policy-key-and-test-keys           \
    --policy_key_name=client-policy-key                     \
    --policy_key_output_file=$CLIENT_POLICY_KEY_FILE_NAME     \
    --policy_cert_output_file=$CLIENT_POLICY_CERT_FILE_NAME   \
    --platform_key_output_file=platform_key_file.bin        \
    --attest_key_output_file=attest_key_file.bin

  $CERTIFIER_ROOT/utilities/cert_utility.exe                              \
    --operation=generate-policy-key-and-test-keys           \
    --policy_key_name=server-policy-key                     \
    --policy_key_output_file=$SERVER_POLICY_KEY_FILE_NAME   \
    --policy_cert_output_file=$SERVER_POLICY_CERT_FILE_NAME \
    --platform_key_output_file=platform_key_file.bin        \
    --attest_key_output_file=attest_key_file.bin

  popd > /dev/null

  echo "do-make-keys done"
}

function do-compile-program() {
  echo "do-compile-program"

  pushd $CERTIFIER_ROOT/sample_apps/multidomain_simple_app > /dev/null
  pushd ./client_provisioning > /dev/null
  $CERTIFIER_ROOT/utilities/embed_policy_key.exe      \
    --input=$CLIENT_POLICY_CERT_FILE_NAME --output=../client_policy_key.cc
  popd > /dev/null
  pushd ./client_provisioning > /dev/null
  $CERTIFIER_ROOT/utilities/embed_policy_key.exe      \
    --input=$SERVER_POLICY_CERT_FILE_NAME --output=../server_policy_key.cc
  popd > /dev/null
  make -f multidomain_app.mak

  echo "do-compile-program done"
}

function do-make-policy() {
  echo "do-make-policy"

  $CERTIFIER_ROOT/utilities/measurement_utility.exe   \
     --type=hash --input=../multidomain_client_app.exe       \
     --output=multidomain_client_app.exe.measurement

  $CERTIFIER_ROOT/utilities/measurement_utility.exe   \
     --type=hash --input=../multidomain_server_app.exe       \
     --output=multidomain_server_app.exe.measurement

  $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe            \
    --key_subject=""                                 \
    --measurement_subject=multidomain_client_app.exe.measurement      \
    --verb="is-trusted"                              \
    --output=ts2a-md-server.bin

    # vse_policy2a is server-policy-key says server_measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe     \
       --key_subject=server_policy_key_file.bin     \
       --verb="says"                                \
       --clause=ts2a-md-server.bin                  \
       --output=server_vse_policy2a.bin

    # ts2b is client-measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe            \
       --key_subject=""                                 \
       --measurement_subject=multidomain_client_app.exe.measurement \
       --verb="is-trusted"                              \
       --output=ts2b-md-client.bin
   # vse_policy2b is server-policy-key says client_measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe     \
       --key_subject=server_policy_key_file.bin     \
       --verb="says"                                \
       --clause=ts2b-md-client.bin                  \
       --output=server_vse_policy2b.bin

    # vse_policy2c is client-policy-key says server_measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
       --key_subject=client_policy_key_file.bin \
       --verb="says" \
       --clause=ts2a-md-server.bin \
       --output=client_vse_policy2c.bin

    # vse_policy2d is client-policy-key says client_measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
       --key_subject=client_policy_key_file.bin \
       --verb="says" \
       --clause=ts2b-md-client.bin \
       --output=client_vse_policy2d.bin

    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe    \
      --vse_file=server_vse_policy1a.bin                   \
      --duration=9000                                      \
      --private_key_file=server_policy_key_file.bin        \
      --output=server_signed_claim_1a.bin

    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe    \
      --vse_file=client_vse_policy1b.bin                   \
      --duration=9000                                      \
      --private_key_file=client_policy_key_file.bin        \
      --output=client_signed_claim_1b.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe   \
      --vse_file=server_vse_policy2a.bin                  \
      --duration=9000                                     \
      --private_key_file=server_policy_key_file.bin       \
      --output=server_signed_claim_2a.bin

    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe   \
      --vse_file=server_vse_policy2b.bin                  \
      --duration=9000                                     \
      --private_key_file=server_policy_key_file.bin       \
      --output=server_signed_claim_2b.bin

    # client-policy-key signs vse_policy2c and policy2d
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe   \
      --vse_file=client_vse_policy2c.bin                  \
      --duration=9000                                     \
      --private_key_file=client_policy_key_file.bin       \
      --output=client_signed_claim_2c.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe   \
      --vse_file=client_vse_policy2d.bin                  \
      --duration=9000                                     \
      --private_key_file=client_policy_key_file.bin       \
      --output=client_signed_claim_2d.bin

    $CERTIFIER_ROOT/utilities/package_claims.exe       \
      --input=server_signed_claim_1a.bin,server_signed_claim_2a.bin,server_signed_claim_2b.bin \ 
      --output=server_policy.bin
    $CERTIFIER_ROOT/utilities/package_claims.exe       \
      --input=client_signed_claim_1b.bin,client_signed_claim_2c.bin,client_signed_claim_2d.bin \
      --output=client_policy.bin
    $CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=server_policy.bin
    $CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=client_policy.bin

  echo " "

  popd > /dev/null

  echo "do-make-policy done"
}

function do-compile-certifier() {
  echo "do-compile-certifier"

  pushd $CERTIFIER_ROOT/certifier_service > /dev/null

  pushd graminelib > /dev/null
    make dummy
  popd > /dev/null
  pushd oelib > /dev/null
    make dummy
  popd > /dev/null
  pushd isletlib > /dev/null
    make dummy
  popd > /dev/null
  pushd teelib > /dev/null
    make
  popd > /dev/null

  go build simpleserver.go

  popd > /dev/null

  echo "do-compile-certifier done"
}

function do-copy-files() {
  echo "do-copy-files"

  mkdir $EXAMPLE_DIR/app1_data || true
  mkdir $EXAMPLE_DIR/app2_data || true
  pushd $EXAMPLE_DIR/provisioning > /dev/null
  cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/service
  cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME example_app.measurement policy.bin $EXAMPLE_DIR/app1_data
  cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME example_app.measurement policy.bin $EXAMPLE_DIR/app2_data
  cp platform_attest_endorsement.bin  attest_key_file.bin ../app1_data || true
  cp platform_attest_endorsement.bin  attest_key_file.bin ../app2_data || true
  popd > /dev/null
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
