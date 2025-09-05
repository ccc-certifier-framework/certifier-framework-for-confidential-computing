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

if [ $ARG_SIZE == 0 ] ; then
  echo "Must call with arguments, as follows:"
  echo "  ./prepare-test.sh fresh"
  echo "  ./prepare-test.sh all client-domain_name server-domain-name"
  echo "  ./prepare-test.sh compile-utilities"
  echo "  ./prepare-test.sh make-keys client-domain_name server-domain-name"
  echo "  ./prepare-test.sh compile-program client-domain_name server-domain-name"
  echo "  ./prepare-test.sh make-policy client-domain_name server-domain-name"
  echo "  ./prepare-test.sh compile-certifier"
  echo "  ./prepare-test.sh copy-files client-domain_name server-domain-name"
  exit
fi

if [[ $ARG_SIZE == 1 && "$1" != "compile-utilities"  && "$1" != "compile-certifier" && "$1" != "fresh" ]] ; then
  echo "wrong number of arguments"
  exit
else
  CLIENT_DOMAIN_NAME=unknown
  SERVER_DOMAIN_NAME=unknown
fi
if [[ $ARG_SIZE == 3 ]] ; then
  CLIENT_DOMAIN_NAME=$2
  SERVER_DOMAIN_NAME=$3
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

  pushd $CERTIFIER_ROOT/utilities
    make clean -f cert_utility.mak
    make clean -f policy_utilities.mak
  popd
  pushd $CERTIFIER_ROOT/vm_model_tools/src
    make clean -f cf_utility.mak
  popd

  if [[ ! -v "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi
  if [[ ! -v "$EXAMPLE_DIR/service" ]] ; then
    mkdir $EXAMPLE_DIR/service
  fi
  if [[ ! -v "$EXAMPLE_DIR/app1_data" ]] ; then
    mkdir $EXAMPLE_DIR/app1_data
  fi
  if [[ ! -v "$EXAMPLE_DIR/app2_data" ]] ; then
    mkdir $EXAMPLE_DIR/app2_data
  fi

  pushd $EXAMPLE_DIR/provisioning 
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/provisioning" ]] ; then
      echo " "
      echo "in $(pwd)"
      if [[ ! -z "$( ls -A '.' )" ]]; then
        rm ./*
      fi
    else
      echo "Wrong directory "
      exit
    fi
  popd

  pushd $EXAMPLE_DIR/service
    if [[ "$(pwd)" == "${EXAMPLE_DIR}/service" ]] ; then
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
      if [[ ! -z "$( ls -A '.' )" ]]; then
        rm ./*
      fi
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
      --policy_key_name=client-policy-key            \
      --policy_key_output_file=$CLIENT_POLICY_KEY_FILE_NAME     \
      --policy_cert_output_file=$CLIENT_POLICY_CERT_FILE_NAME   \
      --platform_key_output_file=platform_key_file.bin  \
      --attest_key_output_file=attest_key_file.bin

    $CERTIFIER_ROOT/utilities/cert_utility.exe    \
      --operation=generate-policy-key-and-test-keys           \
      --policy_key_name=server-policy-key                     \
      --policy_key_output_file=$SERVER_POLICY_KEY_FILE_NAME   \
      --policy_cert_output_file=$SERVER_POLICY_CERT_FILE_NAME \
      --platform_key_output_file=platform_key_file.bin        \
      --attest_key_output_file=attest_key_file.bin
  popd

  echo "do-make-keys done"
}

function do-compile-program() {
  echo "do-compile-program"

  pushd $CERTIFIER_ROOT/sample_apps/multidomain_simple_app
    pushd ./provisioning
      $CERTIFIER_ROOT/utilities/embed_policy_key.exe  \
        --input=$CLIENT_POLICY_CERT_FILE_NAME --output=../client_policy_key.cc
    popd
  pushd ./provisioning
  $CERTIFIER_ROOT/utilities/embed_policy_key.exe  \
    --input=$SERVER_POLICY_CERT_FILE_NAME --output=../server_policy_key.cc
  popd
  make -f multidomain_app.mak

  echo "do-compile-program done"
}

# The policy
#
# ts1a.bin: client_measurement is-trusted
# ts1b.bin: server_measurement is-trusted
# ts3.bin: platform-key is-trusted-for-attestation
# ts4.bin: attest-key is-trusted-for-attestation

# vse_policy1a.bin: server-policy-key says server_measurement is-trusted
# vse_policy1b.bin: server-policy-key says client_measurement is-trusted
# vse-policy2a.bin: client-policy-key says server_measurement is-trusted
# vse-policy2b.bin: client-policy-key says client_measurement is-trusted
# vse-policy3a.bin: server-policy-key says platform-key is-trusted-for-attestation
# vse-policy3b.bin: client-policy-key says platform-key is-trusted-for-attestation
# vse-policy4.bin: platform-key says attest-key is-trusted-for-attestation
# platform_attest_endorsement.bin: platform-key-signed attest-key is-trusted-for-attestation

# signed_claim_1a.bin: server-signed server-policy-key says server_measurement is-trusted
# signed_claim_1b.bin: server-signed server-policy-key says client_measurement is-trusted
# signed_claim_2a.bin: client-signed client-policy-key says server_measurement is-trusted
# signed_claim_2b.bin: client-signed client-policy-key says client_measurement is-trusted
# signed_claim_3a.bin: server-signed server-policy-key says platform-key is-trusted-for-attestation
# signed_claim_3b.bin: client-signed client-policy-key says platform-key is-trusted-for-attestation
# platform_attest_endorsement.bin: platform-key-signed attest-key is-trusted-for-attestation
function do-make-policy() {
  echo "do-make-policy"

  pushd $EXAMPLE_DIR/provisioning
    $CERTIFIER_ROOT/utilities/measurement_utility.exe   \
      --type=hash --input=../multidomain_client_app.exe  \
      --output=multidomain_client_app.exe.measurement

    $CERTIFIER_ROOT/utilities/measurement_utility.exe   \
      --type=hash --input=../multidomain_server_app.exe \
      --output=multidomain_server_app.exe.measurement

    # ts1a.bin: client_measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe   \
      --measurement_subject=multidomain_client_app.exe.measurement  \
      --key_subject="" --verb="is-trusted" --output="ts1a.bin"

    # ts1b.bin: server_measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe   \
      --measurement_subject=multidomain_server_app.exe.measurement  \
      --key_subject="" --verb="is-trusted"    \
      --output="ts1b.bin"

    # vse_policy1a: server-policy-key says server_measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe     \
      --key_subject=$SERVER_POLICY_KEY_FILE_NAME  \
      --verb="says" --clause="ts1a.bin" --output="vse_policy1a.bin"
    echo "vse_policy1a done"

    # vse_policy1b: server-policy-key says client_measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe     \
      --key_subject=$SERVER_POLICY_KEY_FILE_NAME  \
      --verb="says" --clause=ts1b.bin --output=vse_policy1b.bin
    echo "vse_policy1b done"

    # vse_policy2a: client-policy-key says server_measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
      --key_subject=$CLIENT_POLICY_KEY_FILE_NAME \
      --verb="says" --clause="ts1a.bin" --output="vse_policy2a.bin"
    echo "vse_policy2a done"

    # vse_policy2b: client-policy-key says client_measurement is-trusted
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
       --key_subject=$CLIENT_POLICY_KEY_FILE_NAME \
       --verb="says" --clause="ts1b.bin" --output="vse_policy2b.bin"
    echo "vse_policy2b done"

    # signed_claim_1a.bin: server-signed server_vse_policy1a.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe    \
      --vse_file="vse_policy1a.bin" --duration=9000  \
      --private_key_file=$SERVER_POLICY_KEY_FILE_NAME --output="signed_claim_1a.bin"
    echo "signed_claim_1a done"

    # signed_claim_1b.bin: client signed client_vse_policy1b.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe    \
      --vse_file="vse_policy1b.bin" --duration=9000   \
      --private_key_file=$SERVER_POLICY_KEY_FILE_NAME --output="signed_claim_1b.bin"
    echo "signed_claim_1b done"

    # signed_claim_2a.bin: server-signed server_vse_policy2a.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe   \
      --vse_file="vse_policy2a.bin" --duration=9000  \
      --private_key_file=$CLIENT_POLICY_KEY_FILE_NAME --output="signed_claim_2a.bin"
    echo "signed_claim_2a done"

    # signed_claim_2b.bin: vse_policy2b.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe   \
      --vse_file="vse_policy2b.bin" --duration=9000    \
      --private_key_file=$CLIENT_POLICY_KEY_FILE_NAME --output="signed_claim_2b.bin"
    echo "signed_claim_2b done"

    # signed_claim_3a.bin: server-signed server_vse_policy3a.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe   \
      --vse_file="vse_policy3a.bin" --duration=9000  \
      --private_key_file=$SERVER_POLICY_KEY_FILE_NAME --output="signed_claim_3a.bin"
    echo "signed_claim_3a done"

    # signed_claim_3b.bin: vse_policy3b.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe   \
      --vse_file="vse_policy3b.bin" --duration=9000    \
      --private_key_file=$CLIENT_POLICY_KEY_FILE_NAME  \
      --output="signed_claim_3b.bin"
    echo "signed_claim_3b done"

     # ts3.bin: platform-key is-trusted-for-attestation
     $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe  \
       --key_subject=platform_key_file.bin --verb="is-trusted-for-attestation" \
       --output=ts3.bin
     echo "ts3 done"

     # ts4.bin: attest-key is-trusted-for-attestation
     $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
       --key_subject=attest_key_file.bin --verb="is-trusted-for-attestation" \
       --output=ts4.bin
     echo "ts4 done"
   
     # vse-policy3a.bin: sever-policy-key says platform-key is-trusted-for-attestation
     $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
       --key_subject=$SERVER_POLICY_KEY_FILE_NAME --verb="says" \
       --clause=ts3.bin --output=vse_policy3a.bin
     echo "vse_policy3a done"

     # vse-policy3b.bin: client-policy-key says platform-key is-trusted-for-attestation
     $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
        --key_subject=$CLIENT_POLICY_KEY_FILE_NAME --verb="says" \
        --clause="ts3.bin" --output="vse_policy3b.bin"
     echo "vse_policy3b done"

     # vse-policy4.bin: platform-key says attest-key is-trusted-for-attestation
     $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
        --key_subject=platform_key_file.bin --verb="says" \
        --clause=ts4.bin --output=vse_policy4.bin
     echo "vse_policy4 done"
    
     # platform_attest_endorsement.bin: platform-key-signed attest-key is-trusted-for-attestation
     $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe   \
      --vse_file="vse_policy4.bin" --duration=9000  \
      --private_key_file=platform_key_file.bin  --output=platform_attest_endorsement.bin
     echo "signed_vse_policy4 done"

     $CERTIFIER_ROOT/utilities/package_claims.exe \
       --input=signed_claim_1a.bin,signed_claim_1b.bin,signed_claim_3a.bin  \
       --output=server_policy.bin

     $CERTIFIER_ROOT/utilities/package_claims.exe  \
      --input=signed_claim_2a.bin,signed_claim_2b.bin,signed_claim_3b.bin  \
      --output=client_policy.bin

     $CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=server_policy.bin
     $CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=client_policy.bin
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

    pop
  echo "do-compile-certifier done"
}

function do-copy-files() {
  echo "do-copy-files"


  pushd $EXAMPLE_DIR/provisioning
    cp -p server_policy.bin client_policy.bin $EXAMPLE_DIR/service
    cp -p $CLIENT_POLICY_KEY_FILE_NAME  $CLIENT_POLICY_CERT_FILE_NAME \
          multidomain_client_app.exe.measurement policy.bin $EXAMPLE_DIR/app1_data
    cp -p $SERVER_POLICY_KEY_FILE_NAME $SERVER_POLICY_CERT_FILE_NAME \
          multidomain_server_app.exe.measurement policy.bin $EXAMPLE_DIR/app2_data
    cp platform_attest_endorsement.bin  attest_key_file.bin ../app1_data
    cp platform_attest_endorsement.bin  attest_key_file.bin ../app2_data
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
