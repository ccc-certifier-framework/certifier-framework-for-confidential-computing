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

SIMULATED_SEV=1

function do-fresh() {
  echo " "
  echo "do-fresh"

  if [[ ! -v NO_COMPILE_UTILITIES ]] ; then
    pushd $CERTIFIER_ROOT/utilities
      make clean -f cert_utility.mak
      make clean -f policy_utilities.mak
    popd
  fi

  pushd $EXAMPLE_DIR
    make clean -f sev_example_app.mak
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

function do-initialize-sev-simulator() {
  echo " "
  echo "do-initialize-sev-simulator"

  pushd $CERTIFIER_ROOT/sev-snp-simulator
    if [[ -d "/etc/certifier-snp-sim" ]] ; then
      if [[ -e "/etc/certifier-snp-sim/ec-secp384r1-priv-key.pem" && -e "/etc/certifier-snp-sim/ec-secp384r1-pub-key.pem" ]] ; then
        echo "sev simultator keys already exist"
        return
      else
        echo "building simulator"
      fi
    fi
    make
    make keys
    if [[ ! -d /etc/certifier-snp-sim ]] ; then
      sudo etc/certifier-snp-sim
    fi
    set +e
    sudo make insmod
    sudo cp ./keys/* /etc/certifier-snp-sim
    set -e
  popd
  echo "do-initialize-sev-simulator done"
}

function do-compile-utilities() {
  echo " "
  echo "do-compile-utilities"

  if [[ ! -v NO_COMPILE_UTILITIES ]] ; then
    pushd $CERTIFIER_ROOT/utilities
      make -f cert_utility.mak
      make -f policy_utilities.mak
    popd
  fi

  echo "do-compile-utilities done"
}

function do-make-keys() {
  echo " "
  echo "do-make-keys"

  if [[ ! -d "$EXAMPLE_DIR/provisioning" ]] ; then
    mkdir $EXAMPLE_DIR/provisioning
  fi

  pushd $EXAMPLE_DIR/provisioning
    $CERTIFIER_ROOT/utilities/cert_utility.exe  \
      --operation=generate-policy-key-and-test-keys  \
      --policy_key_output_file=$POLICY_KEY_FILE_NAME  \
      --policy_cert_output_file=$POLICY_CERT_FILE_NAME \

    $CERTIFIER_ROOT/utilities/simulated_sev_key_generation.exe  \
         --ark_der=ark_cert.der --ask_der=ask_cert.der \
         --vcek_der=vcek_cert.der  \
         --vcek_key_file=/etc/certifier-snp-sim/ec-secp384r1-pub-key.pem
  popd

  echo "do-make-keys done"
}

function do-compile-program() {
  echo " "
  echo "do-compile-program"

  pushd $EXAMPLE_DIR
    pushd ./provisioning
      $CERTIFIER_ROOT/utilities/embed_policy_key.exe  \
        --input=$POLICY_CERT_FILE_NAME --output=../policy_key.cc
    popd

    if [[ -v SIMULATED_SEV ]] ; then
      CFLAGS='-DSEV_DUMMY_GUEST' make -f sev_example_app_new_api.mak
    else
      make -f sev_example_app_new_api.mak
    fi
  popd

  echo "do-compile-program done"
}

# usage: sev-snp-measure [-h] [--version] [-v] --mode {sev,seves,snp,snp:ovmf-hash,snp:svsm}
#       [--vcpus N] [--vcpu-type CPUTYPE] [--vcpu-sig VALUE]
#       [--vcpu-family FAMILY] [--vcpu-model MODEL] [--vcpu-stepping STEPPING]
#       [--vmm-type VMMTYPE] --ovmf PATH [--kernel PATH] [--initrd PATH]
#       [--append CMDLINE] [--guest-features VALUE]
#       [--output-format {hex,base64}] [--snp-ovmf-hash HASH] [--dump-vmsa]
#       [--svsm PATH] [--vars-size SIZE | --vars-file PATH]
# The following arguments are required: --mode, --ovmf

function do-make-policy() {
  echo " "
  echo "do-make-policy"

  pushd $EXAMPLE_DIR/provisioning
    echo " "

    if [[ -v SIMULATED_SEV ]] ; then
      $CERTIFIER_ROOT/utilities/measurement_init.exe \
        --mrenclave=010203040506070801020304050607080102030405060708010203040506070801020304050607080102030405060708 \
        --out_file=sev-example-app.measurement
    else
      pushd $CERTIFIER_ROOT
        if [[ ! -d "../sev-snp-measure" ]] ; then
          echo "sev-snp-measure tool not found"
          exit
        else
          snp-tool-dir=$(pwd)
          snp-tool="$snp-tool-dir/sev-snp-measure.py"
          echo "sev-snp-measure arguments not ready"
          exit
        fi
      popd
    fi

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe    \
        --cert-subject=ark_cert.der --verb="is-trusted-for-attestation"  \
        --output=ts1.bin
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe \
      --key_subject=$POLICY_KEY_FILE_NAME --verb="says" \
      --clause=ts1.bin --output=vse_policy1.bin

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe \
      --key_subject="" --measurement_subject="sev-example-app.measurement" \
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

    $CERTIFIER_ROOT/utilities/make_property.exe    \
        --property_name=debug                       \
        --property_type='string' comparator="="     \
        --string_value=no                           \
        --output=property1.bin

    $CERTIFIER_ROOT/utilities/make_property.exe    \
        --property_name=migrate                     \
        --property_type='string' comparator="="     \
        --string_value=no                           \
        --output=property2.bin

    $CERTIFIER_ROOT/utilities/make_property.exe    \
        --property_name=smt                         \
        --property_type='string' comparator="="     \
        --string_value=no                           \
        --output=property5.bin
    $CERTIFIER_ROOT/utilities/make_property.exe    \
        --property_name='api-major'                 \
        --property_type=int                         \
        --comparator=">="                           \
        --int_value=0                               \
        --output=property3.bin

    $CERTIFIER_ROOT/utilities/make_property.exe    \
        --property_name='api-minor'                 \
        --property_type=int                         \
        --comparator=">="                           \
        --int_value=0                               \
        --output=property4.bin

    $CERTIFIER_ROOT/utilities/make_property.exe    \
        --property_name='tcb-version'               \
        --property_type=int                         \
        --comparator="="                            \
        --int_value=0x03000000000008115             \
        --output=property6.bin

    $CERTIFIER_ROOT/utilities/combine_properties.exe   \
      --in=property1.bin,property2.bin,property3.bin,property4.bin,property5.bin,property6.bin \
      --output=properties.bin

    $CERTIFIER_ROOT/utilities/make_platform.exe    \
        --platform_type=amd-sev-snp                 \
        --properties_file=properties.bin            \
        --output=platform.bin

    $CERTIFIER_ROOT/utilities/make_unary_vse_clause.exe    \
        --platform_subject=platform.bin                     \
        --verb="has-trusted-platform-property"              \
        --output=ts3.bin
    $CERTIFIER_ROOT/utilities/make_indirect_vse_clause.exe     \
        --key_subject=$POLICY_KEY_FILE_NAME \
        --verb="says"                                           \
        --clause=ts3.bin                                        \
        --output=vse_policy3.bin
    $CERTIFIER_ROOT/utilities/make_signed_claim_from_vse_clause.exe    \
        --vse_file=vse_policy3.bin                                      \
        --duration=9000                                                 \
        --private_key_file=$POLICY_KEY_FILE_NAME \
        --output=signed_claim_3.bin

    $CERTIFIER_ROOT/utilities/package_claims.exe                           \
        --input=signed_claim_1.bin,signed_claim_2.bin,signed_claim_3.bin    \
        --output=policy.bin
    $CERTIFIER_ROOT/utilities/print_packaged_claims.exe --input=policy.bin
  popd

  echo " "
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

  pushd $EXAMPLE_DIR
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
  popd

  pushd $EXAMPLE_DIR/provisioning
    cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/service
    cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/app1_data
    cp -p $POLICY_KEY_FILE_NAME $POLICY_CERT_FILE_NAME policy.bin $EXAMPLE_DIR/app2_data
    cp -p ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/service
    cp -p ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/app1_data
    cp -p ark_cert.der ask_cert.der vcek_cert.der $EXAMPLE_DIR/app2_data
  popd
  echo "do-copy-files done"
}

function do-all() {
  echo " "
  echo "do-all"

  do-initialize-sev-simulator
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
