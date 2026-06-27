
# ------------------------------------------------------------------------------------

# Argument proccessing
ARG_SIZE="$#"

if [[ ${CERTIFIER_ROOT+x} ]]; then
  echo "CERTIFIER_ROOT already set"
else
  echo "setting CERTIFIER_ROOT"
  pushd ../../.. > /dev/null
  CERTIFIER_ROOT=$(pwd) > /dev/null
  popd > /dev/null
fi

if [[ ${EXAMPLE_DIR+x} ]]; then
  echo "EXAMPLE_DIR already set"
else
  echo "setting EXAMPLE_DIR"
  EXAMPLE_DIR=$CERTIFIER_ROOT/vm_model_tools > /dev/null
fi

#echo ""
#echo "Starting"

function print-options() {

  echo ""
  echo "Defined flags and variables"
  echo ""
  echo "-----------------------------------------------------------------"
  echo "Source directory flag: -sd"
  echo "Test directory flag: -td"
  echo "Data directory flag: -dd"
  echo "Domain Name flag: -dn"
  echo "Enclave type, flag: -et"
  echo "Clean flag: -clean"
  echo "Loud flag: -loud"
  echo ""
  echo "Compile certifier utilities flag: -cu"
  echo "Compile program flag: -cp"
  echo ""
  echo "Tpm device flag: -tpm"
  echo "Seal store flag: -ss"
  echo "Quote store flag: -qs"
  echo ""
  echo "Run gtests flag: -rgt"
  echo "Run test flag: -rt"
  echo "Recertify flag: -recertify"
  echo "Provision keys flag: -pk"
  echo ""
  echo "Policy key file flag: -pkn"
  echo "Policy cert file flag: -cfn"
  echo "Cryptstore name flag:  -csn"
  echo "Policy store name flag:  -psn"
  echo "Policy file name flag:  -pfn"
  echo "Policy server IP flag:  -psa"
  echo "Policy port: flag -psp"
  echo "Tpm cert chain flag: -cc_flag"
  echo "Tpm root file flag: -cr_flag"
  echo "Current root file flag: -crf"
  echo "Current issuer file flag: -cif"

  echo ""
  echo "Symmetric algorithm flag: -sea"
  echo "Asymmetric algorithm flag: -aen"
  echo "-----------------------------------------------------------------"
  echo ""
}

# Defaults

SRC_DIR=$EXAMPLE_DIR/src
TEST_DIR=$SRC_DIR/test
DATA_DIR=$TEST_DIR/
DOMAIN_NAME="datica"
ENCLAVE_TYPE="simulated-enclave"
PROVISION_KEYS=1
COMPILE_UTIL=1
COMPILE_PROGRAM=1
RUN_GTESTS=1
RUN_TEST=1
VERBOSE=1
CLEAN=1
RECERTIFY=1
POLICY_KEY_FILE_NAME="policy_key_file.bin"
POLICY_CERT_FILE_NAME="policy_cert_file.bin"
POLICY_STORE_NAME="policy_store.bin"
POLICY_FILE_NAME="policy.bin"
CRYPTSTORE_NAME="cryptstore.bin"
POLICY_SERVER_ADDRESS="localhost"
POLICY_SERVER_PORT="8123"
SYMMETRIC_ENCRYPTION_ALGORITHM="aes-256-gcm"
ASYMMETRIC_ENCRYPTION_ALGORITHM="RSA-4096"
TPM_DEVICE="/dev/tpm0"
SEAL_STORE="seal_hierarchy.bin"
QUOTE_STORE="quote_hierarchy.bin"
TPM_CERT_CHAIN_FILE="ekchain.bin"
TPM_ROOTS_FILE="trustedRoots.bin"
CURRENT_TPM_ROOT_FILE="/var/lib/swtpm-localca/swtpm-localca-rootca-cert.pem"
CURRENT_TPM_ISSUER_FILE="/var/lib/swtpm-localca/issuercert.pem"

function print-variables() {

  echo "Defined flags and variables"
  echo ""
  echo "-----------------------------------------------------------------"
  echo "Certifier root: $CERTIFIER_ROOT"
  echo "Example directory: $EXAMPLE_DIR"
  echo ""
  echo "Source directory: $SRC_DIR"
  echo "Test directory: $TEST_DIR"
  echo "Data directory: $DATA_DIR"
  echo "Domain Name: $DOMAIN_NAME"
  echo ""
  echo "Enclave type: $ENCLAVE_TYPE"
  echo "Tpm device name: $TPM_DEVICE"
  echo "Quote store file name: $QUOTE_STORE"
  echo "Seal store file name: $SEAL_STORE"
  echo ""
  echo "Compile certifier utilities flag: $COMPILE_UTIL"
  echo "Compile program flag: $COMPILE_PROGRAM"
  echo "Clean flag: $CLEAN"
  echo "Loud flag: $VERBOSE"
  echo ""
  echo "Run gtests: $RUN_GTESTS"
  echo "Run tests: $RUN_TEST"
  echo "Recertify: $RECERTIFY"
  echo "Provision keys: $PROVISION_KEYS"
  echo ""
  echo "Policy cert file: $POLICY_CERT_FILE_NAME"
  echo "Policy file name: $POLICY_FILE_NAME"
  echo "Policy store file name: $POLICY_STORE_NAME"
  echo "Cryptstore name: $CRYPTSTORE_NAME"
  echo ""
  echo "Tpm cert chain file: $TPM_CERT_CHAIN_FILE"
  echo "Tpm trusted root file: $TPM_ROOTS_FILE"
  echo "Current tpm root file: $CURRENT_TPM_ROOT_FILE"
  echo "Current tpm issuer file: $CURRENT_TPM_ISSUER_FILE"
  echo ""
  echo "Policy server IP: $POLICY_SERVER_ADDRESS"
  echo "Policy port: $POLICY_SERVER_PORT"
  echo "Symmetric algorithm: $SYMMETRIC_ENCRYPTION_ALGORITHM"
  echo "Asymmetric algorithm: $ASYMMETRIC_ENCRYPTION_ALGORITHM"
  echo "-----------------------------------------------------------------"
  echo ""
}

arg_string=$*
function process-args() {

  IFS=' ' read -ra array <<< "$arg_string"
  for (( i=0; i < $ARG_SIZE; i++ )); do
    #echo "Processing arg $i: ${array[i]}"

    if [[ ${array[i]} = "-sd" ]]; then
            SRC_DIR="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-td" ]]; then
            TEST_DIR="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-cu" ]]; then
            COMPILE_UTIL="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-cp" ]]; then
            COMPILE_PROGRAM="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-cfn" ]]; then
            POLICY_CERT_FILE_NAME="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-dn" ]]; then
            DOMAIN_NAME="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-et" ]]; then
            ENCLAVE_TYPE="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-pk" ]]; then
            PROVISION_KEYS="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-recertify" ]]; then
            RECERTIFY="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-psn" ]]; then
            POLICY_STORE_NAME="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-csn" ]]; then
            CRYPTSTORE_NAME="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-dd" ]]; then
            DATA_DIR="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-sea" ]]; then
            SYMMETRIC_ENCRYPTION_ALGORITHM="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-aen" ]]; then
            ASYMMETRIC_ENCRYPTION_ALGORITHM="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-pfn" ]]; then
            POLICY_FILE_NAME="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-psa" ]]; then
            POLICY_SERVER_ADDRESS="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-psp" ]]; then
            POLICY_SERVER_PORT="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-clean" ]]; then
            CLEAN="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-loud" ]]; then
            VERBOSE="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-rt" ]]; then
            RUN_TEST="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-rgt" ]]; then
            RUN_GTESTS="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-psn" ]]; then
            POLICY_STORE_NAME="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-tpm_device" ]]; then
            TPM_DEVICE="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-ss" ]]; then
            SEAL_STORE="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-qs" ]]; then
            QUOTE_STORE="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-cc_flag" ]]; then
            TPM_CERT_CHAIN_FILE="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-cr_flag" ]]; then
            TPM_ROOTS_FILE="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-crf" ]]; then
            CURRENT_TPM_ROOT_FILE="${array[i+1]}"
    fi
    if [[ ${array[i]} = "-cif" ]]; then
            CURRENT_TPM_ISSUER_FILE="${array[i+1]}"
    fi
  done
}

# ----------------------------------------------------------------------------------


