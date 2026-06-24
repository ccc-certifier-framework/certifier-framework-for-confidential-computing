
# ------------------------------------------------------------------------------------------

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
	EXAMPLE_DIR=$(pwd) > /dev/null
fi

#echo ""
#echo "Starting"

# Variables to find
#	Variable NAME				Flag		Values
#	POLICY_KEY_FILE_NAME			-pkn		name
#	POLICY_CERT_FILE_NAME			-cfn		name
#	POLICY_STORE_NAME			-psn		name
#	CRYPTSTORE_NAME				-csn		name
#	DOMAIN_NAME				-dn		name
#	SYMMETRIC_ENCRYPTION_ALGORITHM		-sea		alg name (see certifier)
#	ASYMMETRIC_ENCRYPTION_ALGORITHM		-aen		alg name (see certifier)
#	PROGRAM_NAME				-pn		name
#	VM_NAME					-vmn		name
#	TEST_TYPE				-tt		simulated/real
#	BUILD_SEV_SIMULATOR			-bss		1 or 0
#	COMPILE_CF				-ccf		1 or 0
#	POLICY_FILE_NAME			-pfn		name
#	POLICY_SERVER_ADDRESS			-psa		ip address or localhost
#	POLICY_SERVER_PORT   			-psp		port number
#	KEY_SERVER_ADDRESS			-ksa		ip address or localhost
#	KEY_SERVER_PORT   			-ksp		port number
#	OPERATION         			-op 		name
#	CLEAN             			-clean 		0/1
#	VERBOSE           			-loud 		0/1
#	DEPLOYMENT_ENCLAVE_TYPE			-et1		enclave types
#       DEPLOYED_ENCLAVE_TYPE			-et2		enclave types
#	DEPLOYMENT_POLICY_STORE_NAME		-psn1		deployment policy file name
#	DEPLOYED_POLICY_STORE_NAME		-psn2		deployed policy store name
#	DEPLOYMENT_CRYPTSTORE_NAME		-csn1		deployment cryptstore name
#	DEPLOYED_CRYPTSTORE_NAME		-csn2		deployed cryptstore name

function print-options() {

	echo "Defined flags and variables"
	echo ""
	echo "Variable name			Flag		Value"
	echo "-------------------------------------------------------"
	echo "COMPILE_CF			-ccf		1 or 0"
	echo "PROVISION_KEYS                    -pk             1 or 0"
	echo "BUILD_SEV_SIMULATOR  		-bss		1 or 0"
	echo "POLICY_KEY_FILE_NAME		-pkn		name"
	echo "POLICY_CERT_FILE_NAME		-cfn		name"
	echo "POLICY_STORE_NAME		-psn		name"
	echo "CRYPTSTORE_NAME			-csn		name"
	echo "DOMAIN_NAME			-dn		name"
	echo "SYMMETRIC_ENCRYPTION_ALGORITHM	-sea		alg name (see certifier)"
	echo "ASYMMETRIC_ENCRYPTION_ALGORITHM	-aen		alg name (see certifier)"
	echo "PROGRAM_NAME			-pn		name"
	echo "VM_NAME				-vmn		name"
	echo "TEST_TYPE			-tt		simulated/real"
	echo "POLICY_FILE_NAME		-pfn		name"
	echo "POLICY_SERVER_ADDRESS		-psa		ip address or localhost"
	echo "POLICY_SERVER_PORT   		-psp		port number"
	echo "KEY_SERVER_ADDRESS		-ksa		ip address or localhost"
	echo "KEY_SERVER_PORT   		-ksp		port number"
	echo "OPERATION     	   		-op 		operation"
	echo "CLEAN             		-clean		0/1"
        echo "DEPLOYMENT_ENCLAVE_TYPE		-et1		enclave types"
        echo "DEPLOYED_ENCLAVE_TYPE		-et2		enclave types"
	echo "DEPLOYMENT_POLICY_STORE_NAME	-psn1		deployment policy file name"
	echo "DEPLOYED_POLICY_STORE_NAME	-psn2		deployed policy store name"
	echo "DEPLOYMENT_CRYPTSTORE_NAME	-csn1		deployment cryptstore name"
	echo "DEPLOYED_CRYPTSTORE_NAME		-csn2		deployed cryptstore name"
	echo "DEPLOYMENT_DATA_DIR		-dd1		directory"
	echo "DEPLOYED_DATA_DIR		-dd1		directory"
	echo "-------------------------------------------------------"
	echo ""
}

# Defaults

DOMAIN_NAME="datica"
POLICY_KEY_FILE_NAME="policy_key_file"
POLICY_CERT_FILE_NAME="policy_cert_file"
POLICY_STORE_NAME="policy_store"
CRYPTSTORE_NAME="cryptstore"
PROGRAM_NAME="datica-program"
SYMMETRIC_ENCRYPTION_ALGORITHM="aes-256-gcm"
ASYMMETRIC_ENCRYPTION_ALGORITHM="RSA-4096"
VM_NAME="datica-sample-vm"
TEST_TYPE="simulated"
BUILD_SEV_SIMULATOR=0
COMPILE_CF=1
PROVISION_KEYS=1
POLICY_FILE_NAME="policy.bin"
POLICY_SERVER_ADDRESS="localhost"
POLICY_SERVER_PORT="8123"
KEY_SERVER_ADDRESS="localhost"
KEY_SERVER_PORT="8120"
OPERATION=""
CLEAN=0
VERBOSE=1
DEPLOYMENT_ENCLAVE_TYPE="simulated-enclave"
DEPLOYED_ENCLAVE_TYPE="sev-enclave"
DEPLOYMENT_POLICY_STORE_NAME=""
DEPLOYED_POLICY_STORE_NAME=""
DEPLOYMENT_CRYPTSTORE_NAME=""
DEPLOYED_CRYPTSTORE_NAME=""
DEPLOYMENT_DATA_DIR="./deployment/"
DEPLOYED_DATA_DIR="./deployed/"


function print-variables() {
	echo ""
	echo "Shell arguments"
	echo ""
	echo "Certifier root:                        $CERTIFIER_ROOT"
	echo "Example directory:                     $EXAMPLE_DIR"
	echo ""
	echo "Clean:                                 $CLEAN"
	echo "Verbose:                               $VERBOSE"
	echo "Compile Certifier flag:                $COMPILE_CF"
	echo "Build SEV simulator:                   $BUILD_SEV_SIMULATOR"
	echo "Provision keys:                        $PROVISION_KEYS"
	echo "Test type:                             $TEST_TYPE"
	echo "Program name:                          $PROGRAM_NAME"
	echo "VM name:                               $VM_NAME"
	echo "Operation:                             $OPERATION"
	echo ""
	echo "Domain name:                           $DOMAIN_NAME"
	echo "Policy Key file name:                  $POLICY_KEY_FILE_NAME"
	echo "Policy cert file name:                 $POLICY_CERT_FILE_NAME"
	echo "Policy store file name:                $POLICY_STORE_NAME"
	echo "Cryptstore file name:                  $CRYPTSTORE_NAME"
	echo "Deployment data directory name:        $DEPLOYMENT_DATA_DIR"
	echo "Deployed data directory name:          $DEPLOYED_DATA_DIR"
	echo "Data directory name:                   $DATA_DIR"
	echo "Deployment enclave type                $DEPLOYMENT_ENCLAVE_TYPE"
	echo "Deployed enclave type                  $DEPLOYED_ENCLAVE_TYPE"
	echo "Deployment policy store name           $DEPLOYMENT_POLICY_STORE_NAME"
	echo "Deployed policy store directory        $DEPLOYED_POLICY_STORE_NAME"
	echo "Deployment cryptstore name             $DEPLOYMENT_CRYPTSTORE_NAME"
	echo "Deployed cryptstore name               $DEPLOYED_CRYPTSTORE_NAME"
	echo ""
	echo "Policy Server address:                 $POLICY_SERVER_ADDRESS"
	echo "Policy server port:                    $POLICY_SERVER_PORT"
	echo "Key server address:                    $KEY_SERVER_ADDRESS"
	echo "Key server port:                       $KEY_SERVER_PORT"
	echo "Encryption Algorithm:                  $SYMMETRIC_ENCRYPTION_ALGORITHM"
	echo "Public key algorithm:                  $ASYMMETRIC_ENCRYPTION_ALGORITHM"
	echo ""
}


arg_string=$*
function process-args() {

	IFS=' ' read -ra array <<< "$arg_string"
	for (( i=0; i < $ARG_SIZE; i++ )); do
		#echo "Processing arg $i: ${array[i]}"

		if [[ ${array[i]} = "-dn" ]]; then
			DOMAIN_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-pkn" ]]; then
			POLICY_KEY_FILE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-cfn" ]]; then
			POLICY_CERT_FILE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-psn" ]]; then
			POLICY_STORE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-csn" ]]; then
			CRYPTSTORE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-dd1" ]]; then
			DEPLOYMENT_DATA_DIR="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-dd2" ]]; then
			DEPLOYED_DATA_DIR="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-sea" ]]; then
			SYMMETRIC_ENCRYPTION_ALGORITHM="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-aen" ]]; then
			ASYMMETRIC_ENCRYPTION_ALGORITHM="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-pn" ]]; then
			PROGRAM_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-vmn" ]]; then
			VM_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-tt" ]]; then
			TEST_TYPE="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-pk" ]]; then
			PROVISION_KEYS="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-bss" ]]; then
			BUILD_SEV_SIMULATOR="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-ccf" ]]; then
			COMPILE_CF="${array[i+1]}"
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
		if [[ ${array[i]} = "-ksa" ]]; then
			KEY_SERVER_ADDRESS="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-ksp" ]]; then
			KEY_SERVER_PORT="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-op" ]]; then
			OPERATION="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-clean" ]]; then
			CLEAN="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-loud" ]]; then
			VERBOSE="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-et1 " ]]; then
			DEPLOYMENT_ENCLAVE_TYPE="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-et2" ]]; then
			DEPLOYED_ENCLAVE_TYPE="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-psn1" ]]; then
			DEPLOYMENT_POLICY_STORE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-psn2" ]]; then
			DEPLOYED_POLICY_STORE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-csn1" ]]; then
			DEPLOYMENT_CRYPTSTORE_NAME="${array[i+1]}"
		fi
		if [[ ${array[i]} = "-csn2" ]]; then
			DEPLOYED_CRYPTSTORE_NAME="${array[i+1]}"
		fi
	done

	POLICY_CERT_FILE_NAME=$POLICY_CERT_FILE_NAME.$DOMAIN_NAME
	POLICY_STORE_NAME=$POLICY_STORE_NAME.$DOMAIN_NAME
	CRYPTSTORE_NAME=$CRYPTSTORE_NAME.$DOMAIN_NAME
}

# ------------------------------------------------------------------------------------------


