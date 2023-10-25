#!/bin/bash
# #############################################################################
# Simple shell script to generate PEM-certificates and private-key files
# using the 'openssl' utility. These files are needed by the
# test_client_server_mtls.py test, which simulates a client-server SSL
# channel with mutual TLS authentication.
# #############################################################################

set -Eeuo pipefail

# Setup script globals, to establish curdir and root path to Certifier code base
Me=$(basename "$0")

# Establish directory locations
pushd "$(dirname "$0")" > /dev/null 2>&1

# shellcheck disable=SC2046
CERT_ROOT="$(dirname $(pwd))"

popd > /dev/null 2>&1

TEST_DATA=${CERT_ROOT}/tests/pytests/data

pushd "${TEST_DATA}" > /dev/null 2>&1

# ----------------------------------------------------------------------------
# NOTE: The -subj "/C=US/ST=CA/CN=test" clause ends up creating a certificate
#       with only few fields (countryName, stateOrProvinceName, commonName) populated.
#
# This is why in the pytest we have the following to denote the 'CN=test'
# fragment specifying the commonName: COMMON_NAME_FIELD = 2

# Parametrize based on openssl version to use -nodes or -noenc
# In more current OpenSSL v3.0 and later, use -noenc.
# If your OpenSSL installation is older, change this to -nodes
pvt_key_encr_arg="-noenc"
set +e
open_ssl_ver_is_1x=$(openssl version | grep -c "OpenSSL 1\.")
set -e
if [ "${open_ssl_ver_is_1x}" -eq 1 ]; then
    pvt_key_encr_arg="-nodes"
fi

echo "${Me}: Generating self-signed server public certificate and private-key ..."
openssl req -batch -new -x509 -days 365 ${pvt_key_encr_arg} \
            -out server.public-cert.pem \
            -keyout server-private.key \
            --addext 'subjectAltName=IP:127.0.0.1' \
            -subj "/C=US/ST=CA/CN=test"

echo "${Me}: Generating self-signed client public certificate and private-key ..."
openssl req -batch -new -x509 -days 365 ${pvt_key_encr_arg} \
            -out client.public-cert.pem \
            -keyout client-private.key \
            --addext 'subjectAltName=IP:127.0.0.1' \
            -subj "/C=US/ST=CA/CN=test"

# ----------------------------------------------------------------------------
# Steps to generate root certificate and then generate server / client certs
# signed by this root certificate.
#
# Steps developed based on workflow documented in:
# Ref: https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309
#
# NOTE(s):
#   - Root Key is the Certifier Policy Key

ROOT_CA_KEY="rootCA.key.pem"    # Root Certificate's key
ROOT_CA_CERT="rootCA.cert"      # Root Certificate file

# These are another pair of root-certs, which are used to verify through
# tests that certificate verification will fail if we use the wrong-root cert.
WRONG_ROOT_CA_KEY="wrong-rootCA.key.pem"    # Root Certificate's key
WRONG_ROOT_CA_CERT="wrong-rootCA.cert"      # Root Certificate file

# Symbols to define client / server key, CSRs and certificates
SERVER_DOMAIN="server-mydomain.com"
SERVER_KEY="${SERVER_DOMAIN}.key"
SERVER_CSR="${SERVER_DOMAIN}.csr"
SERVER_CERT="${SERVER_DOMAIN}.cert"

CLIENT_DOMAIN="client-mydomain.com"
CLIENT_KEY="${CLIENT_DOMAIN}.key"
CLIENT_CSR="${CLIENT_DOMAIN}.csr"
CLIENT_CERT="${CLIENT_DOMAIN}.cert"

# ---------------------
echo " "
echo "${Me}: Generate Root Certificate Authority key and certificates ..."
echo " "
# Create Root Key:
openssl genpkey -algorithm RSA -outform PEM -out ${ROOT_CA_KEY}

# Create and self sign the Root Certificate:
openssl req -x509 -new ${pvt_key_encr_arg} \
            -key ${ROOT_CA_KEY} -sha256 -days 1024 \
            -subj "/C=US/ST=CA/CN=test" \
            -out ${ROOT_CA_CERT}

# Create [wrong] Root Key:
openssl genpkey -algorithm RSA -outform PEM -out ${WRONG_ROOT_CA_KEY}

# Create and self sign the Root Certificate:
openssl req -x509 -new ${pvt_key_encr_arg} \
            -key ${WRONG_ROOT_CA_KEY} -sha256 -days 1024 \
            --addext 'subjectAltName=IP:128.0.0.2' \
            -subj "/C=US/ST=CA/CN=test" \
            -out ${WRONG_ROOT_CA_CERT}

# ---------------------
echo " "
echo "${Me}: Generate Server's key and certificates, signed by root certificate ..."
echo " "
# Create a certificate (Done for each server): Create the server's Certificate key:
openssl genrsa -out ${SERVER_KEY} 2048

# Create the Certificate Signing Request (csr) from the above server's certificate key:
openssl req -new -sha256 -key ${SERVER_KEY} \
            -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=${SERVER_DOMAIN}" \
            -out ${SERVER_CSR}

# Examine the server CSR's contents:
openssl req -in ${SERVER_CSR} -noout -text

# Generate the server's certificate using the mydomain csr and key along with the CA Root key & cert:
# Client verifies the hostname of the server matches the hostname of the server's cert
# If they don't match, connection handling falls-back to verifying the host IP-address
# to which the client is connecting. (This is 'HOST' variable in the test case.)
# Therefore, we need to poke-in the server's host IP-address in the generated cert.
# (Note: The --addext 'subjectAltName=IP:127.0.0.1' syntax does not work here
#        for the 'x509 -req' command. So use the more convoluted syntax.)
#
openssl x509 -req -extfile <(printf "subjectAltName=IP:127.0.0.1") \
             -in ${SERVER_CSR} \
             -CA ${ROOT_CA_CERT} -CAkey ${ROOT_CA_KEY} -CAcreateserial \
             -days 500 \
             -out ${SERVER_CERT}

# Examine the server certificate's contents:
openssl x509 -in ${SERVER_CERT} -text -noout

# Verify server's certificate v/s root certificate. This should succeed ...
# Ref: https://shagihan.medium.com/what-is-certificate-chain-and-how-to-verify-them-be429a030887
echo " "
echo "${Me}: Verify server-certificate v/s CA root certificate. Expected to pass ..."
openssl verify -CAfile ${ROOT_CA_CERT} ${SERVER_CERT}

# This one will certainly fail, so it's run by toggling the -e switch
echo " "
echo "${Me}: Verify server-certificate v/s wrong-CA root certificate. Expected to fail ..."
echo " "
set +e
openssl verify -CAfile ${WRONG_ROOT_CA_CERT} ${SERVER_CERT}
set -e

# ---------------------
echo " "
echo "${Me}: Generate Client's key and certificates, signed by root certificate ..."
echo " "
# Create a certificate (Done for each client): Create the client's Certificate key:
openssl genrsa -out ${CLIENT_KEY} 2048

# Create the Certificate Signing Request (csr) from the above client's certificate key:
openssl req -new -sha256 -key ${CLIENT_KEY} \
            -subj "/C=US/ST=CA/O=MyOrg, Inc./CN=${CLIENT_DOMAIN}" \
            -out ${CLIENT_CSR}

# Verify the client CSR's contents:
openssl req -in ${CLIENT_CSR} -noout -text

# Generate the client's certificate using the mydomain csr and key along with the CA Root key & cert:
openssl x509 -req -in ${CLIENT_CSR} \
             -CA ${ROOT_CA_CERT} -CAkey ${ROOT_CA_KEY} -CAcreateserial -days 500 \
             -out ${CLIENT_CERT}

# Verify the client certificate's contents:
openssl x509 -in ${CLIENT_CERT} -text -noout

popd > /dev/null 2>&1
