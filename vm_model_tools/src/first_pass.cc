//  Copyright (c) 2026, John L Manferdelli.  All rights
//  reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "certifier.h"
#include "support.h"
#include "simulated_enclave.h"
#include "tpm2_support.h"
#include "cc_helpers.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>


using namespace certifier::framework;
using namespace certifier::utilities;

#define DEBUG

// -----------------------------------------------------------------------

// This is the real first pass that uses activate-credential
// The sequence is:
//    1. Client constructs a "quote_certification_request" to a
//       new port.
//    2. Server checks to seed if initial cert in cert chain offered
//       is trusted
//    3. If so, the server validates the cert chain and endorsement
//       cert.
//    4. If the checks pass, the server produces a quote certificate
//       and serializes it.
//    5. The server generates a random symmetric key and encrypts the
//       quote key certificate.
//    6. The sever calls make-credential with the symmetric key as the
//       "credential".
//    7. server returns the quote_certification_response containing the
//       encrypted certificate, credBlob and encrypted secret.
//    8. Client calls "activate credential" to get the random key.
//    9. Client decrypts the cert and saves it.
bool first_pass(const string &tpm_device,
                const string &endorsement_cert_file_name,
                const string &endorsement_cert_chain_file_name,
                const string &seal_hierarchy_file_name,
                const string &quote_hierarchy_file_name,
                int           num_pcrs,
                byte         *pcrs,
                const string &activate_service_host,
                const string &activate_service_port,
                const string &quote_cert_file_name,
                string       *cert_obtained) {

#ifdef DEBUG
  printf("\nfirst-pass (with activate)\n");
#endif
#ifdef DEBUG2
  printf("    tpm device             : %s\n", tpm_device.c_str());
  printf("    endorsement file       : %s\n",
         endorsement_cert_file_name.c_str());
  printf("    cert chain  file       : %s\n",
         endorsement_cert_chain_file_name.c_str());
  printf("    seal hierarchy file    : %s\n", seal_hierarchy_file_name.c_str());
  printf("    quote hierarchy file   : %s\n",
         quote_hierarchy_file_name.c_str());
  printf("    quote_cert  file       : %s\n", quote_cert_file_name.c_str());
#endif

  if (!init_tpm(tpm_device)) {
    printf("%s() error, line %d, tpm_init failed\n", __func__, __LINE__);
    return false;
  }

  extern local_tpm g_tpm;

  printf("PCR's at first pass:\n");
  print_pcrs(g_tpm, num_pcrs, pcrs);

  extern string       g_serialized_quote_cert;
  extern string       g_serialized_endorsement_cert;
  extern string       g_serialized_endorsement_cert_chain;
  extern string       g_seal_hierarchy_file_name;
  extern string       g_quote_hierarchy_file_name;
  extern string       g_seal_thing;
  extern TPM2B_PUBLIC g_public_quote_key;
  extern TPM2B_PUBLIC g_public_endorsement_key;

  quote_certification_request  request;
  quote_certification_response response;

  // Init
  if (!tpm_Init(tpm_device,
                endorsement_cert_file_name,
                endorsement_cert_chain_file_name,
                seal_hierarchy_file_name,
                quote_hierarchy_file_name,
                num_pcrs,
                pcrs)) {
    printf("%s() error, line %d, can't tpm_Init\n", __func__, __LINE__);
    return false;
  }

  // get quote key
  // Construct quote key_message.  Pack the above along with the
  // quote key hashing alg and quote_key_name into the
  // request and send it to the server after serialization.
  // Server returns a response.  If successful, perform the
  // actions above.

  // make quote key message
  key_message         quote_key;
  extern TPM2B_PUBLIC g_public_quote_key;
  string              name("quote-key");
  if (!tpm_public_key_to_key(g_public_quote_key, name, &quote_key)) {
    printf("%s(), error, line: %d, can't translate quote key\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  extern string g_public_quote_key_name;
  string        serialized_quote_key_name;
  string        serialized_request;
  string        quote_hash_alg("sha256");
  if (!construct_activate_request(g_serialized_endorsement_cert,
                                  g_serialized_endorsement_cert_chain,
                                  quote_key,
                                  g_public_quote_key_name,
                                  quote_hash_alg,
                                  &serialized_request)) {
    printf("%s(), error, line: %d, can't construct request\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  // Open socket and send request.
  int sock = -1;
  int port = atoi(activate_service_port.c_str());
  if (!open_client_socket(activate_service_host, port, &sock)) {
    printf("%s() error, line: %d, Can't open request socket\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  // Send request to activate service
  int sized_write_len = sized_socket_write(sock,
                                           serialized_request.size(),
                                           (byte *)serialized_request.data());
  if (sized_write_len < (int)serialized_request.size()) {
    printf("%s() error, line: %d sized_socket_write() len=%d is "
           "< requested size, %d\n",
           __func__,
           __LINE__,
           sized_write_len,
           (int)serialized_request.size());
    tpm_close();
    return false;
  }

  // Read response from Activate Service.
  string serialized_response;
  int    resp_size = sized_socket_read(sock, &serialized_response);
  if (resp_size < 0) {
    printf("%s() error, line: %d, Can't read response\n", __func__, __LINE__);
    return false;
  }
  close(sock);

  extern local_tpm g_tpm;
  bool             ret =
      process_activate_response(g_tpm, serialized_response, cert_obtained);

  if (!ret) {
    printf("%s(), error, line: %d, can't process_activate_response\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  if (!write_file_from_string(quote_cert_file_name, *cert_obtained)) {
    printf("%s(), error, line: %d, couldn't write file\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

#ifdef DEBUG2
  extern bool g_tpm_initialized;
  extern bool g_tpm_environment_initialized;

  printf("process_activate_response succeeded, quote cert written\n");
  if (g_tpm_initialized) {
    printf("tpm initialized\n");
  } else {
    printf("tpm not initialized\n");
  }
  if (g_tpm_environment_initialized) {
    printf("tpm environment initialized\n");
  } else {
    printf("tpm environment not initialized\n");
  }
#endif

  // Don't really need to do all this
  attestation_user_data ud;
  ud.set_enclave_type("tpm-enclave");
  RSA *auth_r = RSA_new();
  if (!generate_new_rsa_key(2048, auth_r)) {
    printf("%s, %d, generate_new_rsa_key error\n", __func__, __LINE__);
    tpm_close();
    return false;
  }
  key_message private_auth_key;
  key_message public_auth_key;
  if (!RSA_to_key(auth_r, &private_auth_key)) {
    printf("%s, %d, RSA_to_key error\n", __func__, __LINE__);
    tpm_close();
    return false;
  }
  private_auth_key.set_key_name("enclave-key");
  if (!private_key_to_public_key(private_auth_key, &public_auth_key)) {
    printf("%s, %d, private_key_to_public_key error\n", __func__, __LINE__);
    return false;
  }
  RSA_free(auth_r);

  // time
  time_point t;
  time_now(&t);
  string str_now;
  time_to_string(t, &str_now);
  ud.set_time(str_now);

  // key
  ud.mutable_enclave_key()->CopyFrom(public_auth_key);

  int    size_out = 4096;
  byte   out[size_out];
  string serialized_user;
  if (!ud.SerializeToString(&serialized_user)) {
    printf("%s, %d, SerializeToString error\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  if (!Attest(ud.enclave_type(),
              serialized_user.size(),
              (byte *)serialized_user.data(),
              &size_out,
              out)) {
    printf("%s, %d Attest failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  string serialized_tpm_msg;
  serialized_tpm_msg.assign((char *)out, size_out);

  tpm_attestation_message att;
  if (!att.ParseFromString(serialized_tpm_msg)) {
    printf("%s, %d, can't parse attestation\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  // extract measurement
  string             extra_data;
  uint32_t           magic;
  uint16_t           type;
  string             signer;
  TPML_PCR_SELECTION pcrSelect;
  string             pcr_digest;
  int                new_num_pcrs = 10;
  byte_t             new_pcrs[num_pcrs];

  if (!decode_quoted((int)att.the_quote().size(),
                     (byte_t *)att.the_quote().data(),
                     &magic,
                     &type,
                     &signer,
                     &extra_data,
                     &pcrSelect,
                     &pcr_digest)) {
    printf("%s, %d, decode_quoted failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  if (!get_pcr_from_select(&pcrSelect, &new_num_pcrs, new_pcrs)) {
    printf("%s, %d, get_pcr_from_select failed\n", __func__, __LINE__);
    tpm_close();
    return false;
  }

  string conf;
  conf.assign((char *)new_pcrs, new_num_pcrs);

#ifdef DEBUG3
  printf("PCR's after attest\n");
  for (int i = 0; i < new_num_pcrs; i++)
    printf("%d ", new_pcrs[i]);
  printf("\n");
  print_pcrs(g_tpm, new_num_pcrs, new_pcrs);
  printf("\n");
#endif
#ifdef DEBUG
  printf("Measurement digest: ");
  print_bytes(pcr_digest.size(), (byte_t *)pcr_digest.data());
  printf("\n");
#endif

  string measurement_file_name("measurement");
  if (!write_file_from_string(measurement_file_name, pcr_digest)) {
    printf("%s(), error, line: %d, can't write measurement\n",
           __func__,
           __LINE__);
    tpm_close();
    return false;
  }

  tpm_close();
  return true;
}

// -----------------------------------------------------------------------
