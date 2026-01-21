#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl_helpers.h>

#include <tpm20.h>
#include <tpm2_lib.h>
#include <tpm2.pb.h>
#include <gflags/gflags.h>

//
// Copyright 2015 Google Corporation, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// Portions of this code were derived TPM2.0-TSS published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// Portions of this code were derived tboot published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// Portions of this code were derived from the crypto utility
// published by John Manferdelli under the Apache 2.0 license.
// See github.com/jlmucb/crypto.
// File: CloudProxySignEndorsementKey.cc


// Calling sequence
//   CloudProxySignEndorsementKey.exe --cloudproxy_private_key_file=file-name [IN]
//       --endorsement_info_file=file-name [IN]
//       --signing_instructions_file=file-name [IN]
//       --signed_endorsement_cert=file-name [OUT]

using std::string;

//  This program reads the endorsement_info_file and sogns a certificate
//  for the endorsement key using the cloudproxy_signing_key in accordance with
//  the signing instructions.  signing instructions contains a subset of:
//  duration, purpose, and other information to be included in the 
//  signed certificate.


#define MAX_BUF_SIZE 8192

#define CALLING_SEQUENCE "Calling secquence: CloudProxySignEndorsementKey.exe" \
"--cloudproxy_private_key_file=input-file-name" \
"--endorsement_info_file=file-name  --signing_instructions_file=input-file-name" \
"--signed_endorsement_cert=output-file-name\n"

void PrintOptions() {
  printf(CALLING_SEQUENCE);
}

DEFINE_string(endorsement_info_file, "", "output file");
DEFINE_string(cloudproxy_private_key_file, "", "private key file");
DEFINE_string(signing_instructions_file, "", "signing instructions file");
DEFINE_string(signed_endorsement_cert, "", "signed endorsement cert file");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif

#define DEBUG

int main(int an, char** av) {
  int ret_val = 0;

  printf("\nCloudProxySignEndorsementKey\n\n");

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  
  if (FLAGS_signing_instructions_file == "") {
    printf("signing_instructions_file is empty\n");
    return 1;
  }
  if (FLAGS_endorsement_info_file == "") {
    printf("endorsement_info_file is empty\n");
    return 1;
  }
  if (FLAGS_cloudproxy_private_key_file == "") {
    printf("cloudproxy_private_key_file is empty\n");
    return 1;
  }
  if (FLAGS_signed_endorsement_cert == "") {
    printf("signed_endorsement_cert is empty\n");
    return 1;
  }

  int in_size = MAX_BUF_SIZE;
  byte in_buf[MAX_BUF_SIZE];

  string input;
  signing_instructions_message signing_message;
  if (!ReadFileIntoBlock(FLAGS_signing_instructions_file, &in_size, 
                         in_buf)) {
    printf("Can't read signing instructions %s\n",
           FLAGS_signing_instructions_file.c_str());
    return 1;
  }
  input.assign((const char*)in_buf, in_size);
  if (!signing_message.ParseFromString(input)) {
    printf("Can't parse signing instructions\n");
    return 1;
  }
#ifdef DEBUG
  printf("issuer: %s, duration: %ld, purpose: %s, hash: %s\n",
         signing_message.issuer().c_str(), (long)signing_message.duration(),
         signing_message.purpose().c_str(), signing_message.hash_alg().c_str());
#endif
  
  if (!signing_message.can_sign()) {
    printf("Signing is invalid\n");
    return 1;
  }

  in_size = MAX_BUF_SIZE;
  endorsement_key_message endorsement_info;
  if (!ReadFileIntoBlock(FLAGS_endorsement_info_file, &in_size, in_buf)) {
    printf("Can't read endorsement info\n");
    return 1;
  }
  input.assign((const char*)in_buf, in_size);
  if (!endorsement_info.ParseFromString(input)) {
    printf("Can't parse endorsement info\n");
    return 1;
  }

  in_size = MAX_BUF_SIZE;
  private_key_blob_message private_key;
  if (!ReadFileIntoBlock(FLAGS_cloudproxy_private_key_file, &in_size, 
                         in_buf)) {
    printf("Can't read private key\n");
    printf("    %s\n", FLAGS_cloudproxy_private_key_file.c_str());
    return 1;
  }
  input.assign((const char*)in_buf, in_size);
  if (!private_key.ParseFromString(input)) {
    printf("Can't parse private key\n");
    return 1;
  }

#ifdef DEBUG
  printf("\nPolicy key type: %s\n", private_key.key_type().c_str());
  printf("Policy key name: %s\n\n", private_key.key_name().c_str());
#endif

  string the_blob = private_key.blob();
  PrintBytes(the_blob.size(), (byte*)the_blob.data());
  const byte* p = (byte*)the_blob.data();
  RSA* signing_key = d2i_RSAPrivateKey(nullptr, &p, the_blob.size());
  if (signing_key == nullptr) {
    printf("Can't translate private key\n");
    return 1;
  }
#ifdef DEBUG
  print_internal_private_key(*signing_key);
#endif

  string key_blob = endorsement_info.tpm2b_blob();
  uint16_t size_in;
  ChangeEndian16((uint16_t*)key_blob.data(), (uint16_t*)&size_in);
  TPM2B_PUBLIC outPublic;
  if (!GetReadPublicOut(size_in, (byte*)(key_blob.data() + sizeof(uint16_t)),
                        &outPublic)) {
    printf("Can't parse endorsement blob\n");
    return 1;
  }

#ifdef DEBUG
  printf("\nEndorsement key size: %d\n",
         (int)outPublic.publicArea.unique.rsa.size * 8);
  printf("Endorsement key modulus: ");
  PrintBytes((int)outPublic.publicArea.unique.rsa.size,
             outPublic.publicArea.unique.rsa.buffer);
  printf("\n\n");
#endif

  // fill x509_cert_request_parameters_message
  x509_cert_request_parameters_message req_message;
  req_message.set_common_name(endorsement_info.machine_identifier());
  // country_name state_name locality_name organization_name
  //      suborganization_name
  req_message.mutable_key()->set_key_type("RSA");
  req_message.mutable_key()->mutable_rsa_key()->set_bit_modulus_size(
      (int)outPublic.publicArea.unique.rsa.size * 8);
  uint64_t expIn = (uint64_t)
      outPublic.publicArea.parameters.rsaDetail.exponent;
  uint64_t expOut;
  ChangeEndian64((uint64_t*)&expIn, (uint64_t*)(&expOut));

  req_message.mutable_key()->mutable_rsa_key()->set_exponent(
      (const char*)&expOut, sizeof(uint64_t));
  req_message.mutable_key()->mutable_rsa_key()->set_modulus(
      (const char*)outPublic.publicArea.unique.rsa.buffer,
      (int)outPublic.publicArea.unique.rsa.size);

#ifdef DEBUG
  printf("\nCert request:\n");
  print_cert_request_message(req_message); printf("\n");
#endif

  EVP_PKEY* subject_key = EVP_PKEY_new();
  RSA* rsa_subject_key = RSA_new();
  rsa_subject_key->n = bin_to_BN((int)outPublic.publicArea.unique.rsa.size,
                                 outPublic.publicArea.unique.rsa.buffer);
  rsa_subject_key->e = bin_to_BN(sizeof(uint64_t), (byte*)&expOut);
  EVP_PKEY_assign_RSA(subject_key, rsa_subject_key);

  X509_REQ* req = X509_REQ_new();
  X509_REQ_set_version(req, 2);
  if (!GenerateX509CertificateRequest(req_message, false, req)) {
    printf("Can't generate x509 request\n");
    return 1;
  }

  // sign it
  X509* cert = X509_new();
  X509_set_pubkey(cert, subject_key);
  // X509_set_issuer_name(cert, issuerSubject)
  if (!SignX509Certificate(signing_key, false, signing_message, subject_key,
                           req, false, cert)) {
    printf("Can't sign x509 request\n");
    return 1;
  }

#ifdef DEBUG
  printf("message signed\n");
#endif

  byte* out = nullptr;
  int size = i2d_X509(cert, &out);
  string output;
  output.assign((const char*)out, size);
  if (!WriteFileFromBlock(FLAGS_signed_endorsement_cert,
                          output.size(),
                          (byte*)output.data())) {
    printf("Can't write endorsement cert\n");
    return 1;
  }
  return ret_val;
}

