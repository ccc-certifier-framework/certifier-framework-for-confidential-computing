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
// File: SelfSignPolicyCert.cc


// Calling sequence
//   SelfSignPolicyCert.exe --signing_instructions=input-file 
//     --key_file=input-file --policy_identifier=name --cert_file=output-file

using std::string;

// This program signs the policy key using the policy key.
// The policy_identifier identifies the policy domain.

DEFINE_string(signing_instructions_file, "", "signing_instructions");
DEFINE_string(key_file, "", "key_input");
DEFINE_string(policy_identifier, "", "text to identify policy domain");
DEFINE_string(cert_file, "cert_file", "cert output file");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif

#define MAX_BUF_SIZE 8192

void PrintOptions() {
  printf("Calling sequence: SelfSignPolicyCert.exe "\
"--signing_instructions_file=input-file "\
"--key_file=input-file --policy_identifier=name --cert_file=output-file\n");
}

int main(int an, char** av) {
  int ret_val = 0;

  printf("\nSelfSignPolicyCert\n\n");

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);
  if (FLAGS_signing_instructions_file == "") {
    printf("You must specify a signing instructions file \n");
    PrintOptions();
    return 1;
  }
   if (FLAGS_key_file == "") {
    printf("key_file is empty\n");
    return 1;
  }
  if (FLAGS_policy_identifier == "") {
    printf("policy_identifier is empty\n");
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
  printf("issuer: %s, duration: %ld, purpose: %s, hash: %s\n",
         signing_message.issuer().c_str(), (long)signing_message.duration(),
         signing_message.purpose().c_str(), signing_message.hash_alg().c_str());

  if (!signing_message.can_sign()) {
    printf("Signing is invalid\n");
    return 1;
  }
  printf("\nGot signing instructions\n");

  in_size = MAX_BUF_SIZE;
  private_key_blob_message private_key;
  if (!ReadFileIntoBlock(FLAGS_key_file, &in_size, in_buf)) {
    printf("Can't read private key\n");
    return 1;
  }
  input.assign((const char*)in_buf, in_size);
  if (!private_key.ParseFromString(input)) {
    printf("Can't parse private key\n");
    return 1;
  }

  printf("Key type: %s\n", private_key.key_type().c_str());
  printf("Key name: %s\n", private_key.key_name().c_str());
  string the_blob = private_key.blob();
  PrintBytes(the_blob.size(), (byte*)the_blob.data());
  const byte* p = (byte*)the_blob.data();
  RSA* signing_key = d2i_RSAPrivateKey(nullptr, &p, the_blob.size());
  if (signing_key == nullptr) {
    printf("Can't translate private key\n");
    return 1;
  }
  printf("\nGot signing key\n");

  // fill x509_cert_request_parameters_message
  x509_cert_request_parameters_message req_message;
  req_message.set_common_name(FLAGS_policy_identifier);
  req_message.mutable_key()->set_key_type("RSA");
  string* mod = BN_to_bin(*signing_key->n);
  if (mod == nullptr) {
    printf("Can't get private key modulus\n");
    return 1;
  }
  req_message.mutable_key()->mutable_rsa_key()->set_bit_modulus_size(
       BN_num_bits(signing_key->n));
  uint64_t expIn = 0x10001ULL;
  uint64_t expOut;
  ChangeEndian64((uint64_t*)&expIn, (uint64_t*)(&expOut));

  req_message.mutable_key()->mutable_rsa_key()->set_exponent(
      (const char*)&expOut, sizeof(uint64_t));
  req_message.mutable_key()->mutable_rsa_key()->set_modulus(
     mod->data(), mod->size());
  printf("\ncert request\n");
  print_cert_request_message(req_message); printf("\n\n");
  printf("\nGenerating request\n");

  X509_REQ* req = X509_REQ_new();
  X509_REQ_set_version(req, 2);
  // TODO(jlm): sign and verify request later
  if (!GenerateX509CertificateRequest(req_message, false, req)) {
    printf("Can't generate x509 request\n");
    return 1;
  }
  printf("Generated certificate request\n");

  // sign it
  X509* cert = X509_new();
  if (!SignX509Certificate(signing_key, true, signing_message, nullptr,
                           req, false, cert)) {
    printf("Can't sign x509 request\n");
    return 1;
  }
  printf("message signed\n");

  byte* out = nullptr;
  int size = i2d_X509(cert, &out);
  string output;
  output.assign((const char*)out, size);
  if (!WriteFileFromBlock(FLAGS_cert_file, output.size(),
                          (byte*)output.data())) {
    printf("Can't write cert\n");
    return 1;
  }
  return ret_val;
}

