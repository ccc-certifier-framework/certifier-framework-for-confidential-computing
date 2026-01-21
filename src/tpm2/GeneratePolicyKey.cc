#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

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
// File: GeneratePolicyKey.cc


// This program creates public/private key pair and produces a file containing
// a protobuf consisting of the keypair.  It is usually the root of a Cloudproxy
// policy domain.

// Calling sequence
//   GeneratePolicyKey.exe --algorithm="RSA" --modulus_size_in_bits=int32
//      --key_name=input-file --cloudproxy_key_file=output-file 
using std::string;


#define CALLING_SEQUENCE "GeneratePolicyKey.exe --algorithm=\"RSA\" "\
" --exponent=exponent --modulus_size_in_bits=int32" \
"--signing_instructions=input-file --key_name=input-file " \
"--cloudproxy_key_file=output-file\n"

void PrintOptions() {
  printf(CALLING_SEQUENCE);
}

DEFINE_string(algorithm, "RSA", "signing algorithm");
DEFINE_int32(modulus_size_in_bits, 2048, "modulus-size");
DEFINE_int64(exponent, 0x010001ULL, "exponent");
DEFINE_string(signing_instructions, "", "input-file-name");
DEFINE_string(, "", "input-file-name");
DEFINE_string(key_name, "", "key name");
DEFINE_string(cloudproxy_key_file, "", "output-file-name");

#ifndef GFLAGS_NS
#define GFLAGS_NS google
#endif

#define MAXKEY_BUF 8192
#define DEBUG

int main(int an, char** av) {
  int ret_val = 0;
  RSA* rsa_key = nullptr;
  byte der_array_private[MAXKEY_BUF];
  byte* start_private = nullptr;
  byte* next_private = nullptr;
  int len_private;
  private_key_blob_message key_out;
  string output;

  printf("\nGeneratePolicyKey\n\n");

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);

  if (FLAGS_algorithm != "RSA") {
    printf("Only RSA supported\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_signing_instructions == "") {
    printf("No signing instructions\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_key_name == "") {
    printf("No key name\n");
    ret_val = 1;
    goto done;
  }
  if (FLAGS_cloudproxy_key_file == "") {
    printf("No key file\n");
    ret_val = 1;
    goto done;
  }

  rsa_key = RSA_generate_key(FLAGS_modulus_size_in_bits, 
                             FLAGS_exponent, nullptr, nullptr);
  if (rsa_key == nullptr) {
    printf("Can't generate RSA key\n");
    ret_val = 1;
    goto done;
  }
  len_private = i2d_RSAPrivateKey(rsa_key, nullptr);
  start_private = der_array_private;
  next_private = der_array_private;
  i2d_RSAPrivateKey(rsa_key, (byte**)&next_private);

#ifdef DEBUG
  printf("der encoded private key (%d): ", len_private);
  PrintBytes(len_private, start_private);
  printf("\n");
#endif

  key_out.set_key_type("RSA");
  key_out.set_key_name(FLAGS_key_name);
  key_out.set_blob((const char*)start_private, len_private);
  if (!key_out.SerializeToString(&output)) {
    printf("Can't serialize output\n");
    ret_val = 1;
    goto done;
  }
  if (!WriteFileFromBlock(FLAGS_cloudproxy_key_file, output.size(),
                          (byte*)output.data())) {
    printf("Can't write output file\n");
    ret_val = 1;
  }

  // write it as protobuf too
  {
    rsa_private_key_message privateMsg;
    privateMsg.mutable_public_key()->set_bit_modulus_size(FLAGS_modulus_size_in_bits);
    byte exp_big_endian[4] = {0, 1, 0, 1};
    string e_b_e;
    e_b_e.assign((const char*)exp_big_endian, 4);
  
    privateMsg.mutable_public_key()->set_exponent(e_b_e);
    string* n = BN_to_bin(*rsa_key->n);
    string* d = BN_to_bin(*rsa_key->d);
    privateMsg.mutable_public_key()->set_modulus(*n);
    privateMsg.set_d(*d);
    if (rsa_key->p != nullptr) {
      string* p = BN_to_bin(*rsa_key->p);
      privateMsg.set_p(*p);
    }
    if (rsa_key->q != nullptr) {
      string* q = BN_to_bin(*rsa_key->q);
      privateMsg.set_q(*q);
    }
    string proto_out;
    if (!privateMsg.SerializeToString(&proto_out)) {
      printf("Can't serialize proto\n");
      goto done;
    }
    string proto_file_name;
    proto_file_name = FLAGS_cloudproxy_key_file + ".proto";
    if (!WriteFileFromBlock(proto_file_name, proto_out.size(),
                            (byte*)proto_out.data())) {
      printf("Can't write output file\n");
      ret_val = 1;
    }
  }

done:
  return ret_val;
}

