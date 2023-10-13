//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights
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

#include <gflags/gflags.h>
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
// "generate-policy-key-and-test-keys" is the other option
DEFINE_string(operation, "", "generate policy key and self-signed cert");

DEFINE_string(policy_key_name, "policyKey", "key name");
DEFINE_string(policy_key_type, Enc_method_rsa_2048_private, "policy key type");
DEFINE_string(policy_authority_name,
              "policyAuthority",
              "policy authority name");
DEFINE_string(policy_key_output_file, "policy_key_file.bin", "policy key file");
DEFINE_string(policy_cert_output_file,
              "policy_cert_file.bin",
              "policy cert file");

bool generate_test_keys() {
  key_message platform_key;
  key_message attest_key;

  int n = 2048;
  if (FLAGS_platform_key_type == Enc_method_rsa_2048_private)
    n = 2048;
  else if (FLAGS_platform_key_type == Enc_method_rsa_1024_private)
    n = 1024;
  if (!make_certifier_rsa_key(n, &platform_key)) {
    return false;
  }
  platform_key.set_key_name(FLAGS_platform_key_name);
  platform_key.set_key_type(FLAGS_platform_key_type);
  string serialized_platform_key;
  if (!platform_key.SerializeToString(&serialized_platform_key))
    return false;
  if (!write_file(FLAGS_platform_key_output_file,
                  serialized_platform_key.size(),
                  (byte *)serialized_platform_key.data()))
    return false;

  n = 2048;
  if (FLAGS_attest_key_type == Enc_method_rsa_2048_private)
    n = 2048;
  else if (FLAGS_attest_key_type == Enc_method_rsa_1024_private)
    n = 1024;
  if (!make_certifier_rsa_key(n, &attest_key)) {
    return false;
  }
  attest_key.set_key_name(FLAGS_attest_key_name);
  attest_key.set_key_type(FLAGS_attest_key_type);
  string serialized_attest_key;
  if (!attest_key.SerializeToString(&serialized_attest_key))
    return false;
  if (!write_file(FLAGS_attest_key_output_file,
                  serialized_attest_key.size(),
                  (byte *)serialized_attest_key.data()))
    return false;

  printf("\nGenerated platform key:\n");
  print_key(platform_key);
  printf("\n");

  printf("\nGenerated attest key:\n");
  print_key(attest_key);
  printf("\n");

  return true;
}

bool generate_policy_key() {
  key_message policy_key;
  key_message policy_pk;  // public policy key

  if (!make_root_key_with_cert(FLAGS_policy_key_type,
                               FLAGS_policy_key_name,
                               FLAGS_policy_authority_name,
                               &policy_key))
    return false;
  if (!private_key_to_public_key(policy_key, &policy_pk))
    return false;

  string serialized_key;
  if (!policy_key.SerializeToString(&serialized_key))
    return false;
  if (!write_file(FLAGS_policy_key_output_file,
                  serialized_key.size(),
                  (byte *)serialized_key.data()))
    return false;
  if (!write_file(FLAGS_policy_cert_output_file,
                  policy_key.certificate().size(),
                  (byte *)policy_key.certificate().data()))
    return false;

  printf("\nGenerated policy key:\n");
  print_key(policy_key);
  printf("\n");
  return true;
}

bool generate_key(const string &type, const string &name, key_message *k) {

  if (type == Enc_method_rsa_1024) {
    RSA *r = RSA_new();
    if (!generate_new_rsa_key(1024, r)) {
      printf("Can't generate rsa key\n");
      return false;
    }
    if (!RSA_to_key(r, k)) {
      printf("Can't convert rsa key to key\n");
      return false;
    }
    k->set_key_type(Enc_method_rsa_1024_private);
  } else if (type == Enc_method_rsa_2048) {
    RSA *r = RSA_new();
    if (!generate_new_rsa_key(2048, r)) {
      printf("Can't generate rsa key\n");
      return false;
    }
    if (!RSA_to_key(r, k)) {
      printf("Can't convert rsa key to key\n");
      return false;
    }
    k->set_key_type(Enc_method_rsa_2048_private);
  } else if (type == Enc_method_rsa_3072) {
    RSA *r = RSA_new();
    if (!generate_new_rsa_key(3072, r)) {
      printf("Can't generate rsa key\n");
      return false;
    }
    if (!RSA_to_key(r, k)) {
      printf("Can't convert rsa key to key\n");
      return false;
    }
    k->set_key_type(Enc_method_rsa_3072_private);
  } else if (type == Enc_method_rsa_4096) {
    RSA *r = RSA_new();
    if (!generate_new_rsa_key(4096, r)) {
      printf("Can't generate rsa key\n");
      return false;
    }
    if (!RSA_to_key(r, k)) {
      printf("Can't convert rsa key to key\n");
      return false;
    }
    k->set_key_type(Enc_method_rsa_4096_private);
  } else if (type == Enc_method_ecc_384) {
    EC_KEY *ec = generate_new_ecc_key(384);
    if (ec == nullptr) {
      printf("Can't generate ecc key\n");
      return false;
    }
    if (!ECC_to_key(ec, k)) {
      printf("Can't convert ecc key to key\n");
      return false;
    }
    k->set_key_type(Enc_method_ecc_384_private);
  } else {
    printf("Unknown key type\n");
    return false;
  }

  k->set_key_name(name);
  k->set_key_format("vse-key");
  string str;
  if (!k->SerializeToString(&str)) {
    printf("Can't serialize key\n");
    return false;
  }
  if (!write_file(FLAGS_key_output_file, str.size(), (byte *)str.data())) {
    printf("Can't write file\n");
    return false;
  }
  print_key(*k);
  printf("\n");

  return true;
}


int main(int an, char **av) {
  string usage("Utility to generate cert chains");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);

  if (FLAGS_operation == "") {
    printf("%s: %s\n", av[0], usage.c_str());
    printf("\n%s --operation=<generate print> "
           "--num_intermediate=nn "
           "--output_file=<file.bin> "
           "--key_type=<rsa-4096 rsa-2048 ecc-256 ecc-384\n",
           av[0]);

    return 0;
  } else if (FLAGS_operation == "test-sig") {
    test_sig();
  } else if (FLAGS_operation == "generate-policy-key"
             || FLAGS_operation == "generate-policy-key-and-test-keys") {
    printf("Generating policy key and cert\n");
    if (!generate_policy_key()) {
      printf("Generate keys failed\n");
      return 1;
    }

    if (FLAGS_operation == "generate-policy-key-and-test-keys") {
      printf("Generating test keys\n");
      if (!generate_test_keys()) {
        printf("Generate test keys failed\n");
        return 1;
      }
    }
  } else if ("generate-key") {
    key_message k;
    if (!generate_key(FLAGS_key_type, FLAGS_key_name, &k)) {
      printf("generate key failed\n");
      return 1;
    }
  } else {
    printf("Unknown operation\n");
    return 1;
  }

  return 0;
}
