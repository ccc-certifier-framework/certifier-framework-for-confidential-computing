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

// appoint_platform.exe --policy_key=file --cert_file=ark_cert.bin
// --output=output-file-name

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(output, "simple_clause.bin", "output file");
DEFINE_string(policy_key_file, "", "policy key file");
DEFINE_string(cert_file, "", "cert file");

bool get_key_from_file(const string &in, key_message *k) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte serialized_key[in_size];

  if (!read_file(in, &in_read, serialized_key)) {
    printf("Can't read %s\n", in.c_str());
    return false;
  }

  string k_str;
  k_str.assign((char *)serialized_key, in_size);
  if (!k->ParseFromString(k_str)) {
    printf("Can't parse key\n");
    return false;
  }
  return true;
}

bool get_key_from_cert_file(const string &in, key_message *k) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte serialized_cert[in_size];

  if (!read_file(in, &in_read, serialized_cert)) {
    printf("Can't read %s\n", in.c_str());
    return false;
  }
  string str_cert;
  str_cert.assign((char *)serialized_cert, in_read);

  X509 *x = X509_new();
  if (!asn1_to_x509(str_cert, x)) {
    printf("Can't asn1 convert\n");
    return false;
  }
  if (!x509_to_public_key(x, k)) {
    printf("Can't get public key from cert\n");
    return false;
  }
  return true;
}

int main(int an, char **av) {
  gflags::SetUsageMessage("Sample key-mgmt utility: RESOLVE - Fix message");
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  string usage_str("--policy_key=<file> --cert_file=<ark_cert.bin> "
                   "--output=<output-file-name>");
  if (FLAGS_policy_key_file == "") {
    printf("No policy key\n");
    printf("%s %s\n", av[0], usage_str.c_str());
    return 1;
  }

  if (FLAGS_cert_file == "") {
    printf("No cert\n");
    printf("%s: %s\n", av[0], usage_str.c_str());
    return 1;
  }

  entity_message sub_ent;
  entity_message obj_ent;

  key_message policy_key;
  if (!get_key_from_file(FLAGS_policy_key_file, &policy_key)) {
    printf("Can't get policy key\n");
    return 1;
  }
  key_message pub_policy_key;
  if (!private_key_to_public_key(policy_key, &pub_policy_key)) {
    printf("Can't get public policy key\n");
    return 1;
  }
  if (!make_key_entity(policy_key, &sub_ent)) {
    printf("Can't get subject entity\n");
    return 1;
  }

  key_message platform_key;
  if (!get_key_from_cert_file(FLAGS_cert_file, &platform_key)) {
    printf("Can't get platform key\n");
    return 1;
  }

  entity_message plat_ent;
  if (!make_key_entity(platform_key, &plat_ent)) {
    printf("Can't get subject entity\n");
    return 1;
  }

  string     says_str("says");
  string     att_str("is-trusted-for-attestation");
  vse_clause cl1;
  if (!make_unary_vse_clause(plat_ent, att_str, &cl1)) {
    printf("Can't make clause 1\n");
    return 1;
  }

  vse_clause cl2;
  if (!make_indirect_vse_clause(sub_ent, says_str, cl1, &cl2)) {
    printf("Can't make clause 2\n");
    return 1;
  }

  string out_str;
  if (!cl2.SerializeToString(&out_str)) {
    printf("Can't serialize clause\n");
    return 1;
  }

  if (!write_file(FLAGS_output, out_str.size(), (byte *)out_str.data())) {
    printf("Can't write %s\n", FLAGS_output.c_str());
    return 1;
  }

  printf("New statement: ");
  print_vse_clause(cl2);
  printf("\n");

  return 0;
}
