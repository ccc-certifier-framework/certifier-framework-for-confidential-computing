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

// make_signed_claim_from_vse_clause.exe --vse_file=file --duration=hours
// --private_key_file=key=key-file --output=output-file-name

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(vse_file, "vse_claim.bin", "clause file");
DEFINE_string(output, "signed_claim.bin", "output file");
DEFINE_string(private_key_file, "", "signing key");
DEFINE_double(duration, 24, "validity in hours");
DEFINE_string(descipt, "", "descriptor");
DEFINE_string(signing_alg,
              Enc_method_rsa_2048_sha256_pkcs_sign,
              "signing algorithm");

bool get_clause_from_file(const string &in, vse_clause *cl) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte serialized_cl[in_size];

  if (!read_file(in, &in_read, serialized_cl)) {
    printf("Can't read %s\n", in.c_str());
    return false;
  }
  string cl_str;
  cl_str.assign((char *)serialized_cl, in_size);
  if (!cl->ParseFromString(cl_str)) {
    printf("Can't parse clause\n");
    return false;
  }
  return true;
}

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

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  if (FLAGS_private_key_file == "") {
    printf("No signing key\n");
    return 1;
  }

  key_message signing_key;
  if (!get_key_from_file(FLAGS_private_key_file, &signing_key)) {
    printf("can't get signing key\n");
    return 1;
  }

  if (FLAGS_vse_file == "") {
    printf("No clause file\n");
    return 1;
  }

  vse_clause in_cl;
  if (!get_clause_from_file(FLAGS_vse_file, &in_cl)) {
    printf("Can't get indirect clause\n");
    return 1;
  }

  time_point t_not_before;
  string     not_before;
  if (!time_now(&t_not_before)) {
    printf("Can't get current time\n");
    return 1;
  }
  if (!time_to_string(t_not_before, &not_before)) {
    printf("Can't get string current time\n");
    return 1;
  }
  time_point t_not_after;
  string     not_after;
  if (!add_interval_to_time_point(t_not_before, FLAGS_duration, &t_not_after)) {
    printf("Can't get end time\n");
    return 1;
  }
  if (!time_to_string(t_not_after, &not_after)) {
    printf("Can't get string end time\n");
    return 1;
  }

  string serialized_vse_claim;
  if (!in_cl.SerializeToString(&serialized_vse_claim)) {
    printf("Can't serialize vse claim\n");
    return 1;
  }
  string        format("vse-clause");
  string        descriptor = FLAGS_descipt;
  claim_message cm_out;
  if (!make_claim(serialized_vse_claim.size(),
                  (byte *)serialized_vse_claim.data(),
                  format,
                  descriptor,
                  not_before,
                  not_after,
                  &cm_out)) {
    printf("Can't make claim\n");
    return 1;
  }
  printf("Claim: ");
  print_claim(cm_out);
  printf("\n");

  signed_claim_message sc_out;
  if (!make_signed_claim(FLAGS_signing_alg.c_str(),
                         cm_out,
                         signing_key,
                         &sc_out)) {
    printf("Can't make claim\n");
    return 1;
  }
  printf("signed claim: ");
  print_signed_claim(sc_out);
  printf("\n");

  string sc_str;
  if (!sc_out.SerializeToString(&sc_str)) {
    printf("Can't serialize signed claim\n");
    return 1;
  }
  if (!write_file(FLAGS_output, sc_str.size(), (byte *)sc_str.data())) {
    printf("Can't write %s\n", FLAGS_output.c_str());
    return 1;
  }

  return 0;
}
