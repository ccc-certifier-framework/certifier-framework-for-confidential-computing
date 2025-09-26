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

// combine_policy_certs.exe --init=true
//    --add_cert=true --new_cert_file=policy_cert_file.dom0
//    -- existing_certs=my_certs --output=my_certs

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_int32(print_level, 1, "print level");

DEFINE_string(existing_certs, "my_certs", "existing certs input file");
DEFINE_string(new_cert_file, "", "new cert input file");
DEFINE_string(output, "my_certs", "output file");
DEFINE_bool(init, true, "initialized output file");
DEFINE_bool(add_cert, false, "add cert to existing cert");

// -------------------------------------------------------------------------


int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  buffer_sequence seq;

  printf("combine_policy_certs.exe --init=true "
         "--add_cert=true --new_cert_file=policy_cert_file.dom0 "
         "-- existing_certs=my_certs --output=my_certs");
  if (FLAGS_print_level > 0) {
    printf("combine_policy_certs\n");
    if (FLAGS_init) {
      printf("initialize new file\n");
    } else {
      printf("existing file: %s\n", FLAGS_existing_certs.c_str());
    }
    printf("New cert: %s\n", FLAGS_new_cert_file.c_str());
  }

  if (!FLAGS_init) {
    string in;

    if (!read_file_into_string(FLAGS_existing_certs, &in)) {
      printf("%s() error, line %d, can't read %s\n",
             __func__,
             __LINE__,
             FLAGS_existing_certs.c_str());
      return 1;
    }
    if (!seq.ParseFromString(in)) {
      printf("%s() error, line %d, can't parse existing certs\n",
             __func__,
             __LINE__);
      return 1;
    }
  }

  string new_cert;
  if (!read_file_into_string(FLAGS_new_cert_file, &new_cert)) {
    printf("%s() error, line %d, can't read %s\n",
           __func__,
           __LINE__,
           FLAGS_new_cert_file.c_str());
    return 1;
  }

  string *n = seq.add_block();
  n->assign(new_cert.data(), new_cert.size());

  string final_serialized_buffer;
  if (!seq.SerializeToString(&final_serialized_buffer)) {
    printf("%s() error, line %d, can't serialize final buffers\n",
           __func__,
           __LINE__);
    return 1;
  }
  if (!write_file(FLAGS_output,
                  final_serialized_buffer.size(),
                  (byte *)final_serialized_buffer.data())) {
    printf("%s() error, line %d, can't write %s\n",
           __func__,
           __LINE__,
           FLAGS_output.c_str());
    return 1;
  }

  if (FLAGS_print_level > 1) {
    printf("certs in final file:\n");
    for (int i = 0; i < seq.block_size(); i++) {
      X509 *x = X509_new();
      if (x == nullptr) {
        return 1;
      }
      if (!asn1_to_x509(seq.block(i), x)) {
        printf("%s() error, line %d, can't asn1 translate %d\n",
               __func__,
               __LINE__,
               i);
        return 1;
      }
      printf("\nCert %d:\n", i);
      X509_print_fp(stdout, x);
      printf("\n");

      X509_free(x);
    }
  }

  return 0;
}

// -------------------------------------------------------------------------
