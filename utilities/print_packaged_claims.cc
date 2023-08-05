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

// print_packaged_claims.exe --input=input-file

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(input, "simple_clause.bin", "input file");

void print_signed_claim_clauses(const signed_claim_message &sc) {
  string cm_str;
  cm_str.assign((char *)sc.serialized_claim_message().data(),
                sc.serialized_claim_message().size());
  claim_message cm;
  if (!cm.ParseFromString(cm_str)) {
    printf("Can't parse serialized claim\n");
    return;
  }
  string vse_str;
  vse_str.assign((char *)cm.serialized_claim().data(),
                 cm.serialized_claim().size());
  vse_clause v;
  if (!v.ParseFromString(vse_str)) {
    printf("Can't parse serialized vse clasue\n");
    return;
  }
  print_vse_clause(v);
  printf("\n");
}

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  int in_size = file_size(FLAGS_input.c_str());
  int in_read = in_size;

  if (in_size <= 0) {
    printf("Invalid size=%d for input file '%s'.\n",
           in_size,
           FLAGS_input.c_str());
    return 1;
  }

  byte   buf[in_size];
  string all_bufs;

  if (!read_file(FLAGS_input, &in_read, buf)) {
    printf("Can't read input file '%s'.\n", FLAGS_input.c_str());
    return 1;
  }

  all_bufs.assign((char *)buf, in_size);
  buffer_sequence seq;
  if (!seq.ParseFromString(all_bufs)) {
    printf("Can't deserialize %s\n", FLAGS_input.c_str());
    return 1;
  }

  printf("\n %d blocks\n", seq.block_size());
  for (int i = 0; i < seq.block_size(); i++) {
    const string &       s = seq.block(i);
    signed_claim_message sc;

    if (!sc.ParseFromString(s)) {
      printf("Can't parse input file\n");
      return 1;
    }
    printf("%d: ", i + 1);
    if (FLAGS_print_all)
      print_signed_claim(sc);
    else
      print_signed_claim_clauses(sc);
    printf("\n");
  }

  return 0;
}
