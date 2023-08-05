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

// package_claims.exe --input=file1,file2,... --output-file=filename

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(input, "input1,input2,...,inputk", "input file");
DEFINE_string(output, "claims_sequence.bin", "output file");

bool get_claim_from_block(const string &block, signed_claim_message *sc) {
  if (!sc->ParseFromString(block)) {
    printf("Can't parse clause\n");
    return false;
  }
  return true;
}

const char *next_comma(const char *p) {
  if (p == nullptr)
    return nullptr;
  while (*p != ',' && *p != '\0')
    p++;
  return p;
}

bool get_input_file_names(const string &name, int *num, string *names) {
  const char *start = name.c_str();
  const char *end = nullptr;
  *num = 0;

  while ((end = next_comma(start)) != nullptr) {
    if (names != nullptr) {
      names[*num].append(start, end - start);
    }
    (*num)++;
    if (*end == '\0')
      break;
    start = end + 1;
  }
  return true;
}

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  int num = 0;
  if (!get_input_file_names(FLAGS_input, &num, nullptr)) {
    printf("Can't get input file\n");
    return 1;
  }
  string *file_names = new string[num];
  if (!get_input_file_names(FLAGS_input, &num, file_names)) {
    printf("Can't get input file\n");
    return 1;
  }

  buffer_sequence bufs;
  for (int i = 0; i < num; i++) {
    int  sz = file_size(file_names[i]);
    byte buf[sz];

    if (!read_file(file_names[i], &sz, buf)) {
      printf("Can't open %s\n", file_names[i].c_str());
      return 1;
    }
    string *out = bufs.add_block();
    out->assign((char *)buf, sz);
  }

  string final_buffer;
  if (!bufs.SerializeToString(&final_buffer)) {
    printf("Can't serialize final buffers\n");
    return 1;
  }
  if (!write_file(FLAGS_output,
                  final_buffer.size(),
                  (byte *)final_buffer.data())) {
    printf("Can't write %s\n", FLAGS_output.c_str());
    return 1;
  }

  return 0;
}
