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
DEFINE_string(input, "", "input file");


bool get_signed_from_file(const string &in, signed_claim_message *sc) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte serialized_cm[in_size];

  if (!read_file(in, &in_read, serialized_cm)) {
    printf("Can't read input file '%s'.\n", in.c_str());
    return false;
  }
  string cm_str;
  cm_str.assign((char *)serialized_cm, in_size);
  if (!sc->ParseFromString(cm_str)) {
    printf("Can't parse signed claim\n");
    return false;
  }
  return true;
}

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  signed_claim_message sc;
  if (!get_signed_from_file(FLAGS_input, &sc)) {
    printf("Can't get signed claim from file '%s'.\n", FLAGS_input.c_str());
    return 1;
  }

  print_signed_claim(sc);
  return 0;
}
