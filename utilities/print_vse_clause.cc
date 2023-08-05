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

// print_vse_clause.exe --input=filename

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(input, "measurement_utility.exe", "input file");

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

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  vse_clause in_cl;
  if (!get_clause_from_file(FLAGS_input, &in_cl)) {
    printf("Can't get clause\n");
    return 1;
  }
  printf("Clause: ");
  print_vse_clause(in_cl);
  printf("\n");
  return 0;
}
