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

// --------------------------------------------------------------------------

DEFINE_int32(print_level, 1, "print level");
DEFINE_string(input, "", "input file");


bool get_signed_from_file(const string &in, signed_claim_message *sc) {
  int  in_size = file_size(in);
  int  in_read = in_size;
  byte serialized_cm[in_size];

  if (!read_file(in, &in_read, serialized_cm)) {
    printf("%s() error, line %d, can't read %s\n",
           __func__,
           __LINE__,
           in.c_str());
    return false;
  }
  string cm_str;
  cm_str.assign((char *)serialized_cm, in_size);
  if (!sc->ParseFromString(cm_str)) {
    printf("%s() error, line %d, can't parse signed claim\n",
           __func__,
           __LINE__);
    return false;
  }
  return true;
}

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  signed_claim_message sc;
  if (!get_signed_from_file(FLAGS_input, &sc)) {
    printf("%s() error, line %d, can't get signed claim\n", __func__, __LINE__);
    return 1;
  }

  if (FLAGS_print_level > 0) {
    print_signed_claim(sc);
  }
  return 0;
}

// --------------------------------------------------------------------------
