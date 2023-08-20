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

// make_measurement.exe --type=hash --input=input-file --output=output-file

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(type, "hash", "measurement type");
DEFINE_string(input, "measurement_utility.exe", "input file");
DEFINE_string(output, "measurement_utility.exe.measurement", "output file");


const int sha256_size = 32;
int       hash_utility(string &input, string &output) {

  int          in_size = file_size(input);
  int          in_read = in_size;
  byte *       to_hash = (byte *)malloc(in_size * sizeof(byte) + 1);
  byte         out[sha256_size];
  unsigned int out_len = sha256_size;

  if (to_hash == nullptr) {
    printf("Can't malloc\n");
    return 1;
  }

  if (!read_file(input, &in_read, to_hash)) {
    free(to_hash);
    printf("Can't read %s\n", input.c_str());
    return 1;
  }
  if (!digest_message(Digest_method_sha256, to_hash, in_size, out, out_len)) {
    free(to_hash);
    return 1;
  }
  if (!write_file(output, (int)out_len, out)) {
    free(to_hash);
    printf("Can't write %s\n", output.c_str());
    return 1;
  }

  if (FLAGS_print_all) {
    printf("Measurement: ");
    print_bytes((int)out_len, out);
    printf("\n");
  }

  free(to_hash);
  return 0;
}

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  if (FLAGS_type == "hash")
    return hash_utility(FLAGS_input, FLAGS_output);

  return 1;
}
