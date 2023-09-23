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
DEFINE_bool(print_debug, false, "print debugging info");
DEFINE_string(type, "hash", "measurement type");
DEFINE_string(input, "measurement_utility.exe", "input file");
DEFINE_string(policy_key, "", "policy key file, e.g., policy_key.py");
DEFINE_string(output, "measurement_utility.exe.measurement", "output file");


const int sha256_size = 32;

int hash_utility(string &input, string &policy_key_file, string &output) {

  int in_size = file_size(input);
  int in_read = in_size;
  int to_hash_size = in_size;

  int policy_key_size =
      (policy_key_file.size() ? file_size(policy_key_file) : 0);

  to_hash_size += policy_key_size;

  byte *       to_hash = (byte *)malloc(to_hash_size * sizeof(byte) + 1);
  byte         out[sha256_size];
  unsigned int out_len = sha256_size;

  if (to_hash == nullptr) {
    printf("Can't malloc\n");
    return 1;
  }

  // Read-in input file to be measured
  if (!read_file(input, &in_read, to_hash)) {
    free(to_hash);
    printf("Can't read %s\n", input.c_str());
    return 1;
  }
  if (FLAGS_print_debug) {
    printf("to_hash_size=%d, in_size=%d, in_read=%d, policy_key_size=%d\n",
           to_hash_size,
           in_size,
           in_read,
           policy_key_size);
  }

  // Read-in policy-key file to be measured, if provided
  int policy_read = policy_key_size;
  if (policy_key_size) {
    // Read-in policy_key after contents of input file read-in
    if (!read_file(policy_key_file, &policy_read, (to_hash + in_read))) {
      free(to_hash);
      printf("Can't read %s\n", policy_key_file.c_str());
      return 1;
    }
    if (FLAGS_print_debug) {
      printf("in_size=%d, in_read=%d, policy_key_size=%d, policy_read=%d\n",
             in_size,
             in_read,
             policy_key_size,
             policy_read);
    }
  }

  // Verify that read did not bust-up to_hash[] array
  if ((in_read + policy_read) > to_hash_size) {
    free(to_hash);
    printf("Detected overflow of data read into to_hash[] array of %d bytes"
           ", in_read=%d, policy_read=%d, sum=%d\n",
           to_hash_size,
           in_read,
           policy_read,
           (in_read + policy_read));
    return 1;
  }
  if (!digest_message(Digest_method_sha256,
                      to_hash,
                      to_hash_size,
                      out,
                      out_len)) {
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
    return hash_utility(FLAGS_input, FLAGS_policy_key, FLAGS_output);

  return 1;
}
