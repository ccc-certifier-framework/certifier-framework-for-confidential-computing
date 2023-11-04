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

#include <sstream>
#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace std;
using namespace certifier::utilities;

int parse_other_files_size(string &        other_files,
                           vector<string> &other_files_list,
                           vector<int> &   other_files_size);

DEFINE_bool(print_all, false, "verbose");
DEFINE_bool(print_debug, false, "print debugging info");
DEFINE_string(type, "hash", "measurement type");
DEFINE_string(input, "measurement_utility.exe", "input file");
DEFINE_string(other_files,
              "",
              "Comma-separated list of other files to include in measurement; "
              "e.g., policy_key.py,certifier_framework.py");
DEFINE_string(output, "measurement_utility.exe.measurement", "output file");


const int sha256_size = 32;

/*
 * Compute the hash-digest for the input file and, optionally, include
 * a list of other-files that need to be included in the measurement,
 * specified by the other_files argument.
 *
 * NOTE: We make sure to read-in the contents of all files that go into the
 * measurement ino one buffer. This slightly reduces the chance that while
 * this utility is running, we don't run into the Time-of-Check to Time-of-Use,
 * abbreviated as "TOCTOU", 'vulnerability'. That might happen if we read-in
 * file-1 first, and while other files are being read, contents of file-1
 * is changed. Second, and more importantly, we use the digest_message()
 * interface, which is a wrapper around EVP_Digest*() interfaces. This
 * wrapper does not yield a hash that can be updated across a call to
 * individual files.
 */
int hash_utility(string &input, string &other_files, string &output) {

  int in_size = file_size(input);
  int in_read = in_size;
  int to_hash_size = in_size;

  vector<string> other_files_list;
  vector<int>    other_files_size;

  int other_files_total_size =
      (other_files.size() ? parse_other_files_size(other_files,
                                                   other_files_list,
                                                   other_files_size)
                          : 0);

  if (other_files_total_size < 0) {
    printf("Error, reading one or more input files.\n");
    return 1;
  }
  to_hash_size += (other_files_total_size);

  byte *       to_hash = (byte *)malloc(to_hash_size * sizeof(byte));
  byte *       to_hash_start = to_hash;
  byte         out[sha256_size];
  unsigned int out_len = sha256_size;

  memset(out, 0, sizeof(out));

  if (to_hash == nullptr) {
    printf("Can't malloc %d bytes.\n", to_hash_size);
    return 1;
  }

  // Read-in input file to be measured
  if (!read_file(input, &in_read, to_hash)) {
    free(to_hash_start);
    printf("Can't read %s\n", input.c_str());
    return 1;
  }
  if (FLAGS_print_debug) {
    printf("%d: to_hash_size=%d, in_size=%d, in_read=%d, "
           "other_files_total_size=%d\n",
           __LINE__,
           to_hash_size,
           in_size,
           in_read,
           other_files_total_size);
  }

  // Read-in the other files to be measured, if provided
  int other_files_read_size = 0;
  if (other_files_total_size) {
    to_hash += in_read;

    // Read-in other files specified, after contents of input file read-in
    for (int fctr = 0; fctr < (int)other_files_list.size(); fctr++) {
      int bytes_read_this_file = other_files_size[fctr];

      if (!read_file(other_files_list[fctr], &bytes_read_this_file, to_hash)) {
        free(to_hash_start);
        printf("Can't read %s\n", other_files_list[fctr].c_str());
        return 1;
      }
      if (FLAGS_print_debug) {
        printf("%d: File: '%s', bytes read=%d\n",
               __LINE__,
               other_files_list[fctr].c_str(),
               bytes_read_this_file);
      }
      to_hash += bytes_read_this_file;
      other_files_read_size += bytes_read_this_file;
    }
  }

  // Verify that read did not bust-up to_hash[] array
  if ((in_read + other_files_read_size) > to_hash_size) {
    free(to_hash_start);
    printf("Detected overflow of data read into to_hash[] array of %d bytes"
           ", in_read=%d, other_files_read_size=%d, sum=%d\n",
           to_hash_size,
           in_read,
           other_files_read_size,
           (in_read + other_files_read_size));
    return 1;
  }
  if (!digest_message(Digest_method_sha256,
                      to_hash_start,
                      to_hash_size,
                      out,
                      out_len)) {
    free(to_hash_start);
    return 1;
  }
  if (!write_file(output, (int)out_len, out)) {
    free(to_hash_start);
    printf("Can't write %s\n", output.c_str());
    return 1;
  }

  if (FLAGS_print_all) {
    printf("Measurement: ");
    print_bytes((int)out_len, out);
    printf("\n");
  }

  free(to_hash_start);
  return 0;
}

/*
 * parse_other_files_size() - Parse a list of comma-separated file names which
 * should be included in the measurement. Get each file's size, and return
 * an error if file could not be found.
 *
 * Parameters:
 *  other_files      - (In) Comma-separated list of file names
 *  other_files_list - (Out) Array of file names found
 *  other_files_size - (Out) Array of each file's size
 *
 * Returns: total size of all files listed in 'other_files'
 */
int parse_other_files_size(string &        other_files,
                           vector<string> &other_files_list,
                           vector<int> &   other_files_size) {
  stringstream ss(other_files);

  int other_files_total_size = 0;
  while (ss.good()) {
    string substr;
    getline(ss, substr, ',');
    int this_files_size = file_size(substr);
    if (this_files_size < 0) {
      printf("Error: Input file '%s' not found.\n", substr.c_str());
      return this_files_size;
    }
    other_files_total_size += this_files_size;
    other_files_list.push_back(substr);
    other_files_size.push_back(this_files_size);
  }
  return other_files_total_size;
}

int main(int an, char **av) {
  string usage("Certifier Measurement utility to generate measurement of "
               "application and dependent software");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  if (FLAGS_type == "hash")
    return hash_utility(FLAGS_input, FLAGS_other_files, FLAGS_output);

  return 1;
}
