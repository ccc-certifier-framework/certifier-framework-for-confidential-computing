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

// combine_properties.exe --in=file1,file2,...,filen --output=out

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(in, "", "input files");
DEFINE_string(output, "", "output file");
DEFINE_int32(print_level, 1, "print level");

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
  int         count = 0;

  while ((end = next_comma(start)) != nullptr) {
    if (count >= (*num - 1)) {
      return false;
    }
    if (names != nullptr) {
      names[count].append(start, end - start);
    }
    count++;
    if (*end == '\0')
      break;
    start = end + 1;
  }
  *num = count;
  return true;
}

int main(int an, char **av) {
  string usage("Combine properties from multiple files into one output file");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  if (FLAGS_in == "") {
    printf("%s: No input files\n", usage.c_str());
    printf("%s --in=name --output=<out_file>\n", av[0]);
    return 1;
  }

  int    num = 20;
  string names[num];
  if (!get_input_file_names(FLAGS_in, &num, names)) {
    printf("%s() error, line %d, too few names allocated\n",
           __func__,
           __LINE__);
    return 1;
  }

  properties my_props;
  for (int i = 0; i < num; i++) {
    property *np = my_props.add_props();
    string    p_str;
    if (!read_file_into_string(names[i], &p_str)) {
      printf("%s() error, line %d, can't read property file\n",
             __func__,
             __LINE__);
      return 1;
    }
    if (!np->ParseFromString(p_str)) {
      printf("%s() error, line %d, can't parse property file\n",
             __func__,
             __LINE__);
      return 1;
    }
  }

  string set_props;
  if (!my_props.SerializeToString(&set_props)) {
    printf("%s() error, line %d, can't serialize properties\n",
           __func__,
           __LINE__);
    return 1;
  }

  if (!write_file(FLAGS_output, set_props.size(), (byte *)set_props.data())) {
    printf("%s() error, line %d, can't write output file\n",
           __func__,
           __LINE__);
    return 1;
  }
  return 0;
}
