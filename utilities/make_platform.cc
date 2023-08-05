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

// make_platform.exe

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(platform_type, "", "platform type");
DEFINE_string(properties_file, "", "properties files");
DEFINE_string(output, "", "output file");

int main(int an, char **av) {
  string usage(
      "Construct platform characteristics for platform verification policy");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  string usage_str("--platform_type=amd-sev-snp "
                   "--properties_file=<properties.bin> "
                   "--output=<platform.bin>");
  if (FLAGS_platform_type == "") {
    printf("No platform type\n");
    printf("%s %s\n", av[0], usage_str.c_str());
    return 1;
  }

  platform plat;
  plat.set_has_key(false);
  plat.set_platform_type(FLAGS_platform_type);

  if (FLAGS_properties_file != "") {
    string pp_str;
    if (!read_file_into_string(FLAGS_properties_file, &pp_str)) {
      printf("Can't read properties file\n");
      return 1;
    }
    if (!plat.mutable_props()->ParseFromString(pp_str)) {
      printf("Can't parse properties file\n");
      return 1;
    }
  }

  string p_out;
  if (!plat.SerializeToString(&p_out)) {
    printf("Can't serialize\n");
    return 1;
  }

  if (!write_file(FLAGS_output, p_out.size(), (byte *)p_out.data())) {
    printf("Can't write output file\n");
    return 1;
  }

  print_platform(plat);
  return 0;
}
