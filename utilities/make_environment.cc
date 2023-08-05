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

// make_environment.exe  --platform_file=file --measurement_file=file
// --output=file

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(platform_file, "", "platform file");
DEFINE_string(measurement_file, "", "measurement file");
DEFINE_string(output, "", "output file");

bool calculate_measurement(const string &in, string *out) {
  size_t size = in.size();
  char   hex[size + 2];
  memset((byte *)hex, 0, size + 2);
  const char *pos = (const char *)hex;
  if (size % 2) {
    hex[0] = '0';
    memcpy(hex + 1, (byte *)in.data(), size + 1);
  } else {
    memcpy(hex, (byte *)in.data(), size + 1);
  }

  printf("Using measurement: %s\n", hex);
  int    measurement_size = strlen(hex) / 2;
  byte   m[measurement_size];
  size_t count = 0;
  for (size_t count = 0;
       count < strlen(hex) / 2 && count < (size_t)measurement_size;
       count++) {
    sscanf(pos, "%2hhx", &m[count]);
    pos += 2;
  }
  out->assign((char *)m, measurement_size);
  return true;
}

int main(int an, char **av) {
  string usage("Generate platform measurement to output file");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

  if (FLAGS_platform_file == "" && FLAGS_measurement_file == ""
      && FLAGS_output == "") {
    printf("%s: %s\n", av[0], usage.c_str());
    printf(
        "%s --platform_file=<file> --measurement_file=<file> --output=<file>\n",
        av[0]);
    printf("Too few arguments\n");
    return 1;
  }

  platform plat;
  string   m_str;
  string   plat_str;

  if (!read_file_into_string(FLAGS_platform_file, &plat_str)) {
    printf("Can't read platform file\n");
    return 1;
  }

  if (!read_file_into_string(FLAGS_measurement_file, &m_str)) {
    printf("Can't read measurement file\n");
    return 1;
  }

  environment env;
  if (!env.mutable_the_platform()->ParseFromString(plat_str)) {
    printf("Can't parse platform file\n");
    return 1;
  }

  string meas;
  if (!calculate_measurement(m_str, &meas)) {
    printf("Can't calculate measurement\n");
    return 1;
  }
  env.mutable_the_measurement()->assign(meas);

  string p_out;
  if (!env.SerializeToString(&p_out)) {
    printf("Can't serialize\n");
    return 1;
  }

  if (!write_file(FLAGS_output, p_out.size(), (byte *)p_out.data())) {
    printf("Can't write output file\n");
    return 1;
  }

  print_environment(env);
  return 0;
}
