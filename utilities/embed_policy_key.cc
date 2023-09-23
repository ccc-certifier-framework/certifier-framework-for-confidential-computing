//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
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

#include <gflags/gflags.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string>
#include <memory>

#include <openssl/evp.h>

#ifndef byte
typedef unsigned char byte;
#endif

using std::string;


DEFINE_bool(print_all, false,  "verbose");
DEFINE_string(input, "policy_cert.bin",  "X509 policy certificate");
DEFINE_string(output, "policy.include.cc",  "policy cert inclusion file");
DEFINE_string(array_name, "initialized_cert",  "Name of byte array");
DEFINE_bool(python, false,  "Python app");
DEFINE_bool(debug, false,  "Print debugging info");

bool write_file(string file_name, int size, byte* data) {
  int out = open(file_name.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (out < 0)
    return false;
  if (write(out, data, size) < 0) {
    printf("Can't write file\n");
    close(out);
    return false;
  }
  close(out);
  return true;
}

int file_size(string file_name) {
  struct stat file_info;

  if (stat(file_name.c_str(), &file_info) != 0)
    return false;
  if (!S_ISREG(file_info.st_mode))
    return false;
  return (int)file_info.st_size;
}

bool read_file(string file_name, int* size, byte* data) {
  struct stat file_info;

  if (stat(file_name.c_str(), &file_info) != 0)
    return false;
  if (!S_ISREG(file_info.st_mode))
    return false;
  int bytes_in_file = (int)file_info.st_size;
  if (bytes_in_file > *size) {
    return false;
  }
  int fd = ::open(file_name.c_str(), O_RDONLY);
  if (fd < 0)
    return false;
  int n = (int)read(fd, data, bytes_in_file);
  close(fd);
  *size = n;
  return true;
}

bool generate_policy_cert_in_code(string& asn1_cert_file, string& include_file) {
  int cert_size = file_size(asn1_cert_file);
  if (cert_size <= 0)
  {
    printf("Invalid size=%d for input file '%s'.\n",
           cert_size, asn1_cert_file.c_str());
    return false;
  }
  byte bin_cert[cert_size];
 
  int t_size = cert_size;
  if(!read_file(asn1_cert_file, &t_size, bin_cert))
    return false;

  if (FLAGS_debug) {
    printf("include_file=%s\n", include_file.c_str());
  }

  int out = open(include_file.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (out < 0)
    return false;

  char terminator_ch = ';';
  char array_start = '{';
  char array_end = '}';
  const int buf_size = 128;
  char t_buf[buf_size];
  memset(t_buf, 0, buf_size);
  if (FLAGS_python) {
    terminator_ch = '\n';
    array_start = '[';
    array_end = ']';
    snprintf(t_buf, buf_size, "#!/usr/bin/env python3\n\n"
                              "\"\"\"Policy certificate generated for Python simple_app"
                              "\"\"\"\n\n");
    if (write(out, (byte*)t_buf, strlen(t_buf)) < 0) {
      printf("Bad write\n");
    }
  }
  // array_name
  string array_name = FLAGS_array_name;
  string size_name = array_name + (FLAGS_python ? "_SIZE" : "_size");

  memset(t_buf, 0, buf_size);
  sprintf(t_buf, "%s%s = %d%c\n",
          (FLAGS_python ? "" : "int "),
          size_name.c_str(),
          t_size,
          terminator_ch);
  if (write(out, (byte*)t_buf, strlen(t_buf)) < 0) {
    printf("Bad write\n");
  }
  memset(t_buf, 0, buf_size);
  if (FLAGS_python) {
    sprintf(t_buf, "%s = %c\n    ", array_name.c_str(), array_start);
  } else {
    sprintf(t_buf, "byte %s[%d] = {\n    ", array_name.c_str(), t_size);
  }

  if (write(out, (byte*)t_buf, strlen(t_buf)) < 0) {
    printf("Bad write\n");
  }
  for (int i = 0; i < t_size; i++) {
    memset(t_buf, 0, buf_size);
    sprintf(t_buf, " 0x%02x,", bin_cert[i]);
    if (write(out, (byte*)t_buf, strlen(t_buf)) < 0) {
      printf("Bad write\n");
    }
    if ((i%8) == 7) {
      if (write(out, (byte*)"\n    ", 5) < 0) {
        printf("Bad write\n");
      }
    }
  }
  snprintf(t_buf, sizeof(t_buf), "\n%c%c%s",
           array_end,
           terminator_ch,
           (FLAGS_python ? "" : "\n\n"));
  if (write(out, (byte*)t_buf, strlen(t_buf)) < 0) {
    printf("Bad write\n");
  }
  close(out);

return true;
}

int main(int an, char** av) {
  string usage("Generate policy certificate to embed policy key in sample app");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);

  if (FLAGS_input == "") {
    printf("No input file\n");
    return 1;
  }
  if (FLAGS_output == "") {
    printf("No output file\n");
    return 1;
  }

  if (!generate_policy_cert_in_code(FLAGS_input, FLAGS_output))
    return 1;
  return 0;
}
