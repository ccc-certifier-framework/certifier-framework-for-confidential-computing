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


DEFINE_bool(print_all, false, "verbose");
DEFINE_bool(test_measurement, false, "init test measurement");
DEFINE_string(in_file, "test.exe", "Input binary");
DEFINE_string(out_file,
              "binary_trusted_measurements_file.bin",
              "binary_trusted_measurements_file");
DEFINE_string(mrenclave, "", "Measurement Hex String");

bool write_file(string file_name, int size, byte *data) {
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

bool read_file(string file_name, int *size, byte *data) {
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

bool digest_message(const byte * message,
                    int          message_len,
                    byte *       digest,
                    unsigned int digest_len) {
  EVP_MD_CTX *mdctx;

  if ((mdctx = EVP_MD_CTX_new()) == NULL)
    return false;
  if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    return false;
  if (1 != EVP_DigestUpdate(mdctx, message, message_len))
    return false;
  if (1 != EVP_DigestFinal_ex(mdctx, digest, &digest_len))
    return false;
  EVP_MD_CTX_free(mdctx);

  return true;
}

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);

  if (FLAGS_print_all) {
    if (FLAGS_test_measurement)
      printf("Generating test measurement\n");
    else if (FLAGS_mrenclave.size() != 0) {
      printf("Using measurement string: %s\n", FLAGS_mrenclave.c_str());
    } else {
      printf("Measuring %s\n", FLAGS_in_file.c_str());
    }
    printf("Output file: %s\n", FLAGS_out_file.c_str());
  }

  int  measurement_size = 64;
  byte m[measurement_size];

  if (FLAGS_test_measurement == true) {
    measurement_size = 32;
    for (int i = 0; i < measurement_size; i++)
      m[i] = (byte)i;
    if (!write_file(FLAGS_out_file, measurement_size, m)) {
      printf("Can't write %s\n", FLAGS_out_file.c_str());
      return 1;
    }
    return 0;
  } else if (FLAGS_mrenclave.size() != 0) {
    size_t size = FLAGS_mrenclave.size();
    char   hex[size + 2];
    memset((byte *)hex, 0, size + 2);
    const char *pos = (const char *)hex;
    byte        m[measurement_size];
    if (size % 2) {
      hex[0] = '0';
      memcpy(hex + 1, FLAGS_mrenclave.c_str(), size + 1);
    } else {
      memcpy(hex, FLAGS_mrenclave.c_str(), size + 1);
    }
    printf("Using measurement: %s\n", hex);
    measurement_size = strlen(hex) / 2;
    for (size_t count = 0;
         count < strlen(hex) / 2 && count < (size_t)measurement_size;
         count++) {
      sscanf(pos, "%2hhx", &m[count]);
      pos += 2;
    }

    if (!write_file(FLAGS_out_file, measurement_size, m)) {
      printf("Can't write %s\n", FLAGS_out_file.c_str());
      return 1;
    }
    return 0;
  }

  // read file and hash it
  int size = file_size(FLAGS_in_file);

  if (FLAGS_print_all) {
    printf("File size: %d\n", size);
  }

  byte *file_contents = (byte *)malloc(size);
  if (file_contents == nullptr) {
    printf("Can't alloc\n");
    return 1;
  }

  if (!read_file(FLAGS_in_file, &size, file_contents)) {
    printf("Can't read %s\n", FLAGS_in_file.c_str());
    free(file_contents);
    return 1;
  }

  measurement_size = 32;
  if (!digest_message(file_contents, size, m, (unsigned int)measurement_size)) {
    printf("Can't digest file\n");
    free(file_contents);
    return 1;
  }

  if (!write_file(FLAGS_out_file, measurement_size, m)) {
    printf("Can't write %s\n", FLAGS_out_file.c_str());
    free(file_contents);
    return 1;
  }

  free(file_contents);
  return 0;
}
