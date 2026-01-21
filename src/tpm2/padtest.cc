
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <tpm2_lib.h>
#include <errno.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl_helpers.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <openssl_helpers.h>

#include <string>
using std::string;


//
// Copyright 2015 Google Corporation, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// Portions of this code were derived TPM2.0-TSS published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// File: tpm2_lib.cc

// standard buffer size

bool white(const char c) {
  return c== ' ' || c == '\n' || c == ' ' || c == '\r';
}

int Convert(int in_size, char* in, byte* out) {
  extern byte ToHex(const char);
  int i;
  int n = 0;
  byte a, b;
  for (i = 0; i < in_size; i += 2) {
    if (i >= (in_size-1)) {
      if (white((const char)in[i]))
        break;
      a = ToHex((const char)in[i]);
      out[n++] = a;
      break;
    }
    if (in[i] == '\n')
      break;
    a = ToHex((const char)in[i]);
    b = ToHex((const char)in[i+1]);
    out[n++] = (a<<4) | b;
  }
  return n;
}

int main(int an, char** av) {
  string filename(av[1]);
  byte buf[1024];
  int buf_size = 1024;
  byte padded_buf[512];
  byte check[512];
  byte repadded_buf[1024];
  memset(check, 0, 512);
  memset(repadded_buf, 0, 512);

  if (!ReadFileIntoBlock(filename, &buf_size, buf)) {
    printf("Cant read %s\n", filename.c_str());
    return 1;
  }
  buf[buf_size] = 0;
  int pad_size = Convert(buf_size, (char*)buf, padded_buf);
  int check_len = RSA_padding_check_PKCS1_OAEP(check, 256, padded_buf, pad_size,
                    256, (byte*)"IDENTITY", strlen("IDENTITY")+1);
  printf("Padding %3d  : ", pad_size);PrintBytes(pad_size, padded_buf);printf("\n");
  printf("check %03d    : ", check_len);PrintBytes(check_len, check);printf("\n");
  int repadded_len = RSA_padding_add_PKCS1_OAEP(repadded_buf, 256, check, check_len,
                    	(byte*)"IDENTITY", strlen("IDENTITY")+1);
  printf("repadded  %03d : ", 256);PrintBytes(256, repadded_buf);printf("\n");
  return 0;
}
