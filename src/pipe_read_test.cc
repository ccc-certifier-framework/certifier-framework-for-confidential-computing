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

#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include "certifier.h"
#include "support.h"
#include "simulated_enclave.h"

using namespace certifier::utilities;

int main(int an, char **av) {

  int fd[2];
  if (pipe2(fd, O_DIRECT) < 0) {
    printf("Pipe failed\n");
    return 0;
  }

  const int buf_size = 100;
  byte      buf[buf_size];
  for (int i = 0; i < buf_size; i++)
    buf[i] = (byte)2 * i;


  bool      res = true;
  const int num_tests = 20;
  int       pid = fork();
  if (pid < 0) {
  } else if (pid == 0) {  // child
    close(fd[0]);
    for (int i = 0; i < num_tests; i++) {
      int k = 4 * i + 1;
      printf("writing %d\n", k);
      sized_pipe_write(fd[1], k, buf);
    }
  } else {  // parent
    close(fd[1]);
    for (int i = 0; i < num_tests; i++) {
      string out;
      int    k = sized_pipe_read(fd[0], &out);
      if (k < 0) {
        res = false;
      } else {
        printf("Bytes out: %d, ", k);
        print_bytes(out.size(), (byte *)out.data());
        printf("\n");
      }
    }
  }

  if (res)
    printf("\nsucceeded\n");
  else
    printf("\nfailed\n");
  printf("\n");
  return 0;
}
