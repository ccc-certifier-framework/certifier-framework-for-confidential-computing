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

// combine_policy_certs.exe --init=true
//    --add_cert=true --new_cert_file=policy_cert_file.dom0
//    -- existing_certs=my_certs --output=my_certs

#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"

using namespace certifier::utilities;

DEFINE_int32(print_level, 1, "print level");

DEFINE_string(existing_certs, "my_certs", "existing certs input file");
DEFINE_string(new_cert_file, "", "new cert input file");
DEFINE_string(output, "my_certs", "output file");
DEFINE_bool(init, true, "initialized output file");
DEFINE_bool(add_cert, false, "add cert to existing cert");

// -------------------------------------------------------------------------


int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;

#if 0
  int num = 0;
  if (!get_input_file_names(FLAGS_input, &num, nullptr)) {
    printf("%s() error, line %d, can't get input file\n", __func__, __LINE__);
    return 1;
  }
  string *file_names = new string[num];
  if (!get_input_file_names(FLAGS_input, &num, file_names)) {
    printf("%s() error, line %d, can't get input file\n", __func__, __LINE__);
    return 1;
  }

  buffer_sequence bufs;
  for (int i = 0; i < num; i++) {
    int  sz = file_size(file_names[i]);
    byte buf[sz];

    if (!read_file(file_names[i], &sz, buf)) {
      printf("%s() error, line %d, can't open %s\n",
             __func__,
             __LINE__,
             file_names[i].c_str());
      return 1;
    }
    string *out = bufs.add_block();
    out->assign((char *)buf, sz);
  }

  string final_buffer;
  if (!bufs.SerializeToString(&final_buffer)) {
    printf("%s() error, line %d, can't serialize final buffers\n",
           __func__,
           __LINE__);
    return 1;
  }
  if (!write_file(FLAGS_output,
                  final_buffer.size(),
                  (byte *)final_buffer.data())) {
    printf("%s() error, line %d, can't write %s\n",
           __func__,
           __LINE__,
           FLAGS_output.c_str());
    return 1;
  }
#endif

  return 0;
}

// -------------------------------------------------------------------------
