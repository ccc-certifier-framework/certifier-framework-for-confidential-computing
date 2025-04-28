// Copyright 2014-2025 John Manferdelli, All Rights Reserved.
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
// File: test_acl.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>

#include "certifier.h"
#include "support.h"
#include "certifier.pb.h"
#include "acl.pb.h"
#include "acl_support.h"
#include "acl.h"
#include "acl_rpc.h"

using namespace certifier::framework;
using namespace certifier::utilities;

DEFINE_bool(server, false, "Server role");
DEFINE_bool(client, true , "Client role");

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!certifier::acl_lib::init_crypto()) {
    printf("Couldn't init crypto\n");
    return 1;
  }

  if (FLAGS_server) {
    printf("Server role\n");
  } else if (FLAGS_client) {
    printf("Client role\n");
  } else {
    printf("No role specified, assuming client role\n");
  }

  certifier::acl_lib::close_crypto();

  return 0;
}
