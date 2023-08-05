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

#ifndef __X509_TESTS_H__
#define __X509_TESTS_H__

// RESOLVE: Need this? using namespace certifier::framework;
// using namespace certifier::utilities;
bool test_x_509_chain(bool print_all);

bool test_x_509_sign(bool print_all);

#ifdef RUN_SEV_TESTS

bool test_sev_certs(bool print_all);

bool test_real_sev_certs(bool print_all);

bool test_sev_request(bool print_all);

bool test_sev(bool);

#endif  // RUN_SEV_TESTS

#endif  // __X509_TESTS_H__
