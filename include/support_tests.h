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

#ifndef __SUPPORT_TESTS_H__
#define __SUPPORT_TESTS_H__

bool test_random(bool print_all);

bool test_encrypt(bool print_all);

bool test_authenticated_encrypt(bool print_all);

bool test_public_keys(bool print_all);

bool test_digest(bool print_all);

bool test_digest_multiple(bool print_all);

bool test_sign_and_verify(bool print_all);

bool test_time(bool print_all);

bool test_key_translation(bool print_all);

bool test_artifact(bool print_all);

bool test_local_certify(bool print_all);

bool test_new_local_certify(bool print_all);

bool test_partial_local_certify(bool print_all);

#endif  // __SUPPORT_TESTS_H__
