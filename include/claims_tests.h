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

#ifndef __CLAIMS_TESTS_H__
#define __CLAIMS_TESTS_H__

bool test_claims_1(bool print_all);

bool test_signed_claims(bool print_all);

bool test_predicate_dominance(bool print_all);

bool test_certify_steps(bool print_all);

bool test_full_certification(bool print_all);

#endif  // __CLAIMS_TESTS_H__
