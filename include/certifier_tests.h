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

#ifndef __CERTIFIER_TESTS_H__
#define __CERTIFIER_TESTS_H__

// This list should be repeated in the same order in certifier_tests.i,
// which defines the SWIG interface for the Python bindings for the
// certifier_tests.so shared library.

#include "primitive_tests.h"
#include "claims_tests.h"
#include "store_tests.h"
#include "x509_tests.h"
#include "support_tests.h"

#endif  // __CERTIFIER_TESTS_H__
