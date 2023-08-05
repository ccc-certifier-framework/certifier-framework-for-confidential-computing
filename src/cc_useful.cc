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

#include <cstddef>
#include "cc_useful.h"

/*
 * Implementation for a collection of useful macros and things ...
 */

/*
 * Find 'optid' in 'opt' lookup array, return option's name.
 * Returns NULL if optid is not found in lookup array.
 */
const char *optbyid(optlookup *opt_array, int optid) {
  if (!opt_array) {
    return CC_EMPTY_STRING;
  }
  // Expect array to be terminated by a NULL-name entry
  optlookup *opt = NULL;
  for (opt = opt_array; opt->name; opt++) {
    if (opt->id == optid) {
      return opt->name;
    }
  }
  return NULL;
}
