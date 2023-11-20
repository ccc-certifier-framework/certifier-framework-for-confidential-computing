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

#ifndef __CC_USEFUL_H__
#define __CC_USEFUL_H__

/*
 * A collection of useful macros and things ...
 */
#define CC_TO_STR(x) #x

// Return this for 'unknown thing', to avoid seg-faults when printing.
#define CC_EMPTY_STRING (const char *)""


/* Option {value -> name } lookup structure */
typedef struct optlookup {
  const int   id;
  const char *name;
} optlookup;

#define DCL__OPTLOOKUP(token, descr)                                           \
  { .id = token, .name = descr }

#define DCL_OPTLOOKUP(token, descr) DCL__OPTLOOKUP(token, #token ": " descr)

// Declare a terminating entry for optlookup table
#define DCL_OPTLOOKUP_TERM()                                                   \
  { .id = -1, .name = NULL }

// Evaluate the size of an array of constants
#define ARRAY_LEN(a) ((int)(sizeof(a) / sizeof((*a))))

const char *optbyid(optlookup *opt, int id);

#endif /* __CC_USEFUL_H__ */
