//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights
//  reserved.  Copyright (c), 2025, John Manferdelli, Paul England and
//  Datica Researdh.
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

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/socket.h>

#include "certifier_algorithms.h"
#include "certifier_framework.h"
#include "certifier_utilities.h"
#include "cryptstore.pb.h"

// cf_support.h

//  -------------------------------------------------------------------

#ifndef __CF_SUPPORT__
#  define __CF_SUPPORT__
using namespace certifier::framework;
using namespace certifier::utilities;

void              print_cryptstore_entry(const cryptstore_entry &ent);
cryptstore_entry *find_in_cryptstore(cryptstore &cs, string &tag, int version);
bool              version_range_in_cryptstore(cryptstore &cs,
                                              string     &tag,
                                              int        *low,
                                              int        *high);
bool              cf_generate_symmetric_key(key_message *key,
                                            string       key_name,
                                            string       key_type,
                                            string       key_format,
                                            double       duration_in_hours);
bool              cf_generate_public_key(key_message *key,
                                         string       key_name,
                                         string       key_type,
                                         string       key_format,
                                         double       duration_in_hours);
bool              get_item(cryptstore &cs,
                           string     &tag,
                           string     *type,
                           int        *version,
                           string     *tp,
                           string     *value);
bool              put_item(cryptstore &cs,
                           string     &tag,
                           string     &type,
                           int        &version,
                           string     &value);
void              print_cryptstore(cryptstore &cs);

bool create_cryptstore(cryptstore &cs,
                       string     &data_dir,
                       string     &encrypted_cryptstore_filename,
                       double      duration,
                       string     &enclave_type,
                       string     &sym_alg);
bool open_cryptstore(cryptstore *cs,
                     string     &data_dir,
                     string     &encrypted_cryptstore_filename,
                     double      duration,
                     string     &enclave_type,
                     string     &sym_alg);
bool save_cryptstore(cryptstore &cs,
                     string     &data_dir,
                     string     &encrypted_cryptstore_filename,
                     double      duration,
                     string     &enclave_type,
                     string     &sym_alg);
#endif

// -------------------------------------------------------------------------------
