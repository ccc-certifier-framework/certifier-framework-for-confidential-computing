//  Copyright (c) 2021-23, VMware Inc, and the Certifier Authors.  All rights
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

// ****************************************************************************
// These are just dummy class definitions, based on the stuff defined in
// certifier_framework.h . These definitions are used solely to exercise
// different combinations of SWIG-interface rules and to verify via pytests
// the logic behind defining those rules.
// ****************************************************************************

#ifndef __SWIGPYTEST_H__
#define __SWIGPYTEST_H__

#include <string>

using std::string;

typedef unsigned char byte;

namespace swigpytests {

class cc_trust_data {

 public:
  string serialized_policy_cert_;
  cc_trust_data();
  ~cc_trust_data();
};

class secure_authenticated_channel {
 public:
  string role_;
  string host_name_;
  int    port_;
  string asn1_pvt_key_cert_;

  secure_authenticated_channel();
  secure_authenticated_channel(string &role);  // role is client or server
  ~secure_authenticated_channel();

  bool init_client_ssl(const string &private_key_cert);

  bool init_client_ssl(const string &host_name,
                       int           port,
                       string &      asn1_root_cert);

  bool init_client_ssl(const string &host_name,
                       int           port,
                       string &      asn1_root_cert,
                       const string &private_key_cert);

  bool init_client_ssl(const string &host_name,
                       int           port,
                       byte *        asn1_root_cert,
                       int           asn1_root_cert_size,
                       const string &private_key_cert);
};

}  // namespace swigpytests

#endif  // __SWIGPYTEST_H__
