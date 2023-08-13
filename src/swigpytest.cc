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

// ****************************************************************************
// swigpytest.cc : To test swigpytest.i SWIG interfaces.
// ****************************************************************************

#include "swigpytest.h"

using namespace swigpytests;

swigpytests::cc_trust_data::cc_trust_data() {
  serialized_policy_cert_ = "Unknown-root-cert";
}

swigpytests::cc_trust_data::~cc_trust_data() {}

swigpytests::secure_authenticated_channel::secure_authenticated_channel() {
  role_ = "Undefined-role";
}

swigpytests::secure_authenticated_channel::secure_authenticated_channel(
    string &role) {
  role_ = role;
}

swigpytests::secure_authenticated_channel::~secure_authenticated_channel() {}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    const string &private_key_cert) {
  asn1_pvt_key_cert_ = private_key_cert;
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    const string &host_name,
    int           port,
    string &      asn1_root_cert) {
  host_name_ = host_name;
  port_ = port;
  asn1_root_cert.assign("New root Certificate");
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    const string &host_name,
    int           port,
    string &      asn1_root_cert,
    const string &auth_cert) {
  host_name_ = host_name;
  port_ = port;
  asn1_root_cert.assign("New root Certificate");
  asn1_pvt_key_cert_ = auth_cert;
  return true;
}
