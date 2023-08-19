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
// These are just dummy class definitions, based on the stuff defined in
// certifier_framework.h . See swigpytest.h for details.
// ****************************************************************************

#include <string.h>
#include "swigpytest.h"

using namespace swigpytests;

// ****************************************************************************
swigpytests::cc_trust_data::cc_trust_data() {
  serialized_policy_cert_ = "Unknown-root-cert";
}

swigpytests::cc_trust_data::~cc_trust_data() {}

// ****************************************************************************
swigpytests::secure_authenticated_channel::secure_authenticated_channel() {
  role_ = "Undefined-role";
}

swigpytests::secure_authenticated_channel::secure_authenticated_channel(
    string &role) {
  role_ = role;
}

swigpytests::secure_authenticated_channel::~secure_authenticated_channel() {}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    const string &asn1_root_cert) {  // In
  printf(" Executing %s():%d ...\n", __func__, __LINE__);

  asn1_root_cert_ = asn1_root_cert;
  swig_wrap_fn_name_.assign("init_client_ssl-const-string-asn1_root_cert");
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    string &asn1_root_cert_io,  // In/Out
    int     port) {                 // In
  printf(" Executing %s():%d ...\n", __func__, __LINE__);
  // Update root-certificate with user-supplied certificate (in)
  asn1_root_cert_ = asn1_root_cert_io;

  port_ = port;

  // Return some new certificate string via user-supplied certificate arg. (out)
  asn1_root_cert_io.assign("New root Certificate");
  swig_wrap_fn_name_.assign(
      "init_client_ssl-const-string-asn1_root_cert_io-port");
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    int           port,
    const string &asn1_root_cert) {  // In
  printf(" Executing %s():%d ...\n", __func__, __LINE__);
  asn1_root_cert_ = asn1_root_cert;
  port_ = port;
  swig_wrap_fn_name_.assign("init_client_ssl-port-const-string-asn1_root_cert");
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    const string &host_name,      // In
    int           port,           // In
    string &      asn1_root_cert_io) {  // In/Out
  printf(" Executing %s():%d ...\n", __func__, __LINE__);
  host_name_ = host_name;
  port_ = port;

  // Update root-certificate with user-supplied certificate (in)
  asn1_root_cert_ = asn1_root_cert_io;

  // Return some new certificate string via user-supplied certificate arg. (out)
  asn1_root_cert_io.assign("New root Certificate");
  swig_wrap_fn_name_.assign(
      "init_client_ssl-host_name-port-string-asn1_root_cert_io");
  return true;
}

/*
bool swigpytests::secure_authenticated_channel::init_client_ssl(
    string &asn1_root_cert, int port) {  // In

  // Update root-certificate with user-supplied certificate (in/out)
  asn1_root_cert_ = asn1_root_cert;

  port_ = port;

  // Return some new certificate string via user-supplied certificate arg.
  asn1_root_cert.assign("New root Certificate");
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    const string &host_name,
    int           port) {
  host_name_ = host_name;
  port_ = port;
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    const string &host_name,
    int           port,
    string &      asn1_root_cert,
    const string &asn1_my_cert_pvtkey) {
  host_name_ = host_name;
  port_ = port;

  // Update root-certificate with user-supplied certificate (in/out)
  asn1_root_cert_ = asn1_root_cert;

  // Update private-certificate with user-supplied private certificate (in/out)
  asn1_my_cert_ = asn1_my_cert_pvtkey;

  // Return some new certificate string via user-supplied certificate arg.
  asn1_root_cert.assign("New root Certificate");
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    const string &host_name,
    int           port,
    byte *        asn1_root_cert,
    int           asn1_root_cert_size,
    const string &auth_cert) {
  host_name_ = host_name;
  port_ = port;
  // asn1_root_cert.assign("New root Certificate");
  string root_cert("New root Certificate");
  memmove(asn1_root_cert, root_cert.c_str(), root_cert.size());
  asn1_pvt_key_cert_ = auth_cert;
  return true;
}
*/
