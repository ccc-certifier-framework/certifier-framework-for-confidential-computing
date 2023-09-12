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
// swigpytests.cc : To test swigpytests.i SWIG interfaces.
// These are just dummy class definitions, based on the stuff defined in
// certifier_framework.h . See swigpytests.h for details.
// ****************************************************************************

#include <string.h>
#include "certifier.pb.h"
#include "swigpytests.h"

using namespace swigpytests;

// ****************************************************************************
swigpytests::cc_trust_data::cc_trust_data() {
  serialized_policy_cert_ = "Unknown-root-cert";
}

swigpytests::cc_trust_data::~cc_trust_data() {}

bool swigpytests::cc_trust_data::initialize_simulated_enclave(
    const byte *serialized_attest_key_signed_claim,
    int         attest_key_signed_claim_size,
    const byte *serialized_attest_key,
    int         attest_key_size,
    const byte *measurement,
    int         measurement_size) {

  serialized_attest_key_.assign((char *)serialized_attest_key, attest_key_size);

  // code pulled from simulated_Init()

  // attest key
  string serialized_attest_key_str((const char *)serialized_attest_key,
                                   attest_key_size);

  key_message my_attestation_key;
  if (!my_attestation_key.ParseFromString(serialized_attest_key_str)) {
    printf("%s():%d: Can't parse attest key\n", __func__, __LINE__);
    printf("Key: %.*s\n", attest_key_size, serialized_attest_key);
    return false;
  }

  // Claim
  string serialized_attest_key_signed_claim_str(
      (const char *)serialized_attest_key_signed_claim,
      attest_key_signed_claim_size);

  signed_claim_message my_attest_claim;
  if (!my_attest_claim.ParseFromString(
          serialized_attest_key_signed_claim_str)) {
    printf("%s():%d: Can't parse attest claim\n", __func__, __LINE__);
    printf("Key: %.*s\n",
           attest_key_signed_claim_size,
           serialized_attest_key_signed_claim);
    return false;
  }
  string my_measurement((const char *)measurement, measurement_size);
  return true;
}

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

  asn1_root_cert_ = asn1_root_cert;
  swig_wrap_fn_name_.assign("init_client_ssl-const-string-asn1_root_cert");
  printf(" Executed %s():%d ... %s\n",
         __func__,
         __LINE__,
         swig_wrap_fn_name_.c_str());
  return true;
}

// Variation of above to exercise interface using Python bytestream input
bool swigpytests::secure_authenticated_channel::python_init_client_ssl(
    const byte *asn1_root_cert,
    int         asn1_root_cert_size) {  // In

  // string((const char *)serialized_attest_key, attest_key_size)
  asn1_root_cert_.assign(
      string((const char *)asn1_root_cert, asn1_root_cert_size));
  swig_wrap_fn_name_.assign(
      "init_client_ssl-byte_start-asn1_root_cert-int-asn1_root_cert_size");
  printf(" Executed %s():%d ... %s\n",
         __func__,
         __LINE__,
         swig_wrap_fn_name_.c_str());
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    string &asn1_root_cert_io,  // In/Out
    int     port) {                 // In
  // Update root-certificate with user-supplied certificate (in)
  asn1_root_cert_ = asn1_root_cert_io;

  port_ = port;

  // Return some new certificate string via user-supplied certificate arg. (out)
  asn1_root_cert_io.assign("New root Certificate");
  swig_wrap_fn_name_.assign(
      "init_client_ssl-const-string-asn1_root_cert_io-port");
  printf(" Executed %s():%d ... %s\n",
         __func__,
         __LINE__,
         swig_wrap_fn_name_.c_str());
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    int           port,
    const string &asn1_root_cert) {  // In
  asn1_root_cert_ = asn1_root_cert;
  port_ = port;
  swig_wrap_fn_name_.assign("init_client_ssl-port-const-string-asn1_root_cert");
  printf(" Executed %s():%d ... %s\n",
         __func__,
         __LINE__,
         swig_wrap_fn_name_.c_str());
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    const string &host_name,      // In
    int           port,           // In
    string &      asn1_root_cert_io) {  // In/Out
  host_name_ = host_name;
  port_ = port;

  // Update root-certificate with user-supplied certificate (in)
  asn1_root_cert_ = asn1_root_cert_io;

  // Return some new certificate string via user-supplied certificate arg. (out)
  asn1_root_cert_io.assign("New root Certificate");
  swig_wrap_fn_name_.assign(
      "init_client_ssl-host_name-port-string-asn1_root_cert_io");
  printf(" Executed %s():%d ... %s\n",
         __func__,
         __LINE__,
         swig_wrap_fn_name_.c_str());
  return true;
}

bool swigpytests::secure_authenticated_channel::init_client_ssl(
    const string &host_name,
    int           port,
    string &      asn1_root_cert_io,
    const string &asn1_my_cert_pvtkey) {
  host_name_ = host_name;
  port_ = port;

  // Update root-certificate with user-supplied certificate (in/out)
  asn1_root_cert_ = asn1_root_cert_io;

  // Update private-certificate with user-supplied private certificate (in/out)
  asn1_my_cert_ = asn1_my_cert_pvtkey;

  // Return some new certificate string via user-supplied certificate arg.
  asn1_root_cert_io.assign("New root Certificate");

  // clang-format off
  swig_wrap_fn_name_.assign(
      "init_client_ssl-host_name-port-string-asn1_root_cert_io-const-string-asn1_my_cert_pvtkey");
  // clang-format on
  printf(" Executed %s():%d ... %s\n",
         __func__,
         __LINE__,
         swig_wrap_fn_name_.c_str());
  return true;
}
