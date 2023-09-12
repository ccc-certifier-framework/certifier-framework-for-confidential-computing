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
// certifier_framework.h . These definitions and interfaces are used solely:
// - to exercise different combinations of SWIG-interface rules
// - to verify via pytests the way to exercise these interfaces
// - to standardize on code structure to exchange data from Python code to C++
// ****************************************************************************

#ifndef __SWIGPYTESTS_H__
#define __SWIGPYTESTS_H__

#include <string>

using std::string;

typedef unsigned char byte;

namespace swigpytests {

// clang-format off
// ****************************************************************************
class cc_trust_data {

 public:
  string serialized_policy_cert_;
  string serialized_attest_key_;

  // To test invocation of constructor w/o any arguments.
  cc_trust_data();
  ~cc_trust_data();

  // The order of parameters is intentionally scrambled v/s the public
  // interface in certifier_framework.h . This is done to ensure that
  // we test that the SWIG-type mapping for multiple arguments still works
  // correctly irrespective of the order of the parameters.
  bool initialize_simulated_enclave(const byte *serialized_attest_endorsement_claim,
                                    int         attest_endorsement_claim_size,
                                    const byte *serialized_attest_key,
                                    int         attest_key_size,
                                    const byte *measurement,
                                    int         measurement_size);
};

/*
 * ****************************************************************************
 * Class to exercise Python interfaces to pass-in string data of
 * different types, for input / ouput etc.
 * ****************************************************************************
 */
class secure_authenticated_channel {
 public:
  // Debugging: Method invoked will poke a bread crumb in this field
  string swig_wrap_fn_name_;

  int port_;

  // Normal string data ... Simple ascii strings
  string role_;
  string host_name_;

  // Different certificate types; May contain Unicode surrogate chars
  string asn1_root_cert_;
  string asn1_my_cert_;

  secure_authenticated_channel();

  // string &role should really be 'const'. Define as non-const to verify via
  // tests how to pass-in data.
  secure_authenticated_channel(string &  role);  // role is client or server

  ~secure_authenticated_channel();

  // Different combinations of interfaces with mulitple arguments, where some
  // of the args are in, in/out, and some 'certificate' args could contain
  // non-standard Unicode surrogate char data.

  /*
   * NOTE: There seems to be no way to define two interfaces taking the same
   *        single argument, with one of them being an in/out arg.
   *        The invocation from Python ends up with the 1st one.
   *        In order to verify that the INOUT typemap rules for
   *        'string &asn1_root_cert_io' are correctly applied, we need an
   *        interface that Python invocation can tell-apart.
   */
  bool init_client_ssl(const string &asn1_root_cert);  // In

  bool init_client_ssl(string &asn1_root_cert_io, int port);    // In/Out
  bool init_client_ssl(int port, const string &asn1_root_cert);

  bool init_client_ssl(const string &host_name,
                       int           port,
                       string &      asn1_root_cert_io);

  bool init_client_ssl(const string &host_name,
                       int           port,
                       string &      asn1_root_cert_io,
                       const string &asn1_my_cert_pvtkey);

  bool python_init_client_ssl(const byte *asn1_root_cert,
                              int asn1_root_cert_size); // In

};

}  // namespace swigpytests

// clang-format on
#endif  // __SWIGPYTESTS_H__
