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

#include <gflags/gflags.h>
#include "support.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");

DEFINE_bool(is_root, false, "verbose");
DEFINE_string(key_name, "testKey", "key name");
DEFINE_string(key_type, Enc_method_rsa_2048_private, "test key type");
DEFINE_string(authority_name, "testAuthority", "authority name");
DEFINE_double(duration, 5.0 * 86400.0 * 365.0, "duration");
DEFINE_uint64(serial_number, 1, "serial number");
DEFINE_bool(generate_cert, false, "generate cert?");

DEFINE_string(key_output_file, "test_key_file.bin", "test key file");
DEFINE_string(cert_output_file, "test_cert_file.bin", "test cert file");


bool generate_key(const string &name,
                  const string &type,
                  const string &authority,
                  key_message * priv,
                  key_message * pub) {

  int n = 0;
  if (type == Enc_method_rsa_4096_private) {
    if (!make_certifier_rsa_key(4096, priv)) {
      return false;
    }
  } else if (type == Enc_method_rsa_2048_private) {
    if (!make_certifier_rsa_key(2048, priv)) {
      return false;
    }
  } else if (type == Enc_method_rsa_1024_private) {
    if (!make_certifier_rsa_key(1024, priv)) {
      return false;
    }
  } else if (type == Enc_method_ecc_384_private) {
    if (!make_certifier_ecc_key(384, priv)) {
      return false;
    }
  } else {
    return false;
  }
  priv->set_key_name(name);
  priv->set_key_type(type);
  priv->set_key_format("vse-key");
  if (!private_key_to_public_key(*priv, pub))
    return false;

  return true;
}

int main(int an, char **av) {
  string usage("Generate certificate keys in different formats to output file");
  gflags::SetUsageMessage(usage);
  gflags::ParseCommandLineFlags(&an, &av, true);

  printf("%s: %s\n", av[0], usage.c_str());
  printf("%s --key_type=<key-type> --key_output_file=<key_file.bin> "
         "--generate_cert=false --cert_output_file=<cert_file.bin> "
         "--duration=in-seconds --serial_number=123231 "
         "--authority_name=authority\n",
         av[0]);
  printf("Key types : rsa-1024-private, rsa-2048-private"
         ", rsa-4096-private, ecc-384-private\n");

  key_message priv;
  key_message pub;
  string      serialized_key;
  if (strcmp(FLAGS_key_type.c_str(), Enc_method_rsa_1024_private) == 0
      || strcmp(FLAGS_key_type.c_str(), Enc_method_rsa_2048_private) == 0
      || strcmp(FLAGS_key_type.c_str(), Enc_method_rsa_4096_private) == 0
      || strcmp(FLAGS_key_type.c_str(), Enc_method_ecc_384_private) == 0) {
    if (!generate_key(FLAGS_key_name,
                      FLAGS_key_type,
                      FLAGS_authority_name,
                      &priv,
                      &pub)) {
      printf("Couldn't generate key\n");
      return 0;
    }
  } else {
    printf("unsupported key type\n");
    return 1;
  }
  if (!priv.SerializeToString(&serialized_key)) {
    printf("Can't serialize key\n");
    return 1;
  }
  if (!write_file(FLAGS_key_output_file,
                  serialized_key.size(),
                  (byte *)serialized_key.data())) {
    printf("Can't write key file\n");
    return 1;
  }
  string asn_cert;
  if (FLAGS_generate_cert) {
    X509 *cert = X509_new();
    if (!produce_artifact(priv,
                          FLAGS_key_name,
                          FLAGS_key_name,
                          pub,
                          FLAGS_key_name,
                          FLAGS_key_name,
                          FLAGS_serial_number,
                          FLAGS_duration,
                          cert,
                          FLAGS_is_root)) {
      printf("Can't generate cert, produce_artifact failed\n");
      return 1;
    }
    if (!x509_to_asn1(cert, &asn_cert)) {
      printf("Can't convert to asn1\n");
      return 1;
    }
    string      issuer_name_str;
    string      issuer_description_str;
    string      subject_name_str;
    string      subject_organization_str;
    uint64_t    sn = 0;
    key_message s_key;
    if (verify_artifact(*cert,
                        pub,
                        &issuer_name_str,
                        &issuer_description_str,
                        &s_key,
                        &subject_name_str,
                        &subject_organization_str,
                        &sn)) {
      printf("Certificate verifies\n");
    } else {
      printf("Certificate does not verify\n");
    }
    if (!write_file(FLAGS_cert_output_file,
                    asn_cert.size(),
                    (byte *)asn_cert.data())) {
      printf("Can't write cert file\n");
      return 1;
    }
  }

  return 0;
}
