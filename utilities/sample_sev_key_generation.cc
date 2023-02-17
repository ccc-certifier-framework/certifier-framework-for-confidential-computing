#include <gflags/gflags.h>
#include "certifier.h"
#include "support.h"
#include "attestation.h"

//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
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


DEFINE_bool(print_all, false,  "verbose");
DEFINE_string(ark_der, "sev_ark_cert.der",  "ark cert file");
DEFINE_string(ask_der, "sev_ask_cert.der",  "ask cert file");
DEFINE_string(vcek_der, "sev_vcek_cert.der",  "vcek cert file");
DEFINE_string(policy_key_file, "policy_key.bin",  "policy key file");
DEFINE_string(sev_attest, "sev_attest.bin",  "simulated attestation file");

static struct attestation_report default_report = {
        .version = 1,
        .guest_svn = 1, // Set to 1 for now
        .policy = 0xff,
        .signature_algo = SIG_ALGO_ECDSA_P384_SHA384,
        .platform_info = 0, // SMT disable
        // TODO: Hardcoded mockup measurement
        .measurement = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
};


// This generates an sev attestation signed by the key in key_file
int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);

  printf("sample_sev_key_generation.exe --ark_der=sev_ark_cert.der --ask_cert=sev_ask_cert.der --vcek_der=sev_vcek_cert.der --sev_attest=sev_attest.bin --policy_key-policy_key.bin\n");

  // policy key
  string policy_key_str;
  key_message policy_key;
  if (!read_file_into_string(FLAGS_policy_key_file, &policy_key_str)) {
    printf("Can't read policy key\n");
    return 1;
  }
  if (!policy_key.ParseFromString(policy_key_str)) {
    printf("Can't parse policy key\n");
    return 1;
  }
  key_message pub_policy_key;
  if (!private_key_to_public_key(policy_key, &pub_policy_key)) {
    printf("Can't translate private policy key\n");
    return 1;
  }

  // Generate keys and certs
  string rsa_type("rsa-4096-private");
  string ecc_type("ecc-384-private");
  string ark_name("ARKKey");
  string ask_name("ASKKey");
  string vcek_name("VCEKKey");
  string ark_desc_str("AMD-ark-key");
  string ask_desc_str("AMD-ask-key");
  string vcek_desc_str("AMD-vcek-key");

  // ARK
  key_message ark_vse_key;
  key_message pub_ark_vse_key;
  RSA* r1 = RSA_new();
  if (!generate_new_rsa_key(4096, r1)) {
    printf("Generate RSA ark key failed\n");
    return 1;
  }
  if (!RSA_to_key(r1, &ark_vse_key)) {
    printf("Generate vse ark key failed\n");
    return 1;
  }
  ark_vse_key.set_key_name(ark_name);
  if (!private_key_to_public_key(ark_vse_key, &pub_ark_vse_key)) {
    printf("private to public ark key failed\n");
    return 1;
  }

  X509* ark_509 = X509_new();
  if (!produce_artifact(ark_vse_key, ark_name, ark_desc_str, pub_ark_vse_key,
          ark_name, ark_desc_str, 1ULL, 86400 * 365.25, ark_509, true)) {
    printf("Generate ark cert failed\n");
    return 1;
  }
  X509_print_fp(stdout, ark_509);
  string ark_der;
  if (!x509_to_asn1(ark_509, &ark_der)) {
    printf("Can't convert ARK to der\n");
    return 1;
  }
  if (!write_file(FLAGS_ark_der, ark_der.size(), (byte*) ark_der.data())) {
    printf("Can't write %s\n", FLAGS_ark_der.c_str());
    return 1;
  }
  RSA_free(r1);

  // ASK
  key_message ask_vse_key;
  key_message pub_ask_vse_key;
  RSA* r2 = RSA_new();
  if (!generate_new_rsa_key(4096, r2)) {
    printf("Generate RSA ark key failed\n");
    return 1;
  }
  if (!RSA_to_key(r2, &ask_vse_key)) {
    printf("Generate vse ask key failed\n");
    return 1;
  }
  ask_vse_key.set_key_name(ask_name);
  if (!private_key_to_public_key(ask_vse_key, &pub_ask_vse_key)) {
    printf("private to public ask key failed\n");
    return 1;
  }

  X509* ask_509 = X509_new();
  if (!produce_artifact(ark_vse_key, ark_name, ark_desc_str, pub_ask_vse_key,
          ask_name, ask_desc_str, 1ULL, 86400 * 365.25, ask_509, false)) {
    printf("Generate ark cert failed\n");
    return 1;
  }
  X509_print_fp(stdout, ask_509);
  string ask_der;
  if (!x509_to_asn1(ask_509, &ask_der)) {
    printf("Can't convert ASK to der\n");
    return 1;
  }
  if (!write_file(FLAGS_ask_der, ask_der.size(), (byte*) ask_der.data())) {
    printf("Can't write %s\n", FLAGS_ask_der.c_str());
    return 1;
  }
  RSA_free(r2);

  // VCEK
  key_message vcek_vse_key;
  key_message pub_vcek_vse_key;
  EC_KEY* ec = generate_new_ecc_key(384);
  if (ec == nullptr) {
    printf("Can't generate ecc key\n");
    return 1;
  }
  if (!ECC_to_key(ec, &vcek_vse_key)) {
    printf("Generate vse vcek key failed\n");
    return 1;
  }
  vcek_vse_key.set_key_name(vcek_name);
  if (!private_key_to_public_key(vcek_vse_key, &pub_vcek_vse_key)) {
    printf("private to public vcek key failed\n");
    return 1;
  }

  X509* vcek_509 = X509_new();
  if (!produce_artifact(ask_vse_key, ask_name, ask_desc_str, pub_vcek_vse_key,
          vcek_name, vcek_desc_str, 1ULL, 86400 * 365.25, vcek_509, false)) {
    printf("Generate ark cert failed\n");
    return 1;
  }
  X509_print_fp(stdout, vcek_509);
  string vcek_der;
  if (!x509_to_asn1(vcek_509, &vcek_der)) {
    printf("Can't convert ASK to der\n");
    return 1;
  }
  if (!write_file(FLAGS_vcek_der, vcek_der.size(), (byte*) vcek_der.data())) {
    printf("Can't write %s\n", FLAGS_vcek_der.c_str());
    return 1;
  }

  // Attestation
  attestation_user_data ud;
  sev_attestation_message sev_att;
  string enclave_type("sev-enclave");

  if (!make_attestation_user_data(enclave_type, pub_policy_key, &ud)) {
    printf("Can't make user data\n");
    return 1;
  }
  string said_str;
  if (!ud.SerializeToString(&said_str)) {
    printf("Can't serialize user data\n");
    return 1;
  }

  sev_attestation_message the_attestation;
  the_attestation.set_what_was_said(said_str);

  int hash_len= 48;
  byte user_data_hash[hash_len];

  if (!digest_message("sha-384", (byte*)said_str.data(), said_str.size(), user_data_hash, hash_len)) {
    printf("digest_message failed\n");
    return 1;
  }
  memcpy(default_report.report_data, user_data_hash, hash_len);

  // sign report, put in in the_attestation
  int size_out = sizeof(signature);
  if (!ecc_sign("sha-384", ec, sizeof(attestation_report) - sizeof(signature), (byte*) &default_report,
                &size_out, (byte*)&default_report.signature)) {
    printf("signature failure\n");
    return 1;
  }
  string att_rep;
  att_rep.assign((char*)&default_report, sizeof(attestation_report));
  the_attestation.set_reported_attestation(att_rep);

  string sev_attest_str;
  if (!sev_att.SerializeToString(&sev_attest_str)) {
    printf("Can't serialize attestation message\n");
    return 1;
  }
  if (!write_file(FLAGS_sev_attest, att_rep.size(), (byte*) att_rep.data())) {
    printf("Can't write %s\n", FLAGS_sev_attest.c_str());
    return 1;
  }
  EC_KEY_free(ec);

  return 0;
}