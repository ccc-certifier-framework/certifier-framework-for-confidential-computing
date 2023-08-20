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
#include "certifier.h"
#include "support.h"
#include "attestation.h"

using namespace certifier::utilities;

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(ark_der, "sev_ark_cert.der", "ark cert file");
DEFINE_string(ask_der, "sev_ask_cert.der", "ask cert file");
DEFINE_string(vcek_der, "sev_vcek_cert.der", "vcek cert file");
DEFINE_string(policy_key_file, "policy_key.bin", "policy key file");
DEFINE_string(sev_attest, "sev_attest.bin", "simulated attestation file");

/*
  From a real Sev machine

    Version: 2
    Guest SVN: 0
  Policy: 0x30000
    - Debugging Allowed:       No
    - Migration Agent Allowed: No
    - SMT Allowed:             Yes
    - Min. ABI Major:          0
    - Min. ABI Minor:          0
  Family ID:
    00000000000000000000000000000000
  Image ID:
    00000000000000000000000000000000
  VMPL: 0
  Signature Algorithm: 1 (ECDSA P-384 with SHA-384)
  Platform Version: 03000000000008115
    - Boot Loader SVN:   3
    - TEE SVN:           0
    - SNP firmware SVN:  8
    - Microcode SVN:    115
  Platform Info: 0x3
    - SMT Enabled: Yes
  Author Key Enabled: Yes
    Report Data:
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
  Measurement:
    5c19d5b4a50066c8c991bd920dfa2276e11d3531c91434a7
    34f3b258ab279cd1b3bbe89ef930236af11dc3d28c70f406
  Host Data:
    0000000000000000000000000000000000000000000000000000000000000000
  ID Key Digest:
    000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000
  Author Key Digest:
    000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000
  Report ID:
    e2af014dad028f1f2adf3c1b0f896a4e43307596fc75b9242c706764d82e620d
  Migration Agent Report ID:
    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  Reported TCB: 03000000000008115
  - Boot Loader SVN:   3
  - TEE SVN:           0
  - SNP firmware SVN:  8
  - Microcode SVN:    115
  Chip ID:
    d30d7b8575881faa90edf4fb4f7a1c52a0beedef9321af3780abd4b4c16cf5c8
    132d9d15d6537f3704de10afe7e8d989c7959654c38be1905cf9506ea737976f
 */


static struct attestation_report default_report = {
    .version = 2,
    .guest_svn = 1,
    .policy = 0x00000ULL,  // no migrate, debug or SMT
    .signature_algo = SIG_ALGO_ECDSA_P384_SHA384,
    .platform_info = 0,  // SMT disable --- should be 0x03?
    // Hardcoded measurement
    .measurement =
        {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        },
};

static void reverse_bytes(byte *buffer, size_t size) {
  if (!buffer || size == 0)
    return;
  for (byte *start = buffer, *end = buffer + size - 1; start < end;
       start++, end--) {
    byte temp = *start;
    *start = *end;
    *end = temp;
  }
}

// This generates an sev attestation signed by the key in key_file
int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);

  printf("sample_sev_key_generation.exe --ark_der=sev_ark_cert.der "
         "--ask_cert=sev_ask_cert.der --vcek_der=sev_vcek_cert.der "
         "--sev_attest=sev_attest.bin --policy_key-policy_key.bin\n");

  // policy key
  string      policy_key_str;
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
  default_report.reported_tcb.raw = 0x03000000000008115ULL;
  default_report.platform_version.raw = 0x03000000000008115ULL;

  // Generate keys and certs
  string rsa_type(Enc_method_rsa_4096_private);
  string ecc_type(Enc_method_ecc_384_private);
  string ark_name("ARKKey");
  string ask_name("ASKKey");
  string vcek_name("VCEKKey");
  string ark_desc_str("AMD-ark-key");
  string ask_desc_str("AMD-ask-key");
  string vcek_desc_str("AMD-vcek-key");

  // ARK
  key_message ark_vse_key;
  key_message pub_ark_vse_key;
  RSA *       r1 = RSA_new();
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

  X509 *ark_509 = X509_new();
  if (!produce_artifact(ark_vse_key,
                        ark_name,
                        ark_desc_str,
                        pub_ark_vse_key,
                        ark_name,
                        ark_desc_str,
                        1ULL,
                        86400 * 365.25,
                        ark_509,
                        true)) {
    printf("Generate ark cert failed\n");
    return 1;
  }
  printf("\nARK Cert\n");
  X509_print_fp(stdout, ark_509);
  string ark_der;
  if (!x509_to_asn1(ark_509, &ark_der)) {
    printf("Can't convert ARK to der\n");
    return 1;
  }
  if (!write_file(FLAGS_ark_der, ark_der.size(), (byte *)ark_der.data())) {
    printf("Can't write %s\n", FLAGS_ark_der.c_str());
    return 1;
  }
  RSA_free(r1);

  // ASK
  key_message ask_vse_key;
  key_message pub_ask_vse_key;
  RSA *       r2 = RSA_new();
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

  X509 *ask_509 = X509_new();
  if (!produce_artifact(ark_vse_key,
                        ark_name,
                        ark_desc_str,
                        pub_ask_vse_key,
                        ask_name,
                        ask_desc_str,
                        1ULL,
                        86400 * 365.25,
                        ask_509,
                        false)) {
    printf("Generate ark cert failed\n");
    return 1;
  }
  printf("\nASK Cert\n");
  X509_print_fp(stdout, ask_509);
  string ask_der;
  if (!x509_to_asn1(ask_509, &ask_der)) {
    printf("Can't convert ASK to der\n");
    return 1;
  }
  if (!write_file(FLAGS_ask_der, ask_der.size(), (byte *)ask_der.data())) {
    printf("Can't write %s\n", FLAGS_ask_der.c_str());
    return 1;
  }
  RSA_free(r2);

  // VCEK
  key_message vcek_vse_key;
  key_message pub_vcek_vse_key;
  EC_KEY *    ec = generate_new_ecc_key(384);
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

  X509 *vcek_509 = X509_new();
  if (!produce_artifact(ask_vse_key,
                        ask_name,
                        ask_desc_str,
                        pub_vcek_vse_key,
                        vcek_name,
                        vcek_desc_str,
                        1ULL,
                        86400 * 365.25,
                        vcek_509,
                        false)) {
    printf("Generate ark cert failed\n");
    return 1;
  }
  printf("\nVCEK Cert\n");
  X509_print_fp(stdout, vcek_509);
  string vcek_der;
  if (!x509_to_asn1(vcek_509, &vcek_der)) {
    printf("Can't convert ASK to der\n");
    return 1;
  }
  if (!write_file(FLAGS_vcek_der, vcek_der.size(), (byte *)vcek_der.data())) {
    printf("Can't write %s\n", FLAGS_vcek_der.c_str());
    return 1;
  }

  // Attestation
  attestation_user_data ud;
  string                enclave_type("sev-enclave");

  // use policy key as enclave key
  if (!make_attestation_user_data(enclave_type, pub_policy_key, &ud)) {
    printf("Can't make user data\n");
    return 1;
  }
  ud.mutable_policy_key()->CopyFrom(pub_policy_key);

  string said_str;
  if (!ud.SerializeToString(&said_str)) {
    printf("Can't serialize user data\n");
    return 1;
  }

  int  hash_len = 48;
  byte user_data_hash[hash_len];

  if (!digest_message(Digest_method_sha_384,
                      (byte *)said_str.data(),
                      said_str.size(),
                      user_data_hash,
                      hash_len)) {
    printf("digest_message failed\n");
    return 1;
  }
  memcpy(default_report.report_data, user_data_hash, hash_len);

  // sign report, put in in the_attestation
  int  size_out = 256;
  byte out[256];
  memset(out, 0, size_out);

  int  sig_digest_len = 48;
  byte sig_digest[sig_digest_len];
  if (!digest_message(Digest_method_sha_384,
                      (byte *)&default_report,
                      sizeof(attestation_report) - sizeof(signature),
                      sig_digest,
                      sig_digest_len)) {
    printf("digest_message  for whole report failed\n");
    return 1;
  }
  ECDSA_SIG *sig = ECDSA_do_sign((const byte *)sig_digest, sig_digest_len, ec);

  if (sig == nullptr) {
    printf("Can't sign digest\n");
    return 1;
  }

  const BIGNUM *nr = ECDSA_SIG_get0_r(sig);
  const BIGNUM *ns = ECDSA_SIG_get0_s(sig);

  printf("r: ");
  BN_print_fp(stdout, nr);
  printf("\n");
  printf("s: ");
  BN_print_fp(stdout, ns);
  printf("\n");

  BN_bn2bin(nr, default_report.signature.r);
  BN_bn2bin(ns, default_report.signature.s);

  reverse_bytes(default_report.signature.r, 48);
  reverse_bytes(default_report.signature.s, 48);
  printf("r: ");
  print_bytes(48, default_report.signature.r);
  printf("\n");
  printf("s: ");
  print_bytes(48, default_report.signature.s);
  printf("\n");

  sev_attestation_message the_attestation;
  the_attestation.set_what_was_said(said_str);
  string att_rep;
  att_rep.assign((char *)&default_report, sizeof(attestation_report));
  the_attestation.set_reported_attestation(att_rep);

  string sev_attest_str;
  if (!the_attestation.SerializeToString(&sev_attest_str)) {
    printf("Can't serialize attestation message\n");
    return 1;
  }
  if (!write_file(FLAGS_sev_attest,
                  sev_attest_str.size(),
                  (byte *)sev_attest_str.data())) {
    printf("Can't write %s\n", FLAGS_sev_attest.c_str());
    return 1;
  }
  EC_KEY_free(ec);

  return 0;
}
