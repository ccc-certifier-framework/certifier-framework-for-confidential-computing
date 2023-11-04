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

#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include "certifier.h"
#include "support.h"
#include "simulated_enclave.h"

#include "certifier_tests.h"

DEFINE_bool(print_all, false, "verbose");
DEFINE_string(trusted_measurements_file,
              "binary_trusted_measurements_file.bin",
              "binary_trusted_measurements_file");
DEFINE_bool(read_measurement_file, false, "read measurement file");

DEFINE_string(policy_key_file_name, "policy_key_file.bin", "policy_key file");
DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement,
              "platform_attest_endorsement.bin",
              "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "example_app.measurement", "measurement");
DEFINE_string(policy_file_name, "", "policy file");
DEFINE_string(ark_key_file_name, "ark_key_file.bin", "ark key");
DEFINE_string(ask_key_file_name, "ask_key_file.bin", "ask key");
DEFINE_string(vcek_key_file_name, "vcek_key_file.bin", "vcek key");
DEFINE_string(ark_cert_file_name, "ark_cert_file.bin", "ark cert");
DEFINE_string(ask_cert_file_name, "ask_cert_file.bin", "ask cert");
DEFINE_string(vcek_cert_file_name, "vcek_cert_file.bin", "vcek cert");

// Encryption and support tests

TEST(test_random, test_random) {
  EXPECT_TRUE(test_random(FLAGS_print_all));
}

TEST(test_digest, test_digest) {
  EXPECT_TRUE(test_digest(FLAGS_print_all));
}

TEST(test_digest_multiple, test_digest_multiple) {
  EXPECT_FALSE(test_digest_multiple(FLAGS_print_all));
}

TEST(test_encrypt, test_encrypt) {
  EXPECT_TRUE(test_encrypt(FLAGS_print_all));
}

TEST(test_authenticated_encrypt, test_authenticated_encrypt) {
  EXPECT_TRUE(test_authenticated_encrypt(FLAGS_print_all));
}

TEST(public_keys, test_public_keys) {
  EXPECT_TRUE(test_public_keys(FLAGS_print_all));
}

TEST(sign_and_verify, test_sign_and_verify) {
  EXPECT_TRUE(test_sign_and_verify(FLAGS_print_all));
}

TEST(key_translation, test_key_translation) {
  EXPECT_TRUE(test_key_translation(FLAGS_print_all));
}

TEST(time, test_time) {
  EXPECT_TRUE(test_time(FLAGS_print_all));
}

// Basic Primitive tests
TEST(seal, test_seal) {
  EXPECT_TRUE(test_seal(FLAGS_print_all));
}

TEST(attest, test_attest) {
  EXPECT_TRUE(test_attest(FLAGS_print_all));
}

// Admission Tests

TEST(artifact, test_artifact) {
  EXPECT_TRUE(test_artifact(FLAGS_print_all));
}

// File protection and store tests
TEST(protect, test_protect) {
  EXPECT_TRUE(test_protect(FLAGS_print_all));
}

TEST(policy_store, test_policy_store) {
  EXPECT_TRUE(test_policy_store(FLAGS_print_all));
}

TEST(init_and_recover_containers, test_init_and_recover_containers) {
  EXPECT_TRUE(test_init_and_recover_containers(FLAGS_print_all));
}

// policy tests
TEST(test_claims_1, test_claims_1) {
  EXPECT_TRUE(test_claims_1(FLAGS_print_all));
}

TEST(signed_claims, test_signed_claims) {
  EXPECT_TRUE(test_signed_claims(FLAGS_print_all));
}

extern bool test__local_certify(string &, bool, string &, string &);
TEST(local_certify, test_local_certify) {
  string enclave_type("simulated-enclave");
  string evidence_descriptor("full-vse-support");
  EXPECT_TRUE(test__local_certify(enclave_type,
                                  FLAGS_read_measurement_file,
                                  FLAGS_trusted_measurements_file,
                                  evidence_descriptor));
}

TEST(local_certify, test_partial_local_certify) {
  string enclave_type("simulated-enclave");
  string evidence_descriptor("platform-attestation-only");
  EXPECT_TRUE(test__local_certify(enclave_type,
                                  FLAGS_read_measurement_file,
                                  FLAGS_trusted_measurements_file,
                                  evidence_descriptor));
}

extern bool test__new_local_certify(string &, bool, string &, string &);
TEST(local_certify, test_new_local_certify) {
  string enclave_type("simulated-enclave");
  string evidence_descriptor("full-vse-support");
  EXPECT_TRUE(test__new_local_certify(enclave_type,
                                      FLAGS_read_measurement_file,
                                      FLAGS_trusted_measurements_file,
                                      evidence_descriptor));
}

TEST(certify, test_certify_steps) {
  EXPECT_TRUE(test_certify_steps(FLAGS_print_all));
}

TEST(full_certification, test_full_certification) {
  EXPECT_TRUE(test_full_certification(FLAGS_print_all));
}

TEST(test_predicate_dominance, test_predicate_dominance) {
  EXPECT_TRUE(test_predicate_dominance(FLAGS_print_all));
}

// The following tests will only work if there is initialized
// policy data in test_data

TEST(test_x_509_chain, test_x_509_chain) {
  EXPECT_TRUE(test_x_509_chain(FLAGS_print_all));
}

TEST(test_x_509_sign, test_x_509_sign) {
  EXPECT_TRUE(test_x_509_sign(FLAGS_print_all));
}

// sev tests
#ifdef RUN_SEV_TESTS

TEST(test_sev_certs, test_sev_certs) {
  EXPECT_TRUE(test_sev_certs(FLAGS_print_all));
}

TEST(test_real_sev_certs, test_real_sev_certs) {
  EXPECT_TRUE(test_real_sev_certs(FLAGS_print_all));
}

TEST(test_sev_request, test_sev_request) {
  EXPECT_TRUE(test_sev_request(FLAGS_print_all));
}

TEST(test_sev, test_sev) {
  EXPECT_TRUE(test_sev(FLAGS_print_all));
}

extern bool test_sev_platform_certify(const bool    debug_print,
                                      const string &policy_file_name,
                                      const string &policy_key_file,
                                      const string &ark_key_file_name,
                                      const string &ask_key_file_name,
                                      const string &vcek_key_file_name,
                                      const string &ark_cert_file_name,
                                      const string &ask_cert_file_name,
                                      const string &vcek_cert_file_name);

TEST(platform_certify, test_platform_certify) {
  if (FLAGS_policy_file_name == "") {
    printf("sev-policy test skipped\n");
    EXPECT_TRUE(true);
  } else {
    EXPECT_TRUE(test_sev_platform_certify(FLAGS_print_all,
                                          FLAGS_policy_file_name,
                                          FLAGS_policy_key_file_name,
                                          FLAGS_ark_key_file_name,
                                          FLAGS_ask_key_file_name,
                                          FLAGS_vcek_key_file_name,
                                          FLAGS_ark_cert_file_name,
                                          FLAGS_ask_cert_file_name,
                                          FLAGS_vcek_cert_file_name));
  }
}
#endif  // RUN_SEV_TESTS

// -----------------------Run Tests-----------------------------

int main(int an, char **av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

#if 1
  extern bool simulator_init();
  if (!simulator_init()) {
    return 1;
  }
#else
  if (!simulated_Init(serialized_policy_cert_,
                      attest_key_file_name,
                      measurement_file_name,
                      attest_endorsement_file_name)) {
    printf("simulated_init failed\n");
    return false;
  }
#endif

  int result = RUN_ALL_TESTS();

  printf("\n");
  return result;
}
