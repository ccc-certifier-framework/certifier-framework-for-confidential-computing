#include <gtest/gtest.h>
#include <gflags/gflags.h>

#include "certifier.h"
#include "support.h"
#include "simulated_enclave.h"

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
DEFINE_string(trusted_measurements_file, "binary_trusted_measurements_file.bin",  "binary_trusted_measurements_file");
DEFINE_bool(read_measurement_file, false,  "read measurement file");

DEFINE_string(platform_file_name, "platform_file.bin", "platform certificate");
DEFINE_string(platform_attest_endorsement, "platform_attest_endorsement.bin", "platform endorsement of attest key");
DEFINE_string(attest_key_file, "attest_key_file.bin", "attest key");
DEFINE_string(measurement_file, "example_app.measurement", "measurement");


// Encryption and support tests
extern bool test_digest(bool print_all);
TEST (test_digest, test_digest) {
  EXPECT_TRUE(test_digest(FLAGS_print_all));
}
extern bool test_encrypt(bool print_all);
TEST (test_encrypt, test_encrypt) {
  EXPECT_TRUE(test_encrypt(FLAGS_print_all));
}
extern bool test_authenticated_encrypt(bool print_all);
TEST (test_authenticated_encrypt, test_authenticated_encrypt) {
  EXPECT_TRUE(test_authenticated_encrypt(FLAGS_print_all));
}
extern bool test_public_keys(bool print_all);
TEST (public_keys, test_public_keys) {
  EXPECT_TRUE(test_public_keys(FLAGS_print_all));
}
extern bool test_sign_and_verify(bool print_all);
TEST (sign_and_verify, test_sign_and_verify) {
  EXPECT_TRUE(test_sign_and_verify(FLAGS_print_all));
}
extern bool test_key_translation(bool print_all);
TEST (key_translation, test_key_translation) {
  EXPECT_TRUE(test_key_translation(FLAGS_print_all));
}
extern bool test_time(bool print_all);
TEST (time, test_time) {
  EXPECT_TRUE(test_time(FLAGS_print_all));
}

// Basic Primitive tests
extern bool test_seal(bool print_all);
TEST (seal, test_seal) {
  EXPECT_TRUE(test_seal(FLAGS_print_all));
}
extern bool test_attest(bool print_all);
TEST (attest, test_attest) {
  EXPECT_TRUE(test_attest(FLAGS_print_all));
}

// Admission Tests
extern bool test_artifact(bool print_all);
TEST (artifact, test_artifact) {
  EXPECT_TRUE(test_artifact(FLAGS_print_all));
}

// File protection and store tests
extern bool test_protect(bool print_all);
TEST (protect, test_protect) {
  EXPECT_TRUE(test_protect(FLAGS_print_all));
}
extern bool test_policy_store(bool print_all);
TEST (policy_store, test_policy_store) {
  EXPECT_TRUE(test_policy_store(FLAGS_print_all));
}
extern bool test_init_and_recover_containers(bool print_all);
TEST (init_and_recover_containers, test_init_and_recover_containers) {
  EXPECT_TRUE(test_init_and_recover_containers(FLAGS_print_all));
}

// policy tests
extern bool test_claims_1(bool print_all);
TEST (test_claims_1, test_claims_1) {
  EXPECT_TRUE(test_claims_1(FLAGS_print_all));
}
extern bool test_signed_claims(bool print_all);
TEST (signed_claims, test_signed_claims) {
  EXPECT_TRUE(test_signed_claims(FLAGS_print_all));
}

extern bool test_local_certify(string&, bool, string&, string&);
TEST (local_certify, test_local_certify) {
  string enclave_type("simulated-enclave");
  string evidence_descriptor("full-vse-support");
  EXPECT_TRUE(test_local_certify(enclave_type, 
    FLAGS_read_measurement_file,
    FLAGS_trusted_measurements_file,
    evidence_descriptor));
}
TEST (local_certify, test_partial_local_certify) {
  string enclave_type("simulated-enclave");
  string evidence_descriptor("platform-attestation-only");
  EXPECT_TRUE(test_local_certify(enclave_type, 
    FLAGS_read_measurement_file,
    FLAGS_trusted_measurements_file,
    evidence_descriptor));
}
extern bool test_new_local_certify(string&, bool, string&, string&);
TEST (local_certify, test_new_local_certify) {
  string enclave_type("simulated-enclave");
  string evidence_descriptor("full-vse-support");
  EXPECT_TRUE(test_new_local_certify(enclave_type, 
    FLAGS_read_measurement_file,
    FLAGS_trusted_measurements_file,
    evidence_descriptor));
}

extern bool test_certify_steps(bool print_all);
TEST (certify, test_certify_steps) {
  EXPECT_TRUE(test_certify_steps(FLAGS_print_all));
}
extern bool test_full_certification(bool print_all);
TEST (full_certification, test_full_certification) {
  EXPECT_TRUE(test_full_certification(FLAGS_print_all));
}
extern bool test_predicate_dominance(bool print_all);
TEST (test_predicate_dominance, test_predicate_dominance) {
  EXPECT_TRUE(test_predicate_dominance(FLAGS_print_all));
}

// sev tests
#ifdef SEV_SNP
TEST (test_sev, test_sev) {
  EXPECT_TRUE(test_sev(FLAGS_print_all));
} 
#endif
// -----------------------Run Tests-----------------------------

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

#if 1
  extern bool simulator_init();
  if (!simulator_init()) {
    return 1;
  }
#else
  if (!simulated_Init(serialized_policy_cert_, attest_key_file_name, measurement_file_name,
          attest_endorsement_file_name)) {
    printf("simulated_init failed\n");
    return false;
  }
#endif

  int result = RUN_ALL_TESTS();

  printf("\n");
  return result;
}
