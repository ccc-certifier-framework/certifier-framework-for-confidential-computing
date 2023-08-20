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

#include "certifier.h"
#include "support.h"

using namespace certifier::framework;
using namespace certifier::utilities;

bool test_protect(bool print_all) {

  protected_blob_message pb;
  key_message            key_start;
  key_message            key_end;

  string enclave_type("simulated-enclave");
  string enclave_id("test-enclave");

  time_point t_nb;
  time_point t_na;
  string     s_nb;
  string     s_na;
  double     hours_to_add = 365.0 * 24.0;

  if (!time_now(&t_nb))
    return false;
  if (!time_to_string(t_nb, &s_nb))
    return false;
  if (!add_interval_to_time_point(t_nb, hours_to_add, &t_na))
    return false;

  if (!time_to_string(t_nb, &s_nb))
    return false;
  if (!time_to_string(t_na, &s_na))
    return false;

  const char *key_str =
      "I am a secret key. Dont tell anyone what I am or else. Here it is";
  const char *secret_data = "I am a secret data.  Protect me.";

  key_start.set_key_name("Test key");
  key_start.set_key_type(Enc_method_aes_256_cbc_hmac_sha256);
  key_start.set_key_format("vse-key");
  key_start.set_not_before(s_nb);
  key_start.set_not_after(s_na);
  key_start.set_secret_key_bits((void *)key_str, 64);

  // protect it
  int  serialized_blob_size = 1024;
  byte serialized_blob[serialized_blob_size];
  memset(serialized_blob, 0, serialized_blob_size);

  if (print_all) {
    printf("Key header\n");
    print_key(key_start);
  }

  if (!protect_blob(enclave_type,
                    key_start,
                    (int)strlen(secret_data),
                    (byte *)secret_data,
                    &serialized_blob_size,
                    serialized_blob)) {
    printf("Can't protect\n");
    return false;
  }

  string protected_blob_string;
  protected_blob_string.assign((char *)serialized_blob, serialized_blob_size);
  pb.ParseFromString(protected_blob_string);

  if (print_all) {
    printf("Protected blob\n");
    print_protected_blob(pb);
  }

  int  size_unencrypted_data = 512;
  byte unencrypted_data[size_unencrypted_data];
  memset(unencrypted_data, 0, size_unencrypted_data);

  // unprotect it
  if (!unprotect_blob(enclave_type,
                      serialized_blob_size,
                      serialized_blob,
                      &key_end,
                      &size_unencrypted_data,
                      unencrypted_data)) {
    printf("Unprotect(1) failed\n");
    return false;
  }

  if (print_all) {
    printf("recovered key\n");
    print_key(key_end);
    printf("recovered data(%d): ", size_unencrypted_data);
    print_bytes(size_unencrypted_data, unencrypted_data);
    printf("\n");
  }
  if (!same_key(key_start, key_end))
    return false;
  if (memcmp(unencrypted_data, (byte *)secret_data, strlen(secret_data)) != 0)
    return false;

  key_message new_key;
  int         size_reprotected_data = serialized_blob_size + 5;
  byte        reprotected_data[size_reprotected_data];
  memset(reprotected_data, 0, size_reprotected_data);
  if (!reprotect_blob(enclave_type,
                      &new_key,
                      serialized_blob_size,
                      serialized_blob,
                      &size_reprotected_data,
                      reprotected_data)) {
    printf("reprotect failed\n");
    return false;
  }

  // unprotect it
  key_message newer_key;
  int         size_unencrypted_data2 = 512;
  byte        unencrypted_data2[size_unencrypted_data2];
  memset(unencrypted_data2, 0, size_unencrypted_data2);
  if (!unprotect_blob(enclave_type,
                      size_reprotected_data,
                      reprotected_data,
                      &newer_key,
                      &size_unencrypted_data2,
                      unencrypted_data2)) {
    printf("unprotect(2) failed\n");
    return false;
  }

  if (print_all) {
    printf("recovered key\n");
    print_key(newer_key);
    printf("recovered data(%d): ", size_unencrypted_data2);
    print_bytes(size_unencrypted_data2, unencrypted_data2);
    printf("\n");
  }
  if (memcmp(unencrypted_data2, (byte *)secret_data, strlen(secret_data)) != 0)
    return false;

  return true;
}

bool test_init_and_recover_containers(bool print_all) {
  policy_store ps;

  // make up standard keys
  key_message policy_key;
  key_message policy_pk;
  if (!make_certifier_rsa_key(2048, &policy_key))
    return false;
  policy_key.set_key_name("policy-key");
  policy_key.set_key_format("vse-key");
  if (!private_key_to_public_key(policy_key, &policy_pk))
    return false;
  string serialized_store;
  if (!ps.Serialize(&serialized_store))
    return false;

  key_message storage_key;
  int         size_storage_key = 64;
  byte        sk[size_storage_key];
  for (int i = 0; i < 64; i++)
    sk[i] = i % 16;
  storage_key.set_secret_key_bits((void *)sk, size_storage_key);
  time_point t_nb;
  time_point t_na;
  string     s_nb;
  string     s_na;
  double     hours_to_add = 365.0 * 24.0;

  if (!time_now(&t_nb))
    return false;
  if (!time_to_string(t_nb, &s_nb))
    return false;
  if (!add_interval_to_time_point(t_nb, hours_to_add, &t_na))
    return false;

  if (!time_to_string(t_nb, &s_nb))
    return false;
  if (!time_to_string(t_na, &s_na))
    return false;
  storage_key.set_key_name("storage-key");
  storage_key.set_key_type(Enc_method_aes_256_cbc_hmac_sha256);
  storage_key.set_key_format("vse-key");
  storage_key.set_not_before(s_nb);
  storage_key.set_not_after(s_na);
  storage_key.set_secret_key_bits((void *)sk, 64);

  key_message recovered_storage_key;

  string enclave_type("simulated-enclave");
  int    size_encrypted = serialized_store.size() + 512;
  byte   encrypted[size_encrypted];

  if (!protect_blob(enclave_type,
                    storage_key,
                    serialized_store.size(),
                    (byte *)serialized_store.data(),
                    &size_encrypted,
                    encrypted))
    return false;
  int  size_recovered = serialized_store.size() + 512;
  byte recovered[size_encrypted];
  if (!unprotect_blob(enclave_type,
                      size_encrypted,
                      encrypted,
                      &recovered_storage_key,
                      &size_recovered,
                      recovered))
    return false;

  string recovered_serialized_store;
  recovered_serialized_store.assign((char *)recovered, size_recovered);
  policy_store recovered_ps;
  if (!recovered_ps.Deserialize(recovered_serialized_store))
    return false;

  return true;
}

bool test_policy_store(bool print_all) {
  policy_store ps(policy_store::MAX_NUM_ENTRIES);

  key_message pk;
  if (!make_certifier_rsa_key(2048, &pk))
    return false;

  time_point t_nb;
  if (!time_now(&t_nb))
    return false;
  string s_nb;
  if (!time_to_string(t_nb, &s_nb))
    return false;

  double     hours_to_add = 365.0 * 24.0;
  time_point t_na;
  if (!add_interval_to_time_point(t_nb, hours_to_add, &t_na))
    return false;
  string s_na;
  if (!time_to_string(t_na, &s_na))
    return false;

  pk.set_not_before(s_nb);
  pk.set_not_after(s_na);

  if (ps.get_num_entries() != 0) {
    printf("Error: policy-key store number of entries should be 0, but is %d\n",
           ps.get_num_entries());
    return false;
  }

  byte   bin[5] = {0, 1, 2, 3, 4};
  string tag1;
  string type1;
  string value1;

  tag1 = "test-entry-1";
  type1 = "binary";
  value1.assign((const char *)bin, sizeof(bin));
  if (!ps.update_or_insert(tag1, type1, value1)) {
    printf("Error:Can't add entry\n");
    return false;
  }

  tag1 = "test-entry-2";
  type1 = "binary";
  value1.assign((const char *)bin, sizeof(bin));
  if (!ps.update_or_insert(tag1, type1, value1)) {
    printf("Error:Can't add entry\n");
    return false;
  }

  tag1 = "test-entry-3";
  type1 = "binary";
  value1.assign((const char *)bin, sizeof(bin));
  if (!ps.update_or_insert(tag1, type1, value1)) {
    printf("Error: Can't update or insert entry\n");
    return false;
  }

  if (ps.get_num_entries() != 3) {
    printf("Error: policy-key store number of entries is %d should be 3\n",
           ps.get_num_entries());
    return false;
  }

  tag1 = "test-entry-2";
  type1 = "binary";
  int ent = ps.find_entry(tag1, type1);
  if (ent < 0) {
    printf("Error: can't find entry 2 by tag\n");
    return false;
  }

  ent = ps.find_entry(tag1, type1);
  if (ent < 0) {
    printf("Error: can't find entry 2 by tag and type\n");
    return false;
  }

  store_entry *p_ent = ps.get_entry(ent);
  if (p_ent == nullptr) {
    printf("Error: can't get entry pointer 1\n");
    return false;
  }

  if (p_ent->tag_ != tag1) {
    printf("Error: mismatched tags 1\n");
    return false;
  }
  if (p_ent->type_ != type1) {
    printf("Error: types 1\n");
    return false;
  }

  if (p_ent->value_.size() != sizeof(bin)
      || memcmp(bin, p_ent->value_.data(), sizeof(bin)) != 0) {
    printf("Error: Retrieved value failure\n");
    return false;
  }

  ps.delete_entry(1);
  if (ps.get_num_entries() != 2) {
    printf("Error: policy-key store number of entries should be 2 after "
           "deletion\n");
    return false;
  }

  string alg(Enc_method_aes_256);
  tag1 = "test-entry-4";
  type1 = "string";
  if (!ps.update_or_insert(tag1, type1, alg)) {
    printf("Error:Can't add entry\n");
    return false;
  }

  if (print_all) {
    ps.print();
  }

  string saved;
  if (!ps.Serialize(&saved)) {
    printf("Error: can't serialize\n");
    return false;
  }

  policy_store ps2;
  if (!ps2.Deserialize(saved)) {
    printf("Error: Can't Deserialize\n");
    return false;
  }
  if (ps2.get_num_entries() != ps.get_num_entries()) {
    printf("Error: Recovered stores don't match %d %d\n",
           ps.get_num_entries(),
           ps2.get_num_entries());
    return false;
  }
  if (ps2.max_num_ents_ != ps.max_num_ents_) {
    printf("Error: Recovered stores don't match (max ents) %d %d\n",
           ps.max_num_ents_,
           ps2.max_num_ents_);
    return false;
  }
  if (print_all) {
    ps2.print();
  }

  return true;
}
