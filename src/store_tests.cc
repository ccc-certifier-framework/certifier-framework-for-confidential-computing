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

#include "certifier.h"
#include "support.h"

using namespace certifier::framework;
using namespace certifier::utilities;

bool test_protect(bool print_all) {

  protected_blob_message pb;
  key_message key_start;
  key_message key_end;

  string enclave_type("simulated-enclave");
  string enclave_id("test-enclave");

  time_point t_nb;
  time_point t_na;
  string s_nb;
  string s_na;
  double hours_to_add = 365.0 * 24.0;

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

  const char* key_str = "I am a secret key. Dont tell anyone what I am or else. Here it is";
  const char* secret_data = "I am a secret data.  Protect me.";

  key_start.set_key_name("Test key");
  key_start.set_key_type("aes-256-cbc-hmac-sha256");
  key_start.set_key_format("vse-key");
  key_start.set_not_before(s_nb);
  key_start.set_not_after(s_na);
  key_start.set_secret_key_bits((void*)key_str, 64);

  // protect it
  int serialized_blob_size = 1024;
  byte serialized_blob[serialized_blob_size];
  memset(serialized_blob, 0, serialized_blob_size);

  if (print_all) {
    printf("Key header\n");
    print_key(key_start);
  }

  if (!Protect_Blob(enclave_type, key_start,
                    (int)strlen(secret_data), (byte*)secret_data,
                    &serialized_blob_size, serialized_blob)) {
    printf("Can't protect\n");
    return false;
  }

  string protected_blob_string;
  protected_blob_string.assign((char*)serialized_blob, serialized_blob_size);
  pb.ParseFromString(protected_blob_string);

  if (print_all) {
    printf("Protected blob\n");
    print_protected_blob(pb);
  }

  int size_unencrypted_data = 512;
  byte unencrypted_data[size_unencrypted_data];
  memset(unencrypted_data, 0, size_unencrypted_data);

  // unprotect it
  if (!Unprotect_Blob(enclave_type, serialized_blob_size, serialized_blob,
                      &key_end, &size_unencrypted_data, unencrypted_data)) {
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

  // Unprotect should return the key used for protecting the data
  if (!same_key(key_start, key_end))
    return false;

  // Unencrypted data should come out same as what was fed-in to protect
  if (memcmp(unencrypted_data, (byte*)secret_data, strlen(secret_data)) != 0)
    return false;

  key_message new_key; // ? RESOLVE: This is uninit'ed. Don't we want to supply a new key here?
  int size_reprotected_data = serialized_blob_size + 5;
  byte reprotected_data[size_reprotected_data];
  memset(reprotected_data, 0, size_reprotected_data);
  if (!Reprotect_Blob(enclave_type, &new_key, serialized_blob_size, serialized_blob,
                      &size_reprotected_data, reprotected_data)) {
    printf("Reprotect failed\n");
    return false;
  }

  // unprotect it
  key_message newer_key;
  int size_unencrypted_data2 = 512;
  byte unencrypted_data2[size_unencrypted_data2];
  memset(unencrypted_data2, 0, size_unencrypted_data2);
  if (!Unprotect_Blob(enclave_type, size_reprotected_data, reprotected_data,
                      &newer_key, &size_unencrypted_data2, unencrypted_data2)) {
    printf("Unprotect(2) failed\n");
    return false;
  }

  if (print_all) {
    printf("recovered key\n");
    print_key(newer_key);
    printf("recovered data(%d): ", size_unencrypted_data2);
    print_bytes(size_unencrypted_data2, unencrypted_data2);
    printf("\n");
  }
  if (memcmp(unencrypted_data2, (byte*)secret_data, strlen(secret_data)) != 0)
    return false;

  return true;
}

bool test_policy_store(bool print_all) {
  policy_store ps;

  key_message pk;
  if (!make_certifier_rsa_key(2048,  &pk))
    return false;

  // Upon a new Certifier's make, default policy key is still uninitialized
  const key_message* pkt = ps.get_policy_key();
  if (pkt != nullptr)
    return false;

  if (!ps.replace_policy_key(pk))
    return false;

  pkt = ps.get_policy_key();
  if (pkt == nullptr)
    return false;
  if (!same_key(pk, *pkt))
    return false;
  if (print_all) {
    printf("policy-key replace/get works\n");
  }

  key_message ak;
  if (!make_certifier_rsa_key(2048,  &ak))
    return false;
  string tag("first-authentication-key");
  if (!ps.add_authentication_key(tag, ak))
    return false;
  int lu = ps.get_authentication_key_index_by_tag(tag);
  if (lu < 0)
    return false;
  const key_message* akt = ps.get_authentication_key_by_index(lu);
  if (akt == nullptr)
    return false;
  if (!same_key(ak, *akt))
    return false;

  trusted_service_message tsm;
  tsm.set_trusted_service_address("http://mydata.com");
  string sm_tag("test_sm_tag");
  tsm.set_tag(sm_tag);
  key_message* tsk = new(key_message);
  if (!make_certifier_rsa_key(2048,  tsk))
    return false;
  tsm.set_allocated_trusted_service_key(tsk);
  if (!ps.add_trusted_service(tsm))
    return false;
  lu = ps.get_trusted_service_index_by_tag(sm_tag);
  if (lu < 0)
    return false;

  // Out-of-bounds index should be trapped correctly by lookup method
  const trusted_service_message* tsmt = ps.get_trusted_service_info_by_index(-1);
  if (tsmt != nullptr)
    return false;

  tsmt = ps.get_trusted_service_info_by_index(lu);
  if (tsmt == nullptr)
    return false;

  key_message k;
  if(!make_certifier_rsa_key(1024, &k))
    return false;
  key_message k1;
  if (!private_key_to_public_key(k, &k1))
    return false;
  entity_message e1;
  entity_message e2;
  if (!make_key_entity(k1, &e1))
    return false;
  extern string my_measurement;
  if (!make_measurement_entity(my_measurement, &e2))
    return false;
  vse_clause clause1;
  string s1("is-trusted");
  string s2("says");
  string s3("speaks-for");
  if (!make_unary_vse_clause((const entity_message)e1, s1, &clause1))
    return false;
  vse_clause clause2;
  if (!make_indirect_vse_clause((const entity_message)e1, s2, clause1, &clause2))
    return false;
  vse_clause clause3;
  if (!make_simple_vse_clause((const entity_message)e1, s3, (const entity_message)e2, &clause3))
    return false;

  if (print_all) {
    print_vse_clause(clause1); printf("\n");
    print_vse_clause(clause2); printf("\n");
    print_vse_clause(clause3); printf("\n");
  }

  claim_message full_claim;
  string serialized_claim;
  clause3.SerializeToString(&serialized_claim);
  string f1("vse-clause");
  string d1("basic speaks-for-claim");
  string nb("2021-08-01T05:09:50.000000Z");
  string na("2026-08-01T05:09:50.000000Z");
  if (!make_claim(serialized_claim.size(), (byte*)serialized_claim.data(), f1, d1,
                  nb, na, &full_claim))
    return false;
  string tc_tag("test-claim-tag");
  if (!ps.add_claim(tc_tag, full_claim))
    return false;
  lu = ps.get_claim_index_by_tag(tc_tag);
  if (lu < 0)
    return false;

  // Out-of-bounds index should be trapped correctly by lookup method
  const claim_message* fc = ps.get_claim_by_index(-1);
  if (fc != nullptr)
    return false;

  fc = ps.get_claim_by_index(lu);
  if (fc == nullptr)
    return false;

  byte t_bs1[3] = {
    1,2,3
  };
  string bs1;
  bs1.assign((char*)t_bs1, 3);
  string lab_s1("string-1");
  byte t_bs2[3] = {
    4,5,6
  };
  string bs2;
  bs2.assign((char*)t_bs2, 3);
  string lab_s2("string-2");

  // No blobs have been added, yet
  if (ps.get_num_blobs() != 0)
    return false;

  if (!ps.add_blob(lab_s1, bs1)) {
    return false;
  }
  if (!ps.add_blob(lab_s2, bs2)) {
    return false;
  }

  storage_info_message smi;
  string si_tag("test-si-tag");
  smi.set_tag(si_tag);
  smi.set_storage_type("amazon storage");
  smi.set_storage_descriptor("experimental data");
  smi.set_address("http://amazon.com/storage");
  key_message* sk = new(key_message);
  sk->set_key_name("amazon storage key");
  sk->set_key_type("aes-256-cbc-hmac-sha256");
  sk->set_key_format("vse-key");
  byte kkk[64];
  for (int i = 0; i < 64; i++)
    kkk[i]= (13*i)%16;
  sk->set_secret_key_bits((void*)kkk, 64);
  sk->set_not_before("2021-08-01T05:09:50.000000Z");
  sk->set_not_after("2026-08-01T05:09:50.000000Z");
  smi.set_allocated_storage_key(sk);

  // Not storage has been added, yet.
  if (ps.get_num_storage_info() != 0)
    return false;
  if (!ps.add_storage_info(smi))
    return false;
  lu = ps.get_storage_info_index_by_tag(si_tag);
  if (lu < 0)
    return false;

  // Out-of-bounds index should be trapped correctly by lookup method
  const storage_info_message* sim = ps.get_storage_info_by_index(-1);
  if (sim != nullptr)
    return false;

  sim = ps.get_storage_info_by_index(lu);
  if (sim == nullptr)
    return false;

  int nc = ps.get_num_claims();
  if (print_all) {
    printf("%d claims\n", nc);
    for (int i = 0; i < nc; i++) {
      const claim_message* cl = ps.get_claim_by_index(i);
      print_claim(*cl);
    }
    printf("\n");
  }

  int nsi = ps.get_num_storage_info();
  if (print_all) {
    printf("%d storage locations\n", nsi);
    for (int i = 0; i < nsi; i++) {
      const storage_info_message* si = ps.get_storage_info_by_index(i);
      print_storage_info(*si);
    }
    printf("\n");
  }

  int nt = ps.get_num_trusted_services();
  if (print_all) {
    printf("%d trusted locations\n", nt);
    for (int i = 0; i < nt; i++) {
      const trusted_service_message* tsm = ps.get_trusted_service_info_by_index(i);
      print_trusted_service_message(*tsm);
    }
    printf("\n");
  }

  // Out-of-bounds index should be trapped correctly by lookup method
  const string* tsbs = ps.get_blob_by_index(-1);
  if (tsbs != nullptr)
    return false;

  int ntb = ps.get_num_blobs();

  // Out-of-bounds index should be trapped correctly by lookup method
  tsbs = ps.get_blob_by_index(ntb + 1);
  if (tsbs != nullptr)
    return false;

  // Out-of-bounds index should be trapped correctly by lookup method
  const tagged_blob_message* tsb = ps.get_tagged_blob_info_by_index(-1);
  if (tsb != nullptr)
    return false;

  if (print_all) {
    printf("%d blobs\n", ntb);
    for (int i = 0; i < ntb; i++) {
      tsb = ps.get_tagged_blob_info_by_index(i);
      printf("blob %d, tag %s: ", i, tsb->tag().c_str());
      print_bytes(tsb->b().size(), (byte*)tsb->b().data());
      printf("\n");
    }
    printf("\n");
  }

  return true;
}

bool test_policy_store_signed_claims(bool print_all) {

  // Create a Policy store to test out APIs to manage up to 3 signed_claims
  policy_store * ps = new policy_store("aes-256-cbc-hmac-sha256",
                                       0, 3, 0, 0, 0, 0);

  if (ps->get_num_signed_claims() != 0)
    return false;

  // Adding up to 3 signed_claims should succeed
  string signed_claim_msg_tag1("claim_msg_tag1");
  signed_claim_message signed_claim1;
  if (!ps->add_signed_claim(signed_claim_msg_tag1, signed_claim1))
    return false;

  string signed_claim_msg_tag2("claim_msg_tag2");
  signed_claim_message signed_claim2;
  if (!ps->add_signed_claim(signed_claim_msg_tag2, signed_claim2))
    return false;

  string signed_claim_msg_tag3("claim_msg_tag3");
  signed_claim_message signed_claim3;
  if (!ps->add_signed_claim(signed_claim_msg_tag3, signed_claim3))
    return false;

  // This should fail as we have exceeded signed_claims capacity
  string signed_claim_msg_tag4("claim_msg_tag4");
  signed_claim_message signed_claim4;
  if (ps->add_signed_claim(signed_claim_msg_tag4, signed_claim4))
    return false;

  // Out-of-bounds index should be trapped correctly by lookup method
  const signed_claim_message* scm_out = ps->get_signed_claim_by_index(-1);
  if (scm_out != nullptr)
    return false;

  // Should return a valid index for a valid tag
  int index = ps->get_signed_claim_index_by_tag(signed_claim_msg_tag2);
  if (index < 0)
    return false;

  // Should return an invalid index for an invalid tag
  index = ps->get_signed_claim_index_by_tag(signed_claim_msg_tag4);
  if (index != -1)
    return false;

  return true;
}

bool test_init_and_recover_containers(bool print_all) {
  policy_store ps;

  // make up standard keys
  key_message policy_key;
  key_message policy_pk;
  if (!make_certifier_rsa_key(2048,  &policy_key))
    return false;
  policy_key.set_key_name("policy-key");
  policy_key.set_key_format("vse-key");
  if (!private_key_to_public_key(policy_key, &policy_pk))
    return false;
  if (!ps.replace_policy_key(policy_key))
    return false;
  string serialized_store;
  if (!ps.Serialize(&serialized_store))
    return false;

  key_message storage_key;
  int size_storage_key = 64;
  byte sk[size_storage_key];
  for (int i = 0; i < 64; i++)
    sk[i] = i % 16;
  storage_key.set_secret_key_bits((void*)sk, size_storage_key);
  time_point t_nb;
  time_point t_na;
  string s_nb;
  string s_na;
  double hours_to_add = 365.0 * 24.0;

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
  storage_key.set_key_type("aes-256-cbc-hmac-sha256");
  storage_key.set_key_format("vse-key");
  storage_key.set_not_before(s_nb);
  storage_key.set_not_after(s_na);
  storage_key.set_secret_key_bits((void*)sk, 64);

  key_message recovered_storage_key;

  string enclave_type("simulated-enclave");
  int size_encrypted = serialized_store.size() + 512;
  byte encrypted[size_encrypted];

  if (!Protect_Blob(enclave_type, storage_key,
                    serialized_store.size(), (byte*)serialized_store.data(),
                    &size_encrypted, encrypted))
    return false;
  int size_recovered = serialized_store.size() + 512;
  byte recovered[size_encrypted];
  if (!Unprotect_Blob(enclave_type, size_encrypted, encrypted,
                      &recovered_storage_key, &size_recovered, recovered))
    return false;

  string recovered_serialized_store;
  recovered_serialized_store.assign((char*)recovered, size_recovered);
  policy_store recovered_ps;
  if (!recovered_ps.Deserialize(recovered_serialized_store))
    return false;

  const key_message* recovered_policy_key= ps.get_policy_key();
  if (recovered_policy_key == nullptr)
    return false;
  if (!same_key(policy_key, *recovered_policy_key))
    return false;
  if (print_all) {
    printf("test_init_and_recover_containers succeeded\n");
  }
  return true;
}

