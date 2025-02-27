// Copyright 2014-2025 John Manferdelli, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// File: test_acl.cc

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>

#include "acl.pb.h"
#include "acl_support.h"
#include "acl.h"
#include "acl_rpc.h"

DEFINE_bool(print_all, false, "Print intermediate test computations");

bool construct_sample_principals(principal_list* pl) {
  string p1("john");
  string p2("paul");
  string alg("none");
  string cred;
  if (!add_principal_to_proto_list(p1, alg, cred, pl)) {
    return false;
  }
  if (!add_principal_to_proto_list(p2, alg, cred, pl)) {
    return false;
  }
  return true;
}

bool construct_sample_resources(resource_list* rl) {
  string p1("john");
  string p2("paul");
  string r1("file_1");
  string r2("file_2");
  string l1("./tmp/file_1");
  string l2("./tmp/file_2");
  string t;
  string ty("file");
  time_point tp;

  if (!tp.time_now())
    return false;
  if (!tp.encode_time(&t))
    return false;
  if (!add_resource_to_proto_list(r1, ty, l1, t, t, rl)) {
    return false;
  }
  if (!add_resource_to_proto_list(r2, ty, l2, t, t, rl)) {
    return false;
  }
  if (!add_reader_to_resource_proto_list(p1, rl->mutable_resources(0)))
    return false;
  if (!add_reader_to_resource_proto_list(p2, rl->mutable_resources(1)))
    return false;
  if (!add_reader_to_resource_proto_list(p1, rl->mutable_resources(1)))
    return false;
  if (!add_writer_to_resource_proto_list(p1, rl->mutable_resources(0)))
    return false;
  if (!add_writer_to_resource_proto_list(p2, rl->mutable_resources(1)))
    return false;
  if (!add_writer_to_resource_proto_list(p1, rl->mutable_resources(1)))
    return false;
  if (!add_creator_to_resource_proto_list(p1, rl->mutable_resources(0)))
    return false;
  if (!add_creator_to_resource_proto_list(p2, rl->mutable_resources(1)))
    return false;
  return true;
}

bool make_keys_and_certs(string& root_issuer_name, string& root_issuer_org,
                         string& signing_subject_name, string& signing_subject_org,
                         key_message* root_key, key_message* signer_key,
                         buffer_list* list) {
  bool ret = true;

  key_message public_root_key;
  key_message public_signer_key;
  const char* alg= Enc_method_rsa_2048_sha256_pkcs_sign;

  RSA* r1 = nullptr;
  RSA* r2 = nullptr;
  X509* root_cert = nullptr;
  X509* signing_cert = nullptr;

  string root_asn1_cert_str;
  string signing_asn1_cert_str;

  uint64_t sn = 1;
  uint64_t duration = 86400 * 366;

  int sig_size= 256;
  byte sig[sig_size];
  string* ptr_str= nullptr;

  r1 = RSA_new();
  if (r1 == nullptr) {
    printf("%s() error, line: %d, cannt RSA_new \n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  if (!generate_new_rsa_key(2048, r1)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__, __LINE__);
    return false;
  }
  if (!RSA_to_key(r1, root_key)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  root_key->set_key_name("identity-root");
  if (FLAGS_print_all) {
    printf("root key:\n");
    print_key_message((const key_message)*root_key);
  }
  if (!private_key_to_public_key(*root_key, &public_root_key)) {
    printf("%s() error, line: %d, private_to_public failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  r2 = RSA_new();
  if (r2 == nullptr) {
    printf("%s() error, line: %d, cannt RSA_new \n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  if (!generate_new_rsa_key(2048, r2)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__, __LINE__);
    ret= false;
    goto done;
  }
  if (!RSA_to_key(r2, signer_key)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  signer_key->set_key_name("johns_signing-key");
  if (FLAGS_print_all) {
    printf("signing key:\n");
    print_key_message((const key_message&)*signer_key);
  }
  if (!private_key_to_public_key(*signer_key, &public_signer_key)) {
    printf("%s() error, line: %d, private_to_public failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  // root cert
  root_cert = X509_new();
  if (!produce_artifact(*root_key, root_issuer_name, root_issuer_org,
                        public_root_key, root_issuer_name, root_issuer_org,
                        sn, duration, root_cert, true)) {
    printf("%s() error, line %d: cant generate root cert\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  sn++;
  if (!x509_to_asn1(root_cert, &root_asn1_cert_str)) {
    printf("%s() error, line %d: cant asn1 translate root cert\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  // signing cert
  signing_cert = X509_new();
  if (!produce_artifact(*root_key, root_issuer_name, root_issuer_org,
                        public_signer_key, signing_subject_name, signing_subject_org,
                        sn, duration, signing_cert, false)) {
    printf("%s() error, line %d: cant generate signing cert\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  if (!x509_to_asn1(signing_cert, &signing_asn1_cert_str)) {
    printf("%s() error, line %d: cant asn1 translate signing cert\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  if (FLAGS_print_all) {
    printf("root cert:\n");
    X509_print_fp(stdout, root_cert);
    printf("\n");
    printf("signing cert:\n");
    X509_print_fp(stdout, signing_cert);
    printf("\n");
  }

  ptr_str = list->add_blobs();
  if (ptr_str == nullptr) {
    printf("%s() error, line %d: cant allocate blobs\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  *ptr_str = root_asn1_cert_str;
  ptr_str = list->add_blobs();
  if (ptr_str == nullptr) {
    printf("%s() error, line %d: cant allocate blobs\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  *ptr_str = signing_asn1_cert_str;

done:
  if (r1 != nullptr) {
    RSA_free(r1);
    r1 = nullptr;
  }
  if (r2 != nullptr) {
    RSA_free(r2);
    r2 = nullptr;
  }
  if (root_cert != nullptr) {
    X509_free(root_cert);
    root_cert = nullptr;
  }
  if (signing_cert != nullptr) {
    X509_free(signing_cert);
    signing_cert = nullptr;
  }
  return ret;
}

bool test_basic() {
  principal_list pl;
  resource_list rl;

  if (!construct_sample_principals(&pl)) {
    printf("Cant construct principals\n");
    return false;
  }
  if (!construct_sample_resources(&rl)) {
    printf("Cant construct resources\n");
    return false;
  }
  print_principal_list(pl);
  print_resource_list(rl);

  string p1("john");
  string p2("paul");
  string p3("tho");
  string r1("file_1");
  string r2("file_2");
  string r3("file_3");

  if (on_reader_list(rl.resources(0), p1) < 0) {
    printf("%s should be reader\n", p1.c_str());
    return false;
  }
  if (on_reader_list(rl.resources(1), p2) < 0) {
    printf("%s should be reader\n", p2.c_str());
    return false;
  }
  if (on_reader_list(rl.resources(0), p2) >= 0) {
    printf("%s should not be reader\n", p1.c_str());
    return false;
  }

  if (on_principal_list(p1, pl) < 0) {
    printf("%s should be on principal list\n", p1.c_str());
    return false;
  }
  if (on_resource_list(r1, rl) < 0) {
    printf("%s should be on resource list\n", r1.c_str());
    return false;
  }
  if (on_principal_list(p3, pl) >0 ) {
    printf("%s should NOT be on principal list\n", p3.c_str());
    return false;
  }
  if (on_resource_list(r3, rl) >0 ) {
    printf("%s should NOT be on resource list\n", r3.c_str());
    return false;
  }

  principal_list restored_pl;
  resource_list restored_rl;

  string prin_file("saved_principals.bin");
  if (!save_principals_to_file(pl, prin_file)) {
    printf("Can't save principals file\n");
    return false;
  }
  if (!get_principals_from_file(prin_file, &restored_pl)) {
    printf("Can't recover principals file\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("Restored principals file\n");
    print_principal_list(restored_pl);
  }

  string resource_file("saved_resource.bin");
  if (!save_resources_to_file(rl, resource_file)) {
    printf("Can't save resources file\n");
    return false;
  }
  if (!get_resources_from_file(resource_file, &restored_rl)) {
    printf("Can't recover resources file\n");
    return false;
  }
  if (FLAGS_print_all) {
    printf("Restored resources file\n");
    print_resource_list(restored_rl);
  }

  byte nonce[32];
  int n =  crypto_get_random_bytes(32, nonce);
  if(n < 32) {
    printf("Couldn't get nonce\n");
    return false;
  }
  printf("Nonce: ");
  print_bytes(n, nonce);
  printf("\n");

  return true;
}

bool test_access() {

  principal_list pl;
  resource_list rl;

  if (!construct_sample_principals(&pl)) {
    printf("Cant construct principals\n");
    return false;
  }
  if (!construct_sample_resources(&rl)) {
    printf("Cant construct resources\n");
    return false;
  }

  channel_guard guard;

  string channel_prin("john");
  string nonce;
  string signed_nonce;
  buffer_list credentials;
  key_message root_key;
  key_message signing_key;

  key_message public_root_key;
  key_message public_signing_key;
  const char* alg= Enc_method_rsa_2048_sha256_pkcs_sign;

  int size_nonce = 32;
  byte buf[size_nonce];
  int k = 0;
  X509* root_cert = nullptr;
  X509* signing_cert = nullptr;

  string root_issuer_name("johns-root");
  string root_issuer_org("datica");
  string root_asn1_cert_str;
  string signing_asn1_cert_str;
  string signing_subject_name("johns-signing-key");;
  string signing_subject_org("datica");
  string serialized_cert_chain_str;
  uint64_t sn = 1;

  EVP_PKEY* pkey = nullptr;
  RSA* r2 = nullptr;

  int sig_size= 256;
  byte sig[sig_size];
  bool ret = true;
  string res1("file_1");
  string acc1("read");
  string res2("file_2");
  string acc2("write");
  string* b;
  string prin_name("john");
  int i = 0;
  string dig_alg;
  string auth_alg(Enc_method_rsa_2048_sha256_pkcs_sign);
  string bytes_read;
  string bytes_written("Hello there");

  if (!make_keys_and_certs(root_issuer_name, root_issuer_org,
                         signing_subject_name, signing_subject_org,
                         &root_key, &signing_key, &credentials)) {
    printf("%s() error, line: %d: Can't make credentials\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  if (credentials.blobs_size() < 1) {
    printf("%s() error, line: %d: credentials wrong size\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  root_asn1_cert_str = credentials.blobs(0);

  if (!guard.init_root_cert(root_asn1_cert_str)) {
    printf("%s() error, line %d: cant init_root_cert\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  if (!credentials.SerializeToString(&serialized_cert_chain_str)) {
    printf("%s() error, line %d: cant serialize credentials\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  // put it on principal list
  for (i = 0; i < pl.principals_size(); i++) {
    if (pl.principals(i).principal_name() == prin_name) {
      pl.mutable_principals(i)->set_credential(serialized_cert_chain_str);
      pl.mutable_principals(i)->set_authentication_algorithm(auth_alg);
      break;
    }
  }
  if (i >= pl.principals_size()) {
    printf("%s() error, line %d: couldn't put credentials on principal list\n",
                    __func__, __LINE__);
    ret= false;
    goto done;
  }

  if (FLAGS_print_all) {
    printf("Prinicpals attached\n");
    print_principal_list(pl);
    printf("\n");
  }

  // construct nonce
  k = crypto_get_random_bytes(size_nonce, buf);
  if (k < size_nonce) {
    printf("%s() error, line %d: cant generate nonce\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  nonce.assign((char*)buf, k);

  if (!guard.load_resources(rl)) {
    printf("Cant load resource list\n");
    ret= false;
    goto done;
  }

  if (!guard.authenticate_me(channel_prin, pl, &nonce)) {
    printf("%s() error, line %d: Cant authenticate_me %s\n",
                    __func__, __LINE__, channel_prin.c_str());
    printf("Cant authenticate_me %s\n", channel_prin.c_str());
    ret= false;
    goto done;
  }

  // sign nonce
  if (strcmp(alg, Enc_method_rsa_2048_sha256_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_256;
  } else if (strcmp(alg, Enc_method_rsa_1024_sha256_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_256;
  } else if (strcmp(alg, Enc_method_rsa_3072_sha384_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_384;
  } else {
    printf("%s() error, line %d: unsupported rsa signing alg %s\n", __func__, __LINE__, alg);
    ret= false;
    goto done;
  }

  pkey = pkey_from_key(signing_key);
  if (pkey == nullptr) {
    printf("%s() error, line %d: Can't get pkey\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  r2 = EVP_PKEY_get1_RSA(pkey);
  if (r2 == nullptr) {
    printf("%s() error, line %d: Can't get rsa key\n", __func__, __LINE__);
    ret= false;
    goto done;
  } 

  // sign nonce
  if (!rsa_sign(dig_alg.c_str(), r2, nonce.size(), (byte*)nonce.data(), &sig_size, sig)) {
    printf("%s() error, line %d: sign failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  signed_nonce.assign((char*)sig, sig_size);

  if (!guard.verify_me(channel_prin, signed_nonce)) {
    printf("%s() error, line %d: verify_me %s failed\n", __func__, __LINE__, channel_prin.c_str());
    ret= false;
    goto done;
  }

  if (!guard.open_resource(res1, acc1)) {
    printf("%s() error, line %d: open_resource failed\n", __func__, __LINE__);
    return false;
  }
  if (guard.read_resource(res1, 14, &bytes_read)) {
    printf("open resource succeeded, %d bytes read\n", (int)bytes_read.size());
    printf("Received: %s\n", bytes_read.c_str());
  } else {
    printf("open reading resource failed\n");
    return false;
  }
  if (guard.close_resource(res1)) {
    printf("close resource succeeded\n");
  } else {
    printf("close reading resource failed\n");
    return false;
  }

  if (!guard.open_resource(res2, acc2)) {
    printf("open_resource for writing failed\n");
    return false;
  }
  if (guard.write_resource(res2, 12, bytes_written)) {
  } else {
    printf("write_resource failed\n");
    return false;
  }
  if (guard.close_resource(res2)) {
  } else {
    printf("close writing resource failed\n");
    return false;
  }

done:
#if 0
  if (r1 != nullptr) {
    RSA_free(r1);
    r1 = nullptr;
  }
  if (r2 != nullptr) {
    RSA_free(r2);
    r2 = nullptr;
  }
#endif
  if (root_cert != nullptr) {
    X509_free(root_cert);
    root_cert = nullptr;
  }
  if (signing_cert != nullptr) {
    X509_free(signing_cert);
    signing_cert = nullptr;
  }
  return ret;
}

bool test_random(bool print_all) {
  int  n = 128;
  byte out[n];

  memset(out, 0, n);
  int k = crypto_get_random_bytes(n, out);
  if (k < n) {
    printf("Couldn't get %d random bytes\n", n);
    return false;
  }

  if (print_all) {
    printf("Random bytes: ");
    print_bytes(n, out);
    printf("\n");
  }
  return true;
}

//  Test vectors
//    Input: "abc"
//    sha256: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61
//    f20015ad sha384: cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163
//    1a8b605a43ff5bed
//            8086072ba1e7cc23 58baeca134c825a7
//    sha512: ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2
//    0a9eeee64b55d39a
//            2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e
//            2a9ac94fa54ca49f

byte sha256_test[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

byte sha384_test[48] = {
    0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
    0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
    0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
    0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};

byte sha512_test[64] = {
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73,
    0x49, 0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9,
    0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21,
    0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23,
    0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8,
    0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f};

bool test_digest(bool print_all) {
  const char * message = "1234";
  int          msg_len = strlen(message);
  unsigned int size_digest = 64;
  byte         digest[size_digest];

  memset(digest, 0, size_digest);
  if (!digest_message(Digest_method_sha_256, (const byte *)message,
                      msg_len, digest, size_digest)) {
    printf("%s() error, line: %d, digest failed, %d\n",
           __func__, __LINE__, size_digest);
    return false;
  }
  if (print_all) {
    printf("SHA-256 message: ");
    print_bytes(msg_len, (byte *)message);
    printf("\n");
    printf("SHA-256 digest : ");
    print_bytes(32, digest);
    printf("\n");
  }

  // Verifier outputs
  const char *message2 = "abc";
  msg_len = 3;

  size_digest = (unsigned int)digest_output_byte_size(Digest_method_sha256);
  if (size_digest < 0) {
    printf("%s() error, line: %d, digest size failed, %d\n",
           __func__,
           __LINE__,
           size_digest);
    return false;
  }
  memset(digest, 0, size_digest);
  if (!digest_message(Digest_method_sha_256, (const byte *)message2, msg_len,
                      digest, size_digest)) {
    printf("%s() error, line: %d, digest_message() failed\n",
           __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("\nSHA-256 message: ");
    print_bytes(msg_len, (byte *)message2);
    printf("\n");
    printf("SHA-256 digest : ");
    print_bytes((int)size_digest, digest);
    printf("\n");
  }
  if (memcmp(digest, sha256_test, size_digest) != 0) {
    printf("%s() error, line: %d, test digest doesn't match\n",
           __func__, __LINE__);
    return false;
  }

  size_digest = (unsigned int)digest_output_byte_size(Digest_method_sha_384);
  if (size_digest < 0) {
    printf("%s() error, line: %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }
  memset(digest, 0, size_digest);
  if (!digest_message(Digest_method_sha_384, (const byte *)message2, msg_len,
                      digest, size_digest)) {
    printf("%s() error, line: %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("SHA-384 message: ");
    print_bytes(msg_len, (byte *)message2);
    printf("\n");
    printf("SHA-384 digest : ");
    print_bytes((int)size_digest, digest);
    printf("\n");
  }
  if (memcmp(digest, sha384_test, size_digest) != 0) {
    printf("%s() error, line: %d, memcmp failed\n", __func__, __LINE__);
    return false;
  }

  size_digest = (unsigned int)digest_output_byte_size(Digest_method_sha_512);
  if (size_digest < 0) {
    printf("%s() error, line: %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }
  memset(digest, 0, size_digest); if (!digest_message(Digest_method_sha_512, (const byte *)message2,
                      msg_len, digest, size_digest)) {
    printf("%s() error, line: %d, digest_message failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("SHA-512 message: ");
    print_bytes(msg_len, (byte *)message2);
    printf("\n");
    printf("SHA-512 digest : ");
    print_bytes((int)size_digest, digest);
    printf("\n");
  }
  if (memcmp(digest, sha512_test, size_digest) != 0) {
    printf("%s() error, line: %d, memcmp failed\n", __func__, __LINE__);
    return false;
  }

  return true;
}


bool test_encrypt(bool print_all) {
  const char *alg_name = Enc_method_aes_256_cbc_hmac_sha256;
  int block_size = cipher_block_byte_size(alg_name);
  int key_size = cipher_key_byte_size(alg_name);
  int in_size = 2 * block_size;
  int out_size = in_size + 128;

  byte key[key_size];
  const int iv_size = block_size;
  byte iv[block_size];
  byte plain[in_size];
  byte cipher[out_size];
  int decrypt_size = in_size + block_size;
  byte decrypted[decrypt_size];
  int  size1 = in_size;
  int  size2 = decrypt_size;

  memset(plain, 0, in_size);
  memset(cipher, 0, out_size);
  memset(key, 0, key_size);
  memset(iv, 0, iv_size);
  memset(decrypted, 0, in_size);

  for (int i = 0; i < key_size; i++)
    key[i] = (byte)(i % 16);
  for (int i = 0; i < block_size; i++)
    iv[i] = (byte)(i % 16);
  const char *msg = "this is a message of length 32.";
  memcpy(plain, (byte *)msg, 32);

  if (print_all) {
    printf("input: ");
    print_bytes(in_size, plain);
    printf("\n");
  }
  if (!encrypt(plain, in_size, key, iv, cipher, &size1)) {
    printf("%s() error, line: %d, encrypt failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("encrypt succeeded, in_size: %d, out_size is %d\n", in_size, size1);
    printf("iv: ");
    print_bytes(block_size, iv);
    printf("\n");
    printf("cipher: ");
    print_bytes(size2, cipher);
    printf("\n");
  }
  if (!decrypt(cipher, size1, key, iv, decrypted, &size2)) {
    printf("%s() error, line: %d, decrypt failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("decrypt succeeded, out_size is %d\n", size2);
    printf("decrypted: ");
    print_bytes(size2, decrypted);
    printf("\n");
  }
  if (size2 != in_size || memcmp(plain, decrypted, in_size) != 0) {
    printf("comparison failed\n");
    printf("%s() error, line: %d, comparison failed\n", __func__, __LINE__);
    return false;
  }
  return true;
}

bool test_authenticated_encrypt(bool print_all) {
  const char *alg_name = Enc_method_aes_256_cbc_hmac_sha256;
  int block_size = cipher_block_byte_size(alg_name);
  int in_size = 2 * block_size;
  int out_size = in_size + 256;
  int key_size = 96;
  byte key[key_size];
  int iv_size = block_size;
  byte iv[block_size];
  byte plain[in_size];
  byte cipher[out_size];
  int  size_encrypt_out = out_size;
  int  size_decrypt_out = out_size;

  const int decrypt_size = in_size + block_size;
  byte decrypted[decrypt_size];

  memset(plain, 0, in_size);
  memset(cipher, 0, out_size);
  memset(key, 0, key_size);
  memset(iv, 0, iv_size);
  memset(decrypted, 0, decrypt_size);

  for (int i = 0; i < key_size; i++)
    key[i] = (byte)(i % 16);

  for (int i = 0; i < block_size; i++)
    iv[i] = (byte)(i % 16);
  const char *msg = "this is a message of length 32.";
  memcpy(plain, (byte *)msg, 32);

  if (print_all) {
    printf("\nAuthenticated encryption\n");
    printf("input: ");
    print_bytes(in_size, plain);
    printf("\n");
  }

  if (!authenticated_encrypt(alg_name, plain, in_size,
                             key, key_size, iv, iv_size, cipher, &size_encrypt_out)) {
    printf("%s() error, line: %d, authenticated encrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("authenticated encrypt for aes-256-cbc-hmac-sha256 succeeded, "
           "in_size: %d, out_size is %d\n", in_size, size_encrypt_out);
    printf("iv: ");
    print_bytes(block_size, iv);
    printf("\n");
    printf("cipher: ");
    print_bytes(size_encrypt_out, cipher);
    printf("\n");
  }
  if (!authenticated_decrypt(Enc_method_aes_256_cbc_hmac_sha256, cipher, size_encrypt_out,
                             key, key_size, decrypted, &size_decrypt_out)) {
    printf("%s() error, line: %d, authenticated decrypt failed\n",
           __func__, __LINE__);
    return false;
  }

  if (print_all) {
    printf("authenticated decrypt for aes-256-cbc-hmac-sha256 succeeded, "
           "out_size is %d\n",
           size_decrypt_out);
    printf("decrypted: ");
    print_bytes(size_decrypt_out, decrypted);
    printf("\n");
    printf("\n");
  }
  if (size_decrypt_out != in_size || memcmp(plain, decrypted, in_size) != 0) {
    printf("%s() error, line: %d, comparisonfailed\n", __func__, __LINE__);
    return false;
  }

  size_encrypt_out = out_size;
  size_decrypt_out = out_size;
  int size_in = 32;
  if (print_all) {
    printf("\nAuthenticated encryption\n");
    printf("input: ");
    print_bytes(in_size, plain);
    printf("\n");
  }

  if (!authenticated_encrypt(Enc_method_aes_256_cbc_hmac_sha384, plain, in_size,
                             key, key_size, iv, iv_size, cipher, &size_encrypt_out)) {
    printf("%s() error, line: %d, authenticated encrypt failed\n",
           __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("authenticated encrypt for aes-256-cbc-hmac-sha384 succeeded, "
           "in_size: %d, out_size is %d\n", in_size, size_encrypt_out);
    printf("iv: ");
    print_bytes(block_size, iv);
    printf("\n");
    printf("cipher: ");
    print_bytes(size_encrypt_out, cipher);
    printf("\n");
  }
  if (!authenticated_decrypt(Enc_method_aes_256_cbc_hmac_sha384, cipher, size_encrypt_out,
                             key, key_size, decrypted, &size_decrypt_out)) {
    printf("%s() error, line: %d, authenticated decrypt failed\n",
           __func__, __LINE__);
    return false;
  }

  if (print_all) {
    printf("authenticated decrypt for aes-256-cbc-hmac-sha384 succeeded, "
           "out_size is %d\n",
           size_decrypt_out);
    printf("decrypted: ");
    print_bytes(size_decrypt_out, decrypted);
    printf("\n");
    printf("\n");
  }
  if (size_decrypt_out != size_in || memcmp(plain, decrypted, size_in) != 0) {
    printf("%s() error, line: %d, plaintext and decrypted text are different\n",
           __func__, __LINE__);
    return false;
  }

  size_encrypt_out = out_size;
  size_decrypt_out = out_size;

  if (!authenticated_encrypt(Enc_method_aes_256_gcm, plain, in_size, key,
                             key_size, iv, iv_size, cipher, &size_encrypt_out)) {
    printf("%s() error, line: %d, authenticated_encrypt() for aes-256-gcm "
           "encrypt failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("authenticated encrypt for aes-256-gcm succeeded, in_size: %d, "
           "out_size is %d\n",
           in_size,
           size_encrypt_out);
    printf("iv: ");
    print_bytes(block_size, iv);
    printf("\n");
    printf("cipher: ");
    print_bytes(size_encrypt_out, cipher);
    printf("\n");
  }
  if (!authenticated_decrypt(Enc_method_aes_256_gcm, cipher, size_encrypt_out, key,
                             key_size, decrypted, &size_decrypt_out)) {
    printf(
        "%s() error, line: %d, authenticated for aes-256-gcm decrypt failed\n",
        __func__,
        __LINE__);
    return false;
  }

  if (print_all) {
    printf("authenticated decrypt for aes-256-gcm succeeded, out_size is %d\n",
           size_decrypt_out);
    printf("decrypted: ");
    print_bytes(size_decrypt_out, decrypted);
    printf("\n");
    printf("\n");
  }
  if (size_decrypt_out != size_in || memcmp(plain, decrypted, size_in) != 0) {
    printf("%s() error, line: %d, comparison failed\n", __func__, __LINE__);
    return false;
  }

  return true;
}

bool test_public_keys(bool print_all) {

  RSA *r1 = RSA_new();

  if (!generate_new_rsa_key(2048, r1)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__, __LINE__);
    return false;
  }

  key_message km1;
  if (!RSA_to_key(r1, &km1)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    print_key_message((const key_message &)km1);
  }

  const char* msg = "This is a message of length 32  ";
  int size_data = 32;
  byte data[size_data];
  int  size_out = 2048;
  byte out[size_out];
  int  size_recovered = 2048;
  byte recovered[size_recovered];

  memset(data, 0, size_data);
  memset(out, 0, size_out);
  memset(recovered, 0, size_recovered);
  memcpy(data, (byte *)msg, size_data);

  if (print_all) {
    printf("public to encrypt: ");
    print_bytes(size_data, data);
    printf("\n");
  }
  if (!rsa_public_encrypt(r1, data, size_data, out, &size_out)) {
    printf("%s() error, line: %d, rsa_public_encrypt failed\n",
           __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("public encrypted: ");
    print_bytes(size_out, out);
    printf("\n");
  }
  if (!rsa_private_decrypt(r1, out, size_out, recovered, &size_recovered)) {
    printf("%s() error, line: %d, rsa_private_decrypt failed\n",
           __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("public recovered: ");
    print_bytes(size_recovered, recovered);
    printf("\n");
  }
  RSA_free(r1);
  if (memcmp(data, recovered, size_recovered) != 0) {
    printf("%s() error, line: %d, memcmpfailed\n", __func__, __LINE__);
    return false;
  }

  RSA *r2 = RSA_new();
  if (!generate_new_rsa_key(4096, r2)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__, __LINE__);
    return false;
  }

  size_out = 2048;
  size_recovered = 2048;
  key_message km2;
  if (!RSA_to_key(r2, &km2)) {
    printf("RSA_to_key failed\n");
    return false;
  }
  if (print_all) {
    printf("\n");
    print_key_message((const key_message &)km2);
  }

  memset(data, 0, size_data);
  memset(out, 0, size_out);
  memset(recovered, 0, size_recovered);
  memcpy(data, (byte *)msg, size_data);

  if (print_all) {
    printf("public to encrypt: ");
    print_bytes(size_data, data);
    printf("\n");
  }
  if (!rsa_public_encrypt(r2, data, size_data, out, &size_out)) {
    printf("%s() error, line: %d, rsa_public_encrypt failed\n",
           __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("public encrypted: ");
    print_bytes(size_out, out);
    printf("\n");
  }
  if (!rsa_private_decrypt(r2, out, size_out, recovered, &size_recovered)) {
    printf("%s() error, line: %d, rsa_private_decrypt failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (print_all) {
    printf("public recovered: ");
    print_bytes(size_recovered, recovered);
    printf("\n");
  }
  RSA_free(r2);
  if (memcmp(data, recovered, size_recovered) != 0) {
    printf("%s() error, line: %d, memcmp failed\n", __func__, __LINE__);
    return false;
  }

  // ECC
  size_out = 2048;
  size_recovered = 2048;
  EC_KEY *ecc_key = generate_new_ecc_key(384);
  if (ecc_key == nullptr) {
    printf("%s() error, line: %d, Can't generate new ecc key failed\n",
           __func__,
           __LINE__);
    return false;
  }
  key_message km3;
  if (!ECC_to_key(ecc_key, &km3)) {
    printf("%s() error, line: %d, ECC_to_key failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    printf("\n");
    print_key_message((const key_message &)km3);
  }
  if (print_all) {
    printf("public to encrypt: ");
    print_bytes(size_data, data);
    printf("\n");
  }
  if (!ecc_sign(Digest_method_sha_384, ecc_key, size_data, data,
                &size_out, out)) {
    printf("ecc_sign failed\n");
    printf("Sig size: %d\n", size_out);
    return false;
  }
  if (print_all) {
    printf("ecc sign out    : ");
    print_bytes(size_out, out);
    printf("\n");
  }
  if (!ecc_verify(Digest_method_sha_384, ecc_key, size_data,
                  data, size_out, out)) {
    printf("%s() error, line: %d, ecc verify failed\n", __func__, __LINE__);
    return false;
  }

  key_message priv_km;
  key_message pub_km;
  if (!ECC_to_key(ecc_key, &priv_km)) {
    printf("%s() error, line: %d, ECC_to_key failed\n", __func__, __LINE__);
    return false;
  }

  priv_km.set_key_name("test-key");
  priv_km.set_key_type(Enc_method_ecc_384_private);
  if (print_all) {
    printf("Key:\n");
    print_key_message(priv_km);
    printf("\n");
  }

  if (!private_key_to_public_key(priv_km, &pub_km)) {
    printf("%s() error, line: %d, ECC private_key_to_public_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  if (print_all) {
    printf("Key:\n");
    print_key_message(pub_km);
    printf("\n");

    printf("Descriptor: ");
    print_key_descriptor(pub_km);
    printf("\n");
  }

  EC_KEY_free(ecc_key);

  size_out = 2048;
  size_recovered = 2048;
  memset(data, 0, size_data);
  memset(out, 0, size_out);
  memset(recovered, 0, size_recovered);
  memcpy(data, (byte *)msg, size_data);

  EC_KEY *ecc_key2 = generate_new_ecc_key(256);
  if (ecc_key2 == nullptr) {
    printf("%s() error, line: %d, Can't generate new ecc key\n",
           __func__, __LINE__);
    return false;
  }
  key_message km4;
  if (!ECC_to_key(ecc_key2, &km4)) {
    printf("Can't ECC to key\n");
    return false;
  }
  if (print_all) {
    printf("\n");
    print_key_message((const key_message &)km4);
  }

  if (print_all) {
    printf("public to encrypt: ");
    print_bytes(size_data, data);
    printf("\n");
  }
  if (!ecc_sign(Digest_method_sha_256, ecc_key2, size_data, data,
                &size_out, out)) {
    printf("%s() error, line: %d, ecc_sign failed, size: %d\n",
           __func__,
           __LINE__,
           size_out);
    return false;
  }
  if (print_all) {
    printf("ecc sign out %d : ", size_out);
    print_bytes(size_out, out);
    printf("\n");
  }
#if 1
  // TODO: sometimes this faults
  if (!ecc_verify(Digest_method_sha_256, ecc_key, size_data,
                  data, size_out, out)) {
    printf("%s() error, line: %d, ecc_verify failed\n", __func__, __LINE__);
    return false;
  }
#endif

  key_message priv_km2;
  key_message pub_km2;
  if (!ECC_to_key(ecc_key2, &priv_km2)) {
    printf("%s() error, line: %d, ECC_to_key failed\n", __func__, __LINE__);
    return false;
  }

  priv_km2.set_key_name("test-key");
  priv_km2.set_key_type(Enc_method_ecc_256_private);
  if (print_all) {
    printf("Key:\n");
    print_key_message(priv_km2);
    printf("\n");
  }

  if (!private_key_to_public_key(priv_km2, &pub_km2)) {
    printf("%s() error, line: %d, ECC private_key_to_public_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  if (print_all) {
    printf("Key:\n");
    print_key_message(pub_km2);
    printf("\n");

    printf("Descriptor: ");
    print_key_descriptor(pub_km2);
    printf("\n");
  }

  EC_KEY_free(ecc_key2);
  return true;
}

bool test_sign_and_verify(bool print_all) {
  RSA *r = RSA_new();

  if (!generate_new_rsa_key(2048, r)) {
    printf("%s() error, line: %d, generate_new_rsa_key failed\n",
           __func__, __LINE__);
    return false;
  }

  key_message km;
  if (!RSA_to_key(r, &km)) {
    printf("%s() error, line: %d, RSA_to_key failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    print_key_message((const key_message &)km);
  }

  const char *test_message = "I am a test message, verify me";

  int  sig_size = RSA_size(r);
  byte sig[sig_size];
  int  recovered_size = sig_size;
  byte recovered[recovered_size];
  memset(sig, 0, sig_size);
  memset(recovered, 0, recovered_size);

  if (!rsa_sha256_sign(r, strlen(test_message), (byte *)test_message,
                       &sig_size, sig)) {
    printf("%s() error, line: %d, rsa_sha256_sign failed\n",
           __func__, __LINE__);
    return false;
  }
  if (!rsa_sha256_verify(r, strlen(test_message), (byte *)test_message,
                         sig_size, sig)) {
    printf("%s() error, line: %d, rsa_sha256_verify failed\n",
           __func__, __LINE__);
    return false;
  }

  RSA_free(r);
  return true;
}

bool test_key_translation(bool print_all) {
  key_message k1;

  if (!make_certifier_rsa_key(2048, &k1)) {
    printf("%s() error, line: %d, make_certifier_rsa_key failed\n",
           __func__,
           __LINE__);
    return false;
  }

  RSA *r2 = RSA_new();
  if (!key_to_RSA(k1, r2)) {
    printf("%s() error, line: %d, key_to_RSA failed\n", __func__, __LINE__);
    return false;
  }
  if (print_all) {
    int nb = RSA_bits(r2);
    printf("BITS: %d\n", nb);
  }
  key_message k2;
  RSA_to_key(r2, &k2);
  RSA_free(r2);
  if (!same_key(k1, k2)) {
    printf("%s() error, line: %d, same_key failed\n", __func__, __LINE__);
    return false;
  }

  key_message k3;
  if (!make_certifier_rsa_key(2048, &k3)) {
    printf("%s() error, line: %d, make_certifier_rsa_key failed\n",
           __func__,
           __LINE__);
    return false;
  }
  if (same_key(k1, k3)) {
    printf("%s() error, line: %d, same_key failed\n", __func__, __LINE__);
    return false;
  }
  return true;
}

bool test_artifact(bool print_all) {
  X509* cert = X509_new();
  key_message signing_key;
  key_message subject_key;
  string issuer_name_str("Policy-key");  // eventually serialized key
  string issuer_description_str("Policy-key");
  string enclave_type("simulated-enclave");

  string subject_name_str("JLM");
  if (print_all)
    printf("Subject name: %s\n", subject_name_str.c_str());
  string subject_description_str("writer");

  double   secs_duration = 60.0 * 60.0 * 24.0 * 365.0;
  uint64_t sn = 1;

  if (!make_certifier_rsa_key(2048, &signing_key)) {
    printf("Cant make signing key\n");
    return false;
  }
  if (!make_certifier_rsa_key(2048, &subject_key)) {
    printf("Cant make subject key\n");
    return false;
  }
  if (!produce_artifact(signing_key, issuer_name_str, issuer_description_str,
                        subject_key, subject_name_str, subject_description_str, sn,
                        secs_duration, cert, true)) {
    printf("Cant produce artifact\n");
    return false;
  }

  if (print_all)
    X509_print_fp(stdout, cert);

  uint64_t recovered_sn;
  string recovered_subject_name_str;
  string recovered_issuer_name_str;
  string recovered_subject_description_str;
  string recovered_issuer_description_str;
  key_message recovered_subject_key;
  if (!verify_artifact(*cert, signing_key, &recovered_issuer_name_str, &recovered_issuer_description_str,
                       &recovered_subject_key, &recovered_subject_name_str, &recovered_subject_description_str,
                       &recovered_sn)) {
    printf("Cant verify artifact\n");
    return false;
  }
  if (print_all)
    printf("Recovered subject name: %s\n", recovered_subject_name_str.c_str());
  return true;
}

bool test_signed_nonce() {
  bool ret = true;

  string root_issuer_name("johns-root");
  string root_issuer_org("datica");
  string signing_subject_name("johns-signing-key");
  string signing_subject_org("datica");

  buffer_list list;
  string nonce;
  string signed_nonce;

  // make up keys and certs
  key_message root_key;
  key_message signing_key ;
  const char* alg= Enc_method_rsa_2048_sha256_pkcs_sign;
  EVP_PKEY* pkey = nullptr;
  RSA* r2 = nullptr;

  int size_nonce = 32;
  byte buf[size_nonce];
  int size_sig = 512;
  byte sig[size_sig];
  int k = 0;
  string dig_alg;

  if (!make_keys_and_certs(root_issuer_name, root_issuer_org,
                         signing_subject_name, signing_subject_org,
                         &root_key, &signing_key, &list)) {
    printf("%s() error, line %d: cant make keys and certs\n", __func__, __LINE__);
    ret= false;
    goto done;

  }

  // construct nonce
  k = crypto_get_random_bytes(size_nonce, buf);
  if (k < size_nonce) {
    printf("%s() error, line %d: cant generate nonce\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  nonce.assign((char*)buf, k);

  if (strcmp(alg, Enc_method_rsa_2048_sha256_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_256;
  } else if (strcmp(alg, Enc_method_rsa_1024_sha256_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_256;
  } else if (strcmp(alg, Enc_method_rsa_3072_sha384_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_384;
  } else {
    printf("%s() error, line %d: unsupported rsa signing alg %s\n", __func__, __LINE__, alg);
    ret= false;
    goto done;
  }

  pkey = pkey_from_key(signing_key);
  if (pkey == nullptr) {
    printf("%s() error, line %d: Can't get pkey\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  r2 = EVP_PKEY_get1_RSA(pkey);
  if (r2 == nullptr) {
    printf("%s() error, line %d: Can't get rsa key\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  // sign nonce
  if (!rsa_sign(dig_alg.c_str(), r2, nonce.size(), (byte*)nonce.data(), &size_sig, sig)) {
    printf("%s() error, line %d: sign failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  // verify it
  if (!rsa_verify(dig_alg.c_str(), r2, nonce.size(), (byte*)nonce.data(), size_sig, sig)) {
    printf("%s() error, line %d: verify failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

done:
  if (pkey != nullptr) {
    EVP_PKEY_free(pkey);
    pkey= nullptr;
  }
  return ret;
}

bool test_crypto() {
  if (!test_random(FLAGS_print_all)) {
    printf("test_random failed\n");
    return false;
  }
  if (!test_digest(FLAGS_print_all)) {
    printf("test_digest failed\n");
    return false;
  }
  if (!test_encrypt(FLAGS_print_all)) {
    printf("test_encrypt failed\n");
    return false;
  }
  if (!test_authenticated_encrypt(FLAGS_print_all)) {
    printf("test_authenticated_encrypt failed\n");
    return false;
  }
  if (!test_public_keys(FLAGS_print_all)) {
    printf("test_public_keys failed\n");
    return false;
  }
  if (!test_sign_and_verify(FLAGS_print_all)) {
    printf("test_sign_and_verify failed\n");
    return false;
  }
  if (!test_key_translation(FLAGS_print_all)) {
    printf("test_key_translation failed\n");
    return false;
  }
  if (!test_artifact(FLAGS_print_all)) {
    printf("test_artifact failed\n");
    return false;
  }
  if (!test_signed_nonce()) {
    printf("test_signed_nonce failed\n");
    return false;
  }
  return true;
}

#if 1
acl_server_dispatch g_server(nullptr);
#endif

bool test_rpc() {

  string signing_subject_name("johns-signing-key");
  string signing_subject_org("datica");
  string root_issuer_name("johns-root");
  string root_issuer_org("datica");
  buffer_list credentials;
  key_message root_key;
  key_message signing_key;
  key_message public_root_key;
  key_message public_signing_key;
  const char* alg= Enc_method_rsa_2048_sha256_pkcs_sign;
  EVP_PKEY* pkey = nullptr;
  RSA* r2 = nullptr;
  string serialized_cert_chain_str;

  principal_list pl;
  resource_list rl;

  SSL* ch = nullptr;
  acl_client_dispatch client(ch);

  string prin_name("john");
  string res1_name("file_1");
  string res2_name("file_2");
  string acc1("read");
  string acc2("write");

  string nonce;
  string signed_nonce;

  string bytes_read_from_file;
  string bytes_written_to_file("Hello there");
    
  int size_nonce = 32;
  byte buf[size_nonce];
  int size_sig = 512;
  byte sig[size_sig];
  int k = 0;
  int i = 0;
  string dig_alg;
  string asn1_cert_str;
  string auth_alg(Enc_method_rsa_2048_sha256_pkcs_sign);

  bool ret = true;

#ifndef TEST_SIMULATED_CHANNEL
  printf("test_rpc does not run without TEST_SIMULATED_CHANNEL\n");
  return true;
#endif

  if (!construct_sample_principals(&pl)) {
    printf("%s() error, line %d: Cant construct principals\n",
           __func__, __LINE__);
    return false;
  }
  if (!construct_sample_resources(&rl)) {
    printf("%s() error, line %d: Cant construct resources\n",
           __func__, __LINE__);
    return false;
  }

  if (!g_server.guard_.load_resources(rl)) {
    printf("%s() error, line %d: Cant load resources\n",
           __func__, __LINE__);
    return false;
  }

  // make up keys and certs
  if (!make_keys_and_certs(root_issuer_name, root_issuer_org,
                         signing_subject_name, signing_subject_org,
                         &root_key, &signing_key, &credentials)) {
    printf("%s() error, line %d: cant make keys and certs\n", __func__, __LINE__);
    return false;
  } 

  if (credentials.blobs_size() < 1) {
    printf("%s() error, line %d: cant find root in credentials\n", __func__, __LINE__);
    return false;
  }
  asn1_cert_str= credentials.blobs(0);

  if (!g_server.guard_.init_root_cert(asn1_cert_str)) {
    printf("%s() error, line %d: Can't init_root\n", __func__, __LINE__);
    return false;
  }

    if (!credentials.SerializeToString(&serialized_cert_chain_str)) {
    printf("%s() error, line %d: cant serialize credentials\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  // put it on principal list
  for (i = 0; i < pl.principals_size(); i++) {
    if (pl.principals(i).principal_name() == prin_name) {
      pl.mutable_principals(i)->set_credential(serialized_cert_chain_str);
      pl.mutable_principals(i)->set_authentication_algorithm(auth_alg);
      break;
    }
  }
  if (i >= pl.principals_size()) {
    printf("%s() error, line %d: couldn't put credentials on principal list\n",
                    __func__, __LINE__);
    ret= false;
    goto done;
  }

  if (FLAGS_print_all) {
    printf("Prinicpals attached\n");
    print_principal_list(pl);
    printf("\n");
  }

  if (!g_server.load_principals(pl)) {
    printf("%s() error, line %d: Cant load principals\n",
           __func__, __LINE__);
    return false;
  }

  if (!g_server.load_resources(rl)) {
    printf("%s() error, line %d: Cant load resources\n",
           __func__, __LINE__);
    return false;
  }

  ret = client.rpc_authenticate_me(prin_name, &nonce);
  if (!ret) {
    printf("%s() error, line %d: client.rpc_authenticate_me failed\n",
           __func__, __LINE__);
    return false;
  }

  // sign nonce
  if (strcmp(alg, Enc_method_rsa_2048_sha256_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_256;
  } else if (strcmp(alg, Enc_method_rsa_1024_sha256_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_256;
  } else if (strcmp(alg, Enc_method_rsa_3072_sha384_pkcs_sign) == 0) {
    dig_alg = Digest_method_sha_384;
  } else {
    printf("%s() error, line %d: unsupported rsa signing alg %s\n", __func__, __LINE__, alg);
    ret= false;
    goto done;
  }

  pkey = pkey_from_key(signing_key);
  if (pkey == nullptr) {
    printf("%s() error, line %d: Can't get pkey\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  r2 = EVP_PKEY_get1_RSA(pkey);
  if (r2 == nullptr) {
    printf("%s() error, line %d: Can't get rsa key\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  // sign nonce
  if (!rsa_sign(dig_alg.c_str(), r2, nonce.size(), (byte*)nonce.data(), &size_sig, sig)) {
    printf("%s() error, line %d: sign failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  signed_nonce.assign((char*)sig, size_sig);

  ret = client.rpc_verify_me(prin_name, signed_nonce);
  if (!ret) {
    printf("%s() error, line %d: rpc_verify_me failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  ret = client.rpc_open_resource(res1_name, acc1);
  if (!ret) {
    printf("%s() error, line %d: rpc_open_resource failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  ret = client.rpc_read_resource(res1_name, 14, &bytes_read_from_file);
  if (!ret) {
    printf("%s() error, line %d: rpc_read_resource failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  printf("Bytes: %s\n", bytes_read_from_file.c_str());

  ret = client.rpc_close_resource(res1_name);
  if (!ret) {
    printf("%s() error, line %d: rpc_close_resource failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  ret = client.rpc_open_resource(res2_name, acc2);
  if (!ret) {
    printf("%s() error, line %d: rpc_open_resource failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  ret = client.rpc_write_resource(res2_name, bytes_written_to_file);
  if (!ret) {
    printf("%s() error, line %d: rpc_write_resource failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  ret = client.rpc_close_resource(res2_name);
  if (!ret) {
    printf("%s() error, line %d: rpc_close_resource failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

done:
  if (pkey != nullptr) {
    EVP_PKEY_free(pkey);
    pkey = nullptr; 
  }
  return ret;
}

TEST (basic, test_basic) {
  EXPECT_TRUE(test_basic());
}

TEST (crypto, test_crypto) {
  EXPECT_TRUE(test_crypto());
}

TEST (access, test_access) {
  EXPECT_TRUE(test_access());
}

TEST (rpc, test_rpc) {
  EXPECT_TRUE(test_rpc());
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (!init_crypto()) {
    printf("Couldn't init crypto\n");
    return 1;
  }

  int result = RUN_ALL_TESTS();

  close_crypto();

  return result;
}

