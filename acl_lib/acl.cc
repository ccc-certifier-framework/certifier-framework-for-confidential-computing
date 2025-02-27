// Copyright 2014-2020 John Manferdelli, All Rights Reserved.
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
// File: acl.cc

#include "stdio.h"
#include <unistd.h>
#include "sys/fcntl.h"
#include "sys/stat.h"

#include "acl_support.h"
#include "acl.h"

// -----------------------------------------------------------------------------

void print_principal_message(const principal_message& pi) {
  if (pi.has_principal_name())
      printf("Principal: %s\n", pi.principal_name().c_str());
  if (pi.has_authentication_algorithm())
      printf("Authentication algorithm: %s\n", pi.authentication_algorithm().c_str());
  if (pi.has_credential()) {
    printf("Credential: ");
    print_bytes((int)pi.credential().size(), (byte*)pi.credential().data());
    printf("\n");
  }
}

void print_audit_info(const audit_info& inf) {
}

void print_resource_message(const resource_message& rm) {
  printf("\n");
  if (rm.has_resource_identifier())
    printf("Resource: %s\n", rm.resource_identifier().c_str());
  if (rm.has_resource_type())
    printf("Resource type: %s\n", rm.resource_type().c_str());
  if (rm.has_resource_location())
    printf("Resource location: %s\n", rm.resource_location().c_str());
  if (rm.has_time_created())
    printf("Created: %s\n", rm.time_created().c_str());
  if (rm.has_time_last_written())
        printf("Written: %s\n", rm.time_last_written().c_str());
  if (rm.has_resource_key()) {
    print_key_message(rm.resource_key());
  }
  if (rm.has_log()) {
    print_audit_info(rm.log());
  }
  printf("Readers\n");
  for (int i = 0; i < rm.readers_size(); i++) {
    printf("  %s\n", rm.readers(i).c_str());
  }
  printf("Writers\n");
  for (int i = 0; i < rm.writers_size(); i++) {
    printf("  %s\n", rm.writers(i).c_str());
  }
  printf("Deleters\n");
  for (int i = 0; i < rm.deleters_size(); i++) {
    printf("  %s\n", rm.deleters(i).c_str());
  }
  printf("Creators\n");
  for (int i = 0; i < rm.creators_size(); i++) {
    printf("  %s\n", rm.creators(i).c_str());
  }
  printf("\n");
}

void print_principal_list(const principal_list& pl) {
  printf("Principals\n");
  for (int i = 0; i < pl.principals_size(); i++) {
    print_principal_message(pl.principals(i));
  }
  printf("\n");
}

void print_resource_list(const resource_list& rl) {
  printf("Resources\n");
  for (int i = 0; i < rl.resources_size(); i++) {
    print_resource_message(rl.resources(i));
  }
  printf("\n");
}

bool get_resources_from_file(string& file_name, resource_list* rl) {
  string serialized_rl;

  // read file into serialized_rl
  if (!read_file_into_string(file_name, &serialized_rl)) {
    printf("Cant read resource file %s\n", file_name.c_str());
    return false;
  }
  
  return rl->ParseFromString(serialized_rl);
}

bool get_principals_from_file(string& file_name, principal_list* pl) {
  string serialized_pl;
  // read file into serialized_pl
  if (!read_file_into_string(file_name, &serialized_pl)) {
    printf("Cant read principal file %s\n", file_name.c_str());
    return false;
  }
  return pl->ParseFromString(serialized_pl);
}

bool save_resources_to_file(resource_list& rl, string& file_name) {
  string serialized_rl;
  if (!rl.SerializeToString(&serialized_rl)) {
    printf("Cant serialize resource list\n");
    return false;
  }
  if (!write_file_from_string(file_name, serialized_rl)) {
    printf("Cant read resource file %s\n", file_name.c_str());
    return false;
  }
  return true;
}

bool save_principals_to_file(principal_list& pl, string& file_name) {
  string serialized_pl;
  if (!pl.SerializeToString(&serialized_pl)) {
    printf("Cant serialize principals list\n");
    return false;
  }
  // write file
  if (!write_file_from_string(file_name, serialized_pl)) {
    printf("Cant write principals file %s\n", file_name.c_str());
    return false;
  }
  return true;
}

int on_reader_list(const resource_message& r, const string& name) {
  for (int i = 0; i < r.readers_size(); i++) {
    if (r.readers(i) == name)
      return i;
  }
  return -1;
}

int on_writer_list(const resource_message& r, const string& name) {
  for (int i = 0; i < r.writers_size(); i++) {
    if (r.writers(i) == name)
      return i;
  }
  return -1;
}

int on_deleter_list(const resource_message& r, const string& name) {
  for (int i = 0; i < r.deleters_size(); i++) {
    if (r.deleters(i) == name)
      return i;
  }
  return -1;
}

int on_creator_list(const resource_message& r, const string& name) {
  for (int i = 0; i < r.creators_size(); i++) {
    if (r.creators(i) == name)
      return i;
  }
  return -1;
}

int on_principal_list(const string& name, principal_list& pl) {
  for (int i = 0; i < pl.principals_size(); i++) {
    if (pl.principals(i).principal_name() == name)
      return i;
  }
  return -1;
}

int on_resource_list(const string& name, resource_list& rl) {
  for (int i = 0; i < rl.resources_size(); i++) {
    if (rl.resources(i).resource_identifier() == name)
      return i;
  }
  return -1;
}

bool add_reader_to_resource_proto_list(const string& prin_name, resource_message* r) {
  if (on_reader_list(*r, prin_name) >= 0)
    return false;
  string* ns = r->add_readers();
  *ns = prin_name;
  return true;
}

bool add_writer_to_resource_proto_list(const string& name, resource_message* r) {
  if (on_writer_list(*r, name) >= 0)
    return false;
  string* ns = r->add_writers();
  *ns = name;
  return true;
}

bool add_deleter_to_resource_proto_list(const string& name, resource_message* r) {
  if (on_deleter_list(*r, name) >= 0)
    return false;
  string* ns = r->add_deleters();
  *ns = name;
  return true;
}

bool add_creator_to_resource_proto_list(const string& name, resource_message* r) {
  if (on_creator_list(*r, name) >= 0)
    return false;
  string* ns = r->add_creators();
  *ns = name;
  return true;
}

bool add_principal_to_proto_list(const string& name, const string& alg,
                const string& cred, principal_list* pl) {
  principal_message* pm = pl->add_principals();
  pm->set_principal_name(name);
  pm->set_authentication_algorithm(alg);
  pm->set_credential(cred);
  return true;
}

bool add_resource_to_proto_list(const string& id, const string& type,
                const string& locat, const string& t_created, const string& t_written,
                resource_list* rl) {
  resource_message* rm = rl->add_resources();
  rm->set_resource_identifier(id);
  rm->set_resource_type(type);
  rm->set_resource_location(locat);
  rm->set_time_created(t_created);
  rm->set_time_last_written(t_written);
  return true;
}

bool sign_nonce(string& nonce, key_message& k, string* signature) {
  return false;
}

channel_guard::channel_guard() {
  channel_principal_authenticated_= false;
  capacity_resources_ = 0;
  num_resources_ = 0;
  resources_= nullptr;
  num_active_resources_= 0;
  capacity_active_resources_ = max_active_resources;
  root_cert_ = nullptr;
}

channel_guard::~channel_guard() {
}

void channel_guard::print() {
  printf("Principal name: %s\n", principal_name_.c_str());
  printf("Authentication algorithm: %s\n", authentication_algorithm_name_.c_str());
  // byte* creds_;
  if (channel_principal_authenticated_) {
    printf("Principal authenticated\n");
  } else {
    printf("Principal not authenticated\n");
  }
  printf("Number of resources: %d\n", num_resources_);
  if (resources_ == nullptr)
    return;
  for (int i = 0; i <num_resources_; i++) {
    print_resource_message(resources_[i]);
  }
}

bool channel_guard::init_root_cert(const string& asn1_cert_str) {
  root_cert_ = X509_new();
  if (root_cert_ == nullptr) {
    printf("%s() error, line %d: sign failed\n", __func__, __LINE__);
    return false;
  }
  if (!asn1_to_x509(asn1_cert_str, root_cert_)) {
    printf("%s() error, line %d: asn1_to_x509 failed\n", __func__, __LINE__);
    return false;
  }
  return true;
}

bool channel_guard::authenticate_me(const string& name, principal_list& pl, string* nonce) {
  int i = 0;
  for (i = 0; i < pl.principals_size(); i++) {
    if (name == pl.principals(i).principal_name()) {
      principal_name_= pl.principals(i).principal_name();
      authentication_algorithm_name_= pl.principals(i).authentication_algorithm();
      creds_.assign(pl.principals(i).credential());
      break;
    }
  }
  if (i >= pl.principals_size()) {
    printf("%s() error, line %d: Can't find principal %s\n", __func__, __LINE__, name.c_str());
    return false;
  }
  const int size_nonce = 32;
  byte buf[32];
  int k = crypto_get_random_bytes(size_nonce, buf);
  if (k < size_nonce) {
    printf("%s() error, line %d: cant generate nonce\n", __func__, __LINE__);
    return false;
  }
  nonce_.assign((char*)buf, k);
  nonce->assign((char*)buf, k);

  return true;
}

bool channel_guard::verify_me(const string& name, const string& signed_nonce) {

  if (root_cert_ == nullptr) {
    printf("%s() error, line: %d, root_cert_ is null\n", __func__, __LINE__);
    return false;
  }

  bool ret = true;
  string cred_buffer_list_str;
  buffer_list list;
  X509* signing_cert = nullptr;
  EVP_PKEY *subject_pkey = nullptr;
  string subj_cert_str;

  if (!list.ParseFromString(cred_buffer_list_str)) {
    printf("%s() error, line: %d, ParseFromString failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  cred_buffer_list_str.assign((char*)creds_.data(), creds_.size());
  if (!list.ParseFromString(cred_buffer_list_str)) {
    printf("%s() error, line: %d, can't parse credentials\n", __func__,__LINE__);
    ret= false;
    goto done;
  }
  if (list.blobs_size() <= 0) {
    printf("%s() error, line: %d, cred blobs is empty\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  if (!verify_cert_chain(root_cert_, list)) {
    printf("%s() error, line: %d, verify_cert_chain failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  // check signature
  subj_cert_str.assign((char*)list.blobs(list.blobs_size() - 1).data(),
                       list.blobs(list.blobs_size() - 1).size());
  signing_cert = X509_new();
  if (signing_cert == nullptr) {
    printf("%s() error, line: %d, X509_new failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }
  if (!asn1_to_x509(subj_cert_str, signing_cert)) {
    printf("%s() error, line: %d, asn1_to_x509 failed\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  subject_pkey = X509_get_pubkey(signing_cert);
  if (subject_pkey == nullptr) {
    printf("%s() error, line: %d, Can't get public key from cert\n", __func__, __LINE__);
    ret= false;
    goto done;
  }

  if (strcmp(authentication_algorithm_name_.c_str(), Enc_method_rsa_1024_sha256_pkcs_sign) == 0 ||
      strcmp(authentication_algorithm_name_.c_str(), Enc_method_rsa_2048_sha256_pkcs_sign) == 0 ) {
   // verify it
     RSA *rsa_key = EVP_PKEY_get1_RSA(subject_pkey);
     if (rsa_key == nullptr) {
      printf("%s() error, line %d: EVP_PKEY_get1_RSA failed\n", __func__, __LINE__);
      ret= false;
      goto done;
     }
     // free rsa key?
     if (!rsa_verify(Digest_method_sha_256, rsa_key, nonce_.size(), (byte*)nonce_.data(),
                    signed_nonce.size(), (byte*) signed_nonce.data())) {
      printf("%s() error, line %d: verify failed\n", __func__, __LINE__);
      ret= false;
      goto done;
      }
    } else if (strcmp(authentication_algorithm_name_.c_str(), Enc_method_rsa_3072_sha384_pkcs_sign) == 0) {
      RSA *rsa_key = EVP_PKEY_get1_RSA(subject_pkey);;
     if (rsa_key == nullptr) {
      printf("%s() error, line %d: EVP_PKEY_get1_RSA failed\n", __func__, __LINE__);
      ret= false;
      goto done;
     }
      if (!rsa_verify(Digest_method_sha_384, rsa_key, nonce_.size(), (byte*)nonce_.data(),
                    signed_nonce.size(), (byte*)signed_nonce.data())) {
      printf("%s() error, line %d: verify failed\n", __func__, __LINE__);
      ret= false;
      goto done;
      }
    } else {
      printf("%s() error, line: %d, unsupported signing algorithm %s\n",
             __func__, __LINE__, authentication_algorithm_name_.c_str());
      ret= false;
      goto done;
    }

done:
  channel_principal_authenticated_= ret;
  if (signing_cert != nullptr) {
    X509_free(signing_cert);
    signing_cert = nullptr;
  }
  if (subject_pkey != nullptr) {
    EVP_PKEY_free(subject_pkey);
    subject_pkey= nullptr;
  }
  return ret;
}

bool channel_guard::load_resources(resource_list& rl) {
  num_resources_ = rl.resources_size();
  capacity_resources_ = 2 * (num_resources_ + 10);
  resources_= new resource_message[capacity_resources_];
  if (resources_ == nullptr) {
    num_resources_ = 0;
    resources_ = nullptr;
  }
  for (int i = 0; i < num_resources_; i++) {
    resources_[i].CopyFrom(rl.resources(i));
  }
  return true;
}

active_resource::active_resource() {
  desc_ = -1;;
  rights_= 0;

}

active_resource::~active_resource() {
}


// We have to be careful that resource names are unique and not
// subject to spoofing by creators making up a resources with
// an existing name to avoid authentication.
bool channel_guard::can_read(int resource_entry) {
  if (!channel_principal_authenticated_) {
    return false;
  }
  // see if principal_name_ is on reader list
  for (int j = 0; j < resources_[resource_entry].readers_size(); j++) {
    if (resources_[resource_entry].readers(j) == principal_name_) {
      return true;
    }
  }
  return false;
}

bool channel_guard::can_write(int resource_entry) {
  if (!channel_principal_authenticated_) {
    return false;
  }
  for (int j = 0; j < resources_[resource_entry].writers_size(); j++) {
    if (resources_[resource_entry].writers(j) == principal_name_) {
      return true;
    }
  }
  return false;
}

bool channel_guard::can_delete(int resource_entry) {
  if (!channel_principal_authenticated_) {
    return false;
  }
  // see if principal_name_ is on deleters list
  for (int j = 0; j < resources_[resource_entry].deleters_size(); j++) {
    if (resources_[resource_entry].deleters(j) == principal_name_) {
      return true;
    }
  }
  return false;
}

bool channel_guard::can_create(int resource_entry) {
  if (!channel_principal_authenticated_) {
    return false;
  }
  for (int j = 0; j < resources_[resource_entry].creators_size(); j++) {
    if (resources_[resource_entry].creators(j) == principal_name_) {
      return true;
    }
  }
  return false;
}

int channel_guard::find_resource(const string& name) {
  for (int i = 0; i < num_resources_; i++) {
    if (name == resources_[i].resource_identifier()) {
      return i;
    }
  }
  return -1;
}

bool channel_guard::access_check(int resource_entry, const string& action) {
  if (!channel_principal_authenticated_) {
    printf("access_check: nauthenticated\n");
    return false;
  }
  if (action == "read") {
    if (can_read(resource_entry)) {
      return true;
    }
  }
  if (action == "write") {
    if (can_write(resource_entry)) {
      return true;
    }
  }
  if (action == "delete") {
    if (can_delete(resource_entry)) {
      return true;
    }
  }
  if (action == "create") {
    if (can_create(resource_entry)) {
      return true;
    }
  }
  return false;
}

bool accept_credentials(const string& principal_name, const string& alg, const string& cred, principal_list* pl) {
  principal_message pm;
  pm.set_principal_name(principal_name);
  pm.set_authentication_algorithm(alg);
  pm.set_credential(cred);
  return add_principal_to_proto_list(principal_name, alg, cred, pl);
}

bool channel_guard::add_access_rights(string& resource_name, string& right, string& new_prin) {
  // can current channel principal add access rights to this resource?
  int n = find_resource(resource_name);
  if (n < 0) {
    printf("%s() error, line: %d: No such resource\n",
            __func__, __LINE__);
    return false;
  }
  // already there?
  return false;
}

int channel_guard::find_in_active_resource_table(const string& name) {
  for (int i = 0; i < num_active_resources_; i++) {
    if (ar_[i].resource_name_ == name && ar_[i].principal_name_ == principal_name_)
      return i;
  }
  return -1;
}

bool channel_guard::create_resource(string& name) {
  // make up encryption key
  // automatically give creator read, write, delete rights
  return false;
}

bool channel_guard::open_resource(const string& resource_name, const string& access_mode) {
  string file_type("file");

  int resource_index = find_resource(resource_name);
  if (resource_index < 0) {
    printf("%s() error, line: %d: No such resource %s\n",
            __func__, __LINE__, resource_name.c_str());
    return false;
  }
  if (resources_[resource_index].resource_type() != file_type) {
    printf("%s() error, line: %d: only file types supported\n",
            __func__, __LINE__);
    return false;
  }
  if (!access_check(resource_index, access_mode)) {
    printf("%s() error, line: %d: access failure\n",
            __func__, __LINE__);
    return false;
  }

  unsigned requested_right = 0;
  if (access_mode == "read") {
    requested_right |= active_resource::READ;
  } else if (access_mode == "write") {
    requested_right |= active_resource::WRITE;
  } else {
      printf("%s() error, line: %d: unknown access mode\n",
             __func__, __LINE__);
      return false;
  }

  int resource_entry = -1;
  for (int i = 0; i < num_active_resources_; i++) {
      if (ar_[i].principal_name_ == principal_name_ &&
          ar_[i].resource_name_ == resource_name) {
        if (ar_[i].rights_ == requested_right)
          resource_entry = i;
      }
  }
  if (resource_entry < 0) {
    if (num_active_resources_ >= capacity_active_resources_) {
      printf("%s() error, line: %d: number of active resources exceeded\n",
            __func__, __LINE__);
      return false;
    }
    resource_entry = num_active_resources_++;
    ar_[resource_entry].principal_name_ = principal_name_;
    ar_[resource_entry].resource_name_ = resource_name;
    ar_[resource_entry].rights_ |= requested_right;
  }

  // open, set descriptor
  if (ar_[resource_entry].desc_ >= 0) {
    printf("%s() error, line: %d: resource already open\n",
            __func__, __LINE__);
    return false;
  }

  // note that if file doesn't exist, we create it which isn't right
  // principal should have create right on parent directory but we don't
  // support directories yet.
  string file_name;
  file_name = resources_[resource_index].resource_location();
  switch(requested_right) {
    case active_resource::READ:
      // open for reading
      ar_[resource_entry].desc_ = open(file_name.c_str(), O_RDONLY);
      return true;
    case active_resource::WRITE:
      // open for writing
      ar_[resource_entry].desc_ = open(file_name.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
      return true;
    default:
      return false;
  }

  return true;
}

bool channel_guard::read_resource(const string& resource_name, int n, string* out) {
  int rn = find_in_active_resource_table(resource_name);
  if (rn < 0) {
    return false;
  }
  if (ar_[rn].desc_ >= 0) {
    byte buf[n];
    int k = read(ar_[rn].desc_, buf, n);
    if (k < 0)
      return false;
    out->assign((char*)buf, k);
    return true;
  }
  return false;
}

bool channel_guard::write_resource(const string& resource_name, int n, string& in) {
  int rn = find_in_active_resource_table(resource_name);
  if (rn < 0) {
    return false;
  }
  if (ar_[rn].desc_ >= 0) {
    int k = write(ar_[rn].desc_, (byte*)in.data(), in.size());
    if (k < 0)
      return false;
    return true;
  }
  return false;
}

bool channel_guard::delete_resource(const string& resource_name) {
  return false;
}

bool channel_guard::close_resource(const string& resource_name) {
  int rn = find_in_active_resource_table(resource_name);
  if (rn < 0) {
    return false;
  }
  if (ar_[rn].desc_ >= 0) {
    close(ar_[rn].desc_);
    ar_[rn].desc_ = -1;
    return true;
  }
  return false;
}

bool channel_guard::save_active_resources(const string& file_name) {
  // should be database, eventually
  return false;
}

int find_resource_in_resource_proto_list(const resource_list& rl, const string& name) {
  for (int i = 0; i < rl.resources_size(); i++) {
    if (rl.resources(i).resource_identifier() == name)
      return i;
  }
  return -1;
}

int find_principal_in_principal_proto_list(const principal_list& pl, const string& name) {
  for (int i = 0; i < pl.principals_size(); i++) {
    if (pl.principals(i).principal_name() == name)
      return i;
  }
  return -1;
}

// -----------------------------------------------------------------------
