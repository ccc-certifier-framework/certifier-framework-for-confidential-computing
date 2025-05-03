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

#include "certifier.pb.h"
#include "support.h"
#include "certifier.h"
#include "support.h"
#include "acl.pb.h"
#include "acl_support.h"
#include "acl.h"

using namespace certifier::framework;
using namespace certifier::utilities;


namespace certifier {
namespace acl_lib {


extern resource_list       g_rl;
extern principal_list      g_pl;
extern acl_principal_table g_principal_table;
extern acl_resource_table  g_resource_table;
extern bool                g_identity_root_initialized;
extern string              g_identity_root;
extern string              g_signature_algorithm;
extern X509               *g_x509_identity_root;


// -----------------------------------------------------------------------------

void print_principal_message(const principal_message &pi) {
  if (pi.has_principal_name())
    printf("Principal: %s\n", pi.principal_name().c_str());
  if (pi.has_authentication_algorithm())
    printf("Authentication algorithm: %s\n",
           pi.authentication_algorithm().c_str());
  if (pi.has_credential()) {
    printf("Credential: ");
    print_bytes((int)pi.credential().size(), (byte *)pi.credential().data());
    printf("\n");
  }
}

void print_audit_info(const audit_info &inf) {}

void print_resource_message(const resource_message &rm) {
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
    print_key(rm.resource_key());
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

void print_principal_list(const principal_list &pl) {
  printf("Principals\n");
  for (int i = 0; i < pl.principals_size(); i++) {
    print_principal_message(pl.principals(i));
  }
  printf("\n");
}

void print_resource_list(const resource_list &rl) {
  printf("Resources\n");
  for (int i = 0; i < rl.resources_size(); i++) {
    print_resource_message(rl.resources(i));
  }
  printf("\n");
}

bool get_resources_from_file(string &file_name, resource_list *rl) {
  string serialized_rl;

  // read file into serialized_rl
  if (!read_file_into_string(file_name, &serialized_rl)) {
    printf("Cant read resource file %s\n", file_name.c_str());
    return false;
  }

  return rl->ParseFromString(serialized_rl);
}

bool get_principals_from_file(string &file_name, principal_list *pl) {
  string serialized_pl;
  // read file into serialized_pl
  if (!read_file_into_string(file_name, &serialized_pl)) {
    printf("Cant read principal file %s\n", file_name.c_str());
    return false;
  }
  return pl->ParseFromString(serialized_pl);
}

bool save_resources_to_file(resource_list &rl, string &file_name) {
  string serialized_rl;
  if (!rl.SerializeToString(&serialized_rl)) {
    printf("%s() error, line: %d, Cant serialize resource list\n",
           __func__,
           __LINE__);
    return false;
  }
  if (!write_file_from_string(file_name, serialized_rl)) {
    printf("%s() error, line: %d, Cant read resource file %s\n",
           __func__,
           __LINE__,
           file_name.c_str());
    return false;
  }
  return true;
}

bool save_principals_to_file(principal_list &pl, string &file_name) {
  string serialized_pl;
  if (!pl.SerializeToString(&serialized_pl)) {
    printf("%s() error, line: %d, Cant serialize principals list\n",
           __func__,
           __LINE__);
    return false;
  }
  // write file
  if (!write_file_from_string(file_name, serialized_pl)) {
    printf("%s() error, line: %d, Cant write principals file %s\n",
           __func__,
           __LINE__,
           file_name.c_str());
    return false;
  }
  return true;
}

// -----------------------------------------------------------------------------


// This is the table that records the global descriptor
// a client's local descriptor refers to.  These routines
// do not have to be thread safe since channel guard is
// single threaded.
acl_local_descriptor_table::acl_local_descriptor_table() {
  capacity_ = max_local_descriptors;
  num_ = 0;
}

acl_local_descriptor_table::~acl_local_descriptor_table() {}

int acl_local_descriptor_table::find_available_descriptor() {
  for (int i = 0; i < num_; i++) {
    if (descriptor_entry_[i].status_ != VALID) {
      return i;
    }
  }
  if (num_ >= capacity_)
    return -1;
  return num_++;
}

bool acl_local_descriptor_table::free_descriptor(int i, const string &name) {
  if (i >= num_)
    return false;
  if (descriptor_entry_[i].resource_name_ != name)
    return false;
  descriptor_entry_[i].status_ = INVALID;
  return true;
}

acl_principal_table::acl_principal_table() {
  principal_table_mutex_.lock();
  capacity_ = max_principal_table_capacity;
  num_ = 0;
  for (int i = 0; i < max_principal_table_capacity; i++) {
    principal_status_[i] = INVALID;
  }
  principal_table_mutex_.unlock();
}

acl_principal_table::~acl_principal_table() {}

void acl_principal_table::print_entry(int i) {
  printf("principal entry %d\n", i);
  if (principal_status_[i] != VALID) {
    printf("invalid\n");
    return;
  }
  print_principal_message(principals_[i]);
}

bool acl_principal_table::add_principal_to_table(const string &name,
                                                 const string &alg,
                                                 const string &cred,
                                                 string       &creator) {
  bool ret = true;
  principal_table_mutex_.lock();
  int n = find_principal_in_table(name);
  if (n >= 0) {
    printf("%s() error, line: %d: principal already exists\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  for (int i = 0; i < num_; i++) {
    if (principal_status_[i] != VALID) {
      principals_[i].set_principal_name(name);
      principals_[i].set_authentication_algorithm(alg);
      principals_[i].set_credential(cred);
      principal_status_[i] = VALID;
      goto done;
    }
  }
  if (num_ >= capacity_) {
    printf("%s() error, line: %d: principal table is full\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  principals_[num_].set_principal_name(name);
  principals_[num_].set_authentication_algorithm(alg);
  principals_[num_].set_credential(cred);
  principal_status_[num_] = VALID;
  num_++;

done:
  principal_table_mutex_.unlock();
  return ret;
}

bool acl_principal_table::delete_principal_from_table(const string &name,
                                                      const string &deleter) {
  bool ret = true;
  principal_table_mutex_.lock();

  int n = find_principal_in_table(name);
  if (n < 0)
    goto done;
  principal_status_[n] = INVALID;

done:
  principal_table_mutex_.unlock();
  return ret;
}

int acl_principal_table::find_principal_in_table(const string &name) {
  // assume table is already locked
  for (int i = 0; i < num_; i++) {
    if (principal_status_[i] == INVALID)
      continue;
    if (name == principals_[i].principal_name()) {
      return i;
    }
  }
  return -1;
}

bool acl_principal_table::load_principal_table_from_list(
    const principal_list &pl) {

  principal_table_mutex_.lock();
  num_ = 0;
  for (int i = 0; i < pl.principals_size() && i < capacity_; i++) {
    principal_status_[num_] = VALID;
    principals_[num_].set_principal_name(pl.principals(i).principal_name());
    principals_[num_].set_credential(pl.principals(i).credential());
    num_++;
  }
  principal_table_mutex_.unlock();
  return true;
}

// int principal_status_[max_resource_table_capacity];
bool acl_principal_table::save_principal_table_to_list(principal_list *pl) {
  principal_table_mutex_.lock();
  for (int i = 0; i < num_; i++) {
    if (principal_status_[i] != VALID)
      continue;
    principal_message *pm = pl->add_principals();
    pm->CopyFrom(principals_[i]);
  }
  principal_table_mutex_.unlock();
  return true;
}

bool acl_principal_table::load_principal_table_from_file(
    const string &filename) {
  string         serialized_pl;
  principal_list pl;
  bool           ret = true;

  if (!read_file_into_string(filename, &serialized_pl)) {
    printf("%s() error, line: %d: Cant read file\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  if (!pl.ParseFromString(serialized_pl)) {
    printf("%s() error, line: %d: Cant parse principal list\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  ret = load_principal_table_from_list(pl);

done:
  return ret;
}

bool acl_principal_table::save_principal_table_to_file(const string &filename) {
  string         serialized_pl;
  principal_list pl;

  if (!save_principal_table_to_list(&pl)) {
    printf("%s() error, line: %d: can't save principals to principal list\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!pl.SerializeToString(&serialized_pl)) {
    printf("%s() error, line: %d: can't serialize principal list\n",
           __func__,
           __LINE__);
    return false;
  }

  return write_file_from_string(filename, serialized_pl);
}

acl_resource_table::acl_resource_table() {
  capacity_ = max_resource_table_capacity;
  num_ = 0;
}

acl_resource_table::~acl_resource_table() {}

void acl_resource_table::print_entry(int i) {
  printf("resource entry %d\n", i);
  if (resource_status_[i] != VALID) {
    printf("invalid\n");
    return;
  }
  print_resource_message(resources_[i]);
}

bool acl_resource_table::add_resource_to_table(const resource_message &rm) {
  int n = find_resource_in_table(rm.resource_identifier());
  if (n >= 0) {
    printf("%s() error, line: %d: resource already exists\n",
           __func__,
           __LINE__);
    return false;
  }
  for (int i = 0; i < num_; i++) {
    if (resource_status_[i] != VALID) {
      resources_[i].CopyFrom(rm);
      resource_status_[i] = VALID;
      return true;
    }
  }
  if (num_ >= capacity_) {
    printf("%s() error, line: %d: resource table is full\n",
           __func__,
           __LINE__);
    return false;
  }

  resources_[num_].CopyFrom(rm);
  resource_status_[num_] = VALID;
  num_++;
  return true;
}

bool acl_resource_table::add_resource_to_table(const string &name,
                                               const string &type,
                                               const string &location,
                                               const string &creator) {
  bool ret = true;
  resource_table_mutex_.lock();

  int n = find_resource_in_table(name);
  if (n >= 0) {
    printf("%s() error, line: %d: resource already exists\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  for (int i = 0; i < num_; i++) {
    if (resource_status_[i] != VALID) {
      resources_[i].set_resource_identifier(name);
      resources_[i].set_resource_type(type);
      resources_[i].set_resource_location(location);
      resource_status_[i] = VALID;
      goto done;
    }
  }
  if (num_ >= capacity_) {
    printf("%s() error, line: %d: principal table is full\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  resources_[num_].set_resource_identifier(name);
  resources_[num_].set_resource_type(type);
  resources_[num_].set_resource_location(location);
  resource_status_[num_] = VALID;
  num_++;

done:
  resource_table_mutex_.unlock();
  return ret;
}

bool acl_resource_table::delete_resource_from_table(const string &name,
                                                    const string &type,
                                                    const string &deleter) {
  bool ret = true;
  resource_table_mutex_.lock();

  int n = find_resource_in_table(name);
  if (n < 0) {
    goto done;
  }
  resource_status_[n] = INVALID;

done:
  resource_table_mutex_.unlock();
  return ret;
}

int acl_resource_table::find_resource_in_table(const string &name) {
  for (int i = 0; i < num_; i++) {
    if (resource_status_[i] == INVALID)
      continue;
    if (name == resources_[i].resource_identifier())
      return i;
  }
  return -1;
}

bool acl_resource_table::load_resource_table_from_list(
    const resource_list &rl) {

  resource_table_mutex_.lock();

  num_ = 0;
  for (int i = 0; i < rl.resources_size() && i < capacity_; i++) {
    resources_[num_].CopyFrom(rl.resources(i));
    resource_status_[num_] = VALID;
    num_++;
  }
  resource_table_mutex_.unlock();
  return true;
}

bool acl_resource_table::save_resource_table_to_list(resource_list *rl) {
  resource_table_mutex_.lock();

  for (int i = 0; i < num_; i++) {
    if (resource_status_[i] != VALID)
      continue;
    resource_message *rm = rl->add_resources();
    rm->CopyFrom(resources_[i]);
  }

  resource_table_mutex_.unlock();
  return true;
}

bool acl_resource_table::load_resource_table_from_file(const string &filename) {
  string        serialized_rl;
  resource_list rl;

  if (!read_file_into_string(filename, &serialized_rl)) {
    printf("%s() error, line: %d: Cant read file\n", __func__, __LINE__);
    return false;
  }

  if (!rl.ParseFromString(serialized_rl)) {
    printf("%s() error, line: %d: Cant parse resource list\n",
           __func__,
           __LINE__);
    return false;
  }
  return load_resource_table_from_list(rl);
}

bool acl_resource_table::save_resource_table_to_file(const string &filename) {
  string        serialized_rl;
  resource_list rl;

  if (!save_resource_table_to_list(&rl)) {
    printf("%s() error, line: %d: can't save resources to resource list\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!rl.SerializeToString(&serialized_rl)) {
    printf("%s() error, line: %d: can't serialize resource list\n",
           __func__,
           __LINE__);
    return false;
  }

  return write_file_from_string(filename, serialized_rl);
}

acl_resource_data_element::acl_resource_data_element() {
  status_ = INVALID;
}

// -----------------------------------------------------------------------------

acl_resource_data_element::~acl_resource_data_element() {
  status_ = INVALID;
}

int on_reader_list(const resource_message &r, const string &name) {
  for (int i = 0; i < r.readers_size(); i++) {
    if (r.readers(i) == name)
      return i;
  }
  return -1;
}

int on_writer_list(const resource_message &r, const string &name) {
  for (int i = 0; i < r.writers_size(); i++) {
    if (r.writers(i) == name)
      return i;
  }
  return -1;
}

int on_deleter_list(const resource_message &r, const string &name) {
  for (int i = 0; i < r.deleters_size(); i++) {
    if (r.deleters(i) == name)
      return i;
  }
  return -1;
}

int on_creator_list(const resource_message &r, const string &name) {
  for (int i = 0; i < r.creators_size(); i++) {
    if (r.creators(i) == name)
      return i;
  }
  return -1;
}

int on_principal_list(const string &name, principal_list &pl) {
  for (int i = 0; i < pl.principals_size(); i++) {
    if (pl.principals(i).principal_name() == name)
      return i;
  }
  return -1;
}

int on_resource_list(const string &name, resource_list &rl) {
  for (int i = 0; i < rl.resources_size(); i++) {
    if (rl.resources(i).resource_identifier() == name)
      return i;
  }
  return -1;
}

bool add_reader_to_resource_proto_list(const string     &prin_name,
                                       resource_message *r) {
  if (on_reader_list(*r, prin_name) >= 0)
    return false;
  string *ns = r->add_readers();
  *ns = prin_name;
  return true;
}

bool add_writer_to_resource_proto_list(const string     &name,
                                       resource_message *r) {
  if (on_writer_list(*r, name) >= 0)
    return false;
  string *ns = r->add_writers();
  *ns = name;
  return true;
}

bool add_deleter_to_resource_proto_list(const string     &name,
                                        resource_message *r) {
  if (on_deleter_list(*r, name) >= 0)
    return false;
  string *ns = r->add_deleters();
  *ns = name;
  return true;
}

bool add_creator_to_resource_proto_list(const string     &name,
                                        resource_message *r) {
  if (on_creator_list(*r, name) >= 0)
    return false;
  string *ns = r->add_creators();
  *ns = name;
  return true;
}

bool add_principal_to_proto_list(const string   &name,
                                 const string   &alg,
                                 const string   &cred,
                                 principal_list *pl) {
  principal_message *pm = pl->add_principals();
  pm->set_principal_name(name);
  pm->set_authentication_algorithm(alg);
  pm->set_credential(cred);
  return true;
}

bool add_resource_to_proto_list(const string  &id,
                                const string  &type,
                                const string  &locat,
                                const string  &t_created,
                                const string  &t_written,
                                resource_list *rl) {
  resource_message *rm = rl->add_resources();
  rm->set_resource_identifier(id);
  rm->set_resource_type(type);
  rm->set_resource_location(locat);
  rm->set_time_created(t_created);
  rm->set_time_last_written(t_written);
  return true;
}

// -----------------------------------------------------------------------------

bool sign_nonce(string &nonce, key_message &k, string *signature) {
  return false;
}


channel_guard::channel_guard() {
  channel_principal_authenticated_ = false;
  root_cert_ = nullptr;
  initialized_ = false;
}

channel_guard::~channel_guard() {}

void channel_guard::print() {
  printf("Principal name: %s\n", principal_name_.c_str());
  printf("Authentication algorithm: %s\n",
         authentication_algorithm_name_.c_str());

  // byte* creds_;
  if (channel_principal_authenticated_) {
    printf("Principal authenticated\n");
  } else {
    printf("Principal not authenticated\n");
  }
  printf("Number of resources: %d\n", g_resource_table.num_);
  for (int i = 0; i < g_resource_table.num_; i++) {
    g_resource_table.print_entry(i);
    printf("\n");
  }
}

bool channel_guard::init_root_cert(const string &asn1_cert_str) {
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

bool verify_name_in_credential(const string      &name,
                               const buffer_list &credentials) {
  int        max_buf = 512;
  char       name_buf[max_buf];
  string     subject_name_str;
  X509_NAME *subject_name_1 = nullptr;
  X509_NAME *subject_name_2 = nullptr;
  int        n;

  X509 *cert = X509_new();
  if (cert == nullptr)
    return false;

  bool ret = true;

  n = credentials.blobs_size();
  if (n < 2) {
    printf("%s() error, line %d: too few credentials\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!asn1_to_x509(credentials.blobs(n - 1), cert)) {
    X509_free(cert);
    printf("%s() error, line %d: can't asn1 translate user credential\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  subject_name_1 = X509_get_subject_name(cert);
  if (subject_name_1 == nullptr) {
    ret = false;
    goto done;
  }
  if (X509_NAME_get_text_by_NID(subject_name_1,
                                NID_commonName,
                                name_buf,
                                max_buf)
      < 0) {
    ret = false;
    goto done;
  }

  subject_name_str.assign(name_buf);
  if (name != subject_name_str)
    ret = false;

done:
  if (cert != nullptr)
    X509_free(cert);
  return ret;
}

bool channel_guard::authenticate_me(const string &name,
                                    const string &creds,
                                    string       *nonce) {

  buffer_list credentials;

  if (!credentials.ParseFromString(creds)) {
    printf("%s() error, line %d: can't parse credentials.\n",
           __func__,
           __LINE__);
    return false;
  }

  if (!initialized_) {
    // Check that name is the common name in the credential
    if (!verify_name_in_credential(name, credentials)) {
      printf("%s() error, line %d: name doesn't match name in cert.\n",
             __func__,
             __LINE__);
      return false;
    }

    // This isn't quite right right
    if (g_identity_root_initialized) {
      if (!init_root_cert(g_identity_root)) {
        printf("%s() error, line %d: can't initialize root cert.\n",
               __func__,
               __LINE__);
        return false;
      }
      authentication_algorithm_name_ = g_signature_algorithm;
    }

    if (!verify_cert_chain(root_cert_, credentials)) {
      printf("%s() error, line %d: can't verify cert chain.\n",
             __func__,
             __LINE__);
      return false;
    }

    // This puts the credentials on the guard.
    int i = 0;
    for (i = 0; i < g_pl.principals_size(); i++) {
      if (name == g_pl.principals(i).principal_name()) {
        principal_name_ = g_pl.principals(i).principal_name();
        authentication_algorithm_name_ =
            g_pl.principals(i).authentication_algorithm();
        creds_.assign(g_pl.principals(i).credential());
        break;
      }
    }
    if (i >= g_pl.principals_size()) {
      printf("%s() error, line %d: Can't find principal %s\n",
             __func__,
             __LINE__,
             name.c_str());
      return false;
    }
    initialized_ = true;
  } else {
    printf("%s() error, line %d: identiity root not initialized\n",
           __func__,
           __LINE__);
    return false;
  }

  const int size_nonce = 32;
  byte      buf[32];
  int       k = crypto_get_random_bytes(size_nonce, buf);
  if (k < size_nonce) {
    printf("%s() error, line %d: cant generate nonce\n", __func__, __LINE__);
    return false;
  }
  nonce_.assign((char *)buf, k);
  nonce->assign((char *)buf, k);

  return true;
}

bool channel_guard::verify_me(const string &name, const string &signed_nonce) {

  if (root_cert_ == nullptr) {
    printf("%s() error, line: %d, root_cert_ is null\n", __func__, __LINE__);
    return false;
  }

  bool        ret = true;
  string      cred_buffer_list_str;
  buffer_list list;
  X509       *signing_cert = nullptr;
  EVP_PKEY   *subject_pkey = nullptr;
  string      subj_cert_str;

  if (!list.ParseFromString(cred_buffer_list_str)) {
    printf("%s() error, line: %d, ParseFromString failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  cred_buffer_list_str.assign((char *)creds_.data(), creds_.size());
  if (!list.ParseFromString(cred_buffer_list_str)) {
    printf("%s() error, line: %d, can't parse credentials\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }
  if (list.blobs_size() <= 0) {
    printf("%s() error, line: %d, cred blobs is empty\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  if (!verify_cert_chain(root_cert_, list)) {
    printf("%s() error, line: %d, verify_cert_chain failed\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  // check signature
  subj_cert_str.assign((char *)list.blobs(list.blobs_size() - 1).data(),
                       list.blobs(list.blobs_size() - 1).size());
  signing_cert = X509_new();
  if (signing_cert == nullptr) {
    printf("%s() error, line: %d, X509_new failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }
  if (!asn1_to_x509(subj_cert_str, signing_cert)) {
    printf("%s() error, line: %d, asn1_to_x509 failed\n", __func__, __LINE__);
    ret = false;
    goto done;
  }

  subject_pkey = X509_get_pubkey(signing_cert);
  if (subject_pkey == nullptr) {
    printf("%s() error, line: %d, Can't get public key from cert\n",
           __func__,
           __LINE__);
    ret = false;
    goto done;
  }

  if (strcmp(authentication_algorithm_name_.c_str(),
             Enc_method_rsa_1024_sha256_pkcs_sign)
          == 0
      || strcmp(authentication_algorithm_name_.c_str(),
                Enc_method_rsa_2048_sha256_pkcs_sign)
             == 0) {
    // verify it
    RSA *rsa_key = EVP_PKEY_get1_RSA(subject_pkey);
    if (rsa_key == nullptr) {
      printf("%s() error, line %d: EVP_PKEY_get1_RSA failed\n",
             __func__,
             __LINE__);
      ret = false;
      goto done;
    }
    // free rsa key?
    if (!rsa_verify(Digest_method_sha_256,
                    rsa_key,
                    nonce_.size(),
                    (byte *)nonce_.data(),
                    signed_nonce.size(),
                    (byte *)signed_nonce.data())) {
      printf("%s() error, line %d: verify failed\n", __func__, __LINE__);
      ret = false;
      goto done;
    }
  } else if (strcmp(authentication_algorithm_name_.c_str(),
                    Enc_method_rsa_3072_sha384_pkcs_sign)
             == 0) {
    RSA *rsa_key = EVP_PKEY_get1_RSA(subject_pkey);
    if (rsa_key == nullptr) {
      printf("%s() error, line %d: EVP_PKEY_get1_RSA failed\n",
             __func__,
             __LINE__);
      ret = false;
      goto done;
    }
    if (!rsa_verify(Digest_method_sha_384,
                    rsa_key,
                    nonce_.size(),
                    (byte *)nonce_.data(),
                    signed_nonce.size(),
                    (byte *)signed_nonce.data())) {
      printf("%s() error, line %d: verify failed\n", __func__, __LINE__);
      ret = false;
      goto done;
    }
  } else {
    printf("%s() error, line: %d, unsupported signing algorithm %s\n",
           __func__,
           __LINE__,
           authentication_algorithm_name_.c_str());
    ret = false;
    goto done;
  }

done:
  channel_principal_authenticated_ = ret;
  if (signing_cert != nullptr) {
    X509_free(signing_cert);
    signing_cert = nullptr;
  }
  if (subject_pkey != nullptr) {
    EVP_PKEY_free(subject_pkey);
    subject_pkey = nullptr;
  }
  return ret;
}

// -----------------------------------------------------------------------------

// We have to be careful that resource names are unique and not
// subject to spoofing by creators making up a resources with
// an existing name to avoid authentication.
bool channel_guard::can_read(int resource_entry) {
  if (!channel_principal_authenticated_) {
    return false;
  }
  // see if principal_name_ is on reader list
  for (int j = 0;
       j < g_resource_table.resources_[resource_entry].readers_size();
       j++) {
    if (g_resource_table.resources_[resource_entry].readers(j)
        == principal_name_) {
      return true;
    }
  }
  return false;
}

bool channel_guard::can_write(int resource_entry) {
  if (!channel_principal_authenticated_) {
    return false;
  }
  for (int j = 0;
       j < g_resource_table.resources_[resource_entry].writers_size();
       j++) {
    if (g_resource_table.resources_[resource_entry].writers(j)
        == principal_name_) {
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
  for (int j = 0;
       j < g_resource_table.resources_[resource_entry].deleters_size();
       j++) {
    if (g_resource_table.resources_[resource_entry].deleters(j)
        == principal_name_) {
      return true;
    }
  }
  return false;
}

bool channel_guard::can_create(int resource_entry) {
  if (!channel_principal_authenticated_) {
    return false;
  }
  for (int j = 0;
       j < g_resource_table.resources_[resource_entry].creators_size();
       j++) {
    if (g_resource_table.resources_[resource_entry].creators(j)
        == principal_name_) {
      return true;
    }
  }
  return false;
}

int channel_guard::find_resource(const string &name) {
  return g_resource_table.find_resource_in_table(name);
}

bool channel_guard::access_check(int resource_entry, const string &action) {
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

bool channel_guard::accept_credentials(const string   &principal_name,
                                       const string   &alg,
                                       const string   &cred,
                                       principal_list *pl) {
  principal_message pm;
  pm.set_principal_name(principal_name);
  pm.set_authentication_algorithm(alg);
  pm.set_credential(cred);
  return add_principal_to_proto_list(principal_name, alg, cred, pl);
}

bool channel_guard::add_access_rights(string &resource_name,
                                      string &right,
                                      string &new_prin) {
  // can current channel principal add access rights to this resource?
  int n = find_resource(resource_name);
  if (n < 0) {
    printf("%s() error, line: %d: No such resource\n", __func__, __LINE__);
    return false;
  }
  // already there?
  return false;
}

bool channel_guard::create_resource(string &name) {
  // make up encryption key
  // automatically give creator read, write, delete rights
  return false;
}

bool channel_guard::open_resource(const string &resource_name,
                                  const string &requested_right,
                                  int          *local_descriptor) {

  string file_type("file");

  *local_descriptor = -1;
  int table_entry = find_resource(resource_name);
  if (table_entry < 0) {
    printf("%s() error, line: %d: Can't find resource\n", __func__, __LINE__);
    return false;
  }

  // note that if file doesn't exist, we create it which isn't right
  // principal should have create right on parent directory but we don't
  // support directories yet.
  string file_name;
  int    res = -1;

  file_name = g_resource_table.resources_[table_entry].resource_location();
  if (!access_check(table_entry, requested_right)) {
    printf("%s() error, line: %d: access_check failed\n", __func__, __LINE__);
    return false;
  }
  if (requested_right == "read") {
    // open for reading
    res = open(file_name.c_str(), O_RDONLY);
    if (res < 0) {
      printf("%s() error, line: %d: Can't open file\n", __func__, __LINE__);
      return false;
    }
    *local_descriptor = descriptor_table_.find_available_descriptor();
    if (*local_descriptor < 0) {
      printf("%s() error, line: %d: Can't find available table descriptor\n",
             __func__,
             __LINE__);
      return false;
    }
    descriptor_table_.descriptor_entry_[*local_descriptor].global_descriptor_ =
        res;
    descriptor_table_.descriptor_entry_[*local_descriptor].status_ =
        acl_local_descriptor_table::VALID;
    descriptor_table_.descriptor_entry_[*local_descriptor].resource_name_ =
        resource_name;
    return true;
  } else if (requested_right == "write") {
    // open for writing
    res = open(file_name.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (res < 0) {
      printf("%s() error, line: %d: Can't open file %s\n",
             __func__,
             __LINE__,
             file_name.c_str());
      return false;
    }
    *local_descriptor = descriptor_table_.find_available_descriptor();
    if (*local_descriptor < 0) {
      printf("%s() error, line: %d: Can't find available descriptor\n",
             __func__,
             __LINE__);
      return false;
    }
    descriptor_table_.descriptor_entry_[*local_descriptor].global_descriptor_ =
        res;
    descriptor_table_.descriptor_entry_[*local_descriptor].status_ =
        acl_local_descriptor_table::VALID;
    descriptor_table_.descriptor_entry_[*local_descriptor].resource_name_ =
        resource_name;
    return true;
  } else {
    printf("%s() error, line: %d: unknown requested right\n",
           __func__,
           __LINE__);
    return false;
  }

  return true;
}

bool channel_guard::read_resource(const string &resource_name,
                                  int           local_descriptor,
                                  int           n,
                                  string       *out) {

  if (n <= 0) {
    printf("%s() error, line: %d: buffer size\n", __func__, __LINE__);
    return false;
  }
  byte buf[n + 1];
  if (local_descriptor >= descriptor_table_.num_) {
    printf("%s() error, line: %d: bad descriptor\n", __func__, __LINE__);
    return false;
  }
  if (descriptor_table_.descriptor_entry_[local_descriptor].status_
          != acl_resource_data_element::VALID
      || descriptor_table_.descriptor_entry_[local_descriptor].resource_name_
             != resource_name) {
    printf("%s() error, line: %d: invalid desciptor element\n",
           __func__,
           __LINE__);
    return false;
  }
  int k = (int)::read(
      descriptor_table_.descriptor_entry_[local_descriptor].global_descriptor_,
      buf,
      n);
  if (k < 0) {
    printf("%s() error, line: %d: read failed\n", __func__, __LINE__);
    return false;
  }
  out->assign((char *)buf, k);
  return true;
}

bool channel_guard::write_resource(const string &resource_name,
                                   int           local_descriptor,
                                   int           n,
                                   string       &in) {
  if (local_descriptor >= descriptor_table_.num_) {
    printf("%s() error, line: %d: bad descriptor\n", __func__, __LINE__);
    return false;
  }
  if (descriptor_table_.descriptor_entry_[local_descriptor].status_
          != acl_resource_data_element::VALID
      || descriptor_table_.descriptor_entry_[local_descriptor].resource_name_
             != resource_name) {
    printf("%s() error, line: %d: bad  element descriptor\n",
           __func__,
           __LINE__);
    return false;
  }
  int k = write(
      descriptor_table_.descriptor_entry_[local_descriptor].global_descriptor_,
      (byte *)in.data(),
      (int)in.size());
  if (k < 0) {
    printf("%s() error, line: %d\n", __func__, __LINE__);
    return false;
  }
  return true;
}

bool channel_guard::delete_resource(const string &resource_name) {
  printf("%s() error, line: %d, delete_resource not implemented\n",
         __func__,
         __LINE__);
  return false;
}

bool channel_guard::close_resource(const string &resource_name,
                                   int           local_descriptor) {

  if (local_descriptor >= descriptor_table_.num_) {
    printf("%s() error, line: %d: bad descriptor\n", __func__, __LINE__);
    return false;
  }
  if (descriptor_table_.descriptor_entry_[local_descriptor].status_
          != acl_resource_data_element::VALID
      || descriptor_table_.descriptor_entry_[local_descriptor].resource_name_
             != resource_name) {
    printf("%s() error, line: %d: invalid element\n", __func__, __LINE__);
    return false;
  }
  close(
      descriptor_table_.descriptor_entry_[local_descriptor].global_descriptor_);
  return true;
}

int find_resource_in_resource_proto_list(const resource_list &rl,
                                         const string        &name) {
  for (int i = 0; i < rl.resources_size(); i++) {
    if (rl.resources(i).resource_identifier() == name)
      return i;
  }
  return -1;
}

int find_principal_in_principal_proto_list(const principal_list &pl,
                                           const string         &name) {
  for (int i = 0; i < pl.principals_size(); i++) {
    if (pl.principals(i).principal_name() == name)
      return i;
  }
  return -1;
}

}  // namespace acl_lib
}  // namespace certifier

// -----------------------------------------------------------------------
