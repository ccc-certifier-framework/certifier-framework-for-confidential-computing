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
// File: acl.h

#ifndef _ACL_H__
#define _ACL_H__

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "acl.pb.h"
#include "acl_support.h"

// These first definition are copied from certifier.  When linked
// into a certifier applications, we should use those.

// ---------------------------------------------------------------------------
//  These are acl specific

bool sign_nonce(string& nonce, key_message& k, string* signature);
bool rotate_resource_key(string& resource, key_message& km);

class active_resource {
public:
  active_resource();
  ~active_resource();

  enum {READ=0x1, WRITE=0x2, DELETE=0x4, CREATE=0x08};

  string principal_name_;
  string resource_name_;
  int desc_;
  unsigned rights_;
};

void print_principal_info(const principal_message& pi);
void print_audit_info(const audit_info& inf);
void print_resource_message(const resource_message& rm);
void print_principal_message(const principal_message& pm);
void print_resource_list(const resource_list& rl);
void print_principal_list(const principal_list& pl);

bool add_reader_to_resource_proto_list(const string& name, resource_message* r);
bool add_writer_to_resource_proto_list(const string& name, resource_message* r);
bool add_deleter_to_resource_proto_list(const string& name, resource_message* r);
bool add_creator_to_resource_proto_list(const string& name, resource_message* r);
bool add_principal_to_proto_list(const string& name, const string& alg,
                  const string& cred, principal_list* pl);
bool add_resource_to_proto_list(const string& id, const string& type,
                  const string& locat, const string& t_created,
                  const string& t_written, resource_list* rl);
bool get_resources_from_file(string& file_name, resource_list* rl);
bool get_principals_from_file(string& file_name, principal_list* pl);
bool save_resources_to_file(resource_list& rl, string& file_name);
bool save_principals_to_file(principal_list& pl, string& file_name);

int on_reader_list(const resource_message& r, const string& name);
int on_writer_list(const resource_message& r, const string& name);
int on_deleter_list(const resource_message& r, const string& name);
int on_creator_list(const resource_message& r, const string& name);

int on_principal_list(const string& name, principal_list& pl);
int on_resource_list(const string& name, resource_list& rl);

bool add_reader_to_resource(string& name, resource_message* r);
bool add_writer_to_resource(string& name, resource_message* r);
bool add_deleter_to_resource(string& name, resource_message* r);
bool add_creator_to_resource(string& name, resource_message* r);
bool add_principal_to_proto_list(const string& name, const string& alg,
                const string& cred, principal_list* pl);
bool add_resource_to_proto_list(const string& id, const string& locat,
                const string& t_created, const string& t_written,
                resource_list* rl);

const int max_active_resources = 25;
class channel_guard {
public:
  channel_guard();
  ~channel_guard();

  string principal_name_;
  string authentication_algorithm_name_;
  string creds_;
  bool channel_principal_authenticated_;

  int  capacity_resources_;
  int  num_resources_;
  resource_message* resources_;
  int num_active_resources_;
  int capacity_active_resources_;
  active_resource ar_[max_active_resources];
  string nonce_;

  X509* root_cert_;

  void print();

  int find_resource(const string& name);
  int find_in_active_resource_table(const string& name);

  bool init_root_cert(const string& asn1_cert_str);
  bool authenticate_me(const string& name, principal_list& pl, string* nonce);
  bool verify_me(const string& name, const string& signed_nonce);
  bool load_resources(resource_list& rl);

  bool can_read(int resource_entry);
  bool can_write(int resource_entry);
  bool can_delete(int resource_entry);
  bool can_create(int resource_entry);

  bool access_check(int resource_entry, const string& action);

  bool add_resource(resource_message& rm);
  bool save_active_resources(const string& file_name);

  // Called from grpc
  bool accept_credentials(const string& principal_name, const string& alg,const string& cred, principal_list* pl);
  bool add_access_rights(string& resource_name, string& right, string& new_prin);
  bool create_resource(string& name);
  bool open_resource(const string& resource_name, const string& access_mode);
  bool read_resource(const string& resource_name, int n, string* out);
  bool write_resource(const string& resource_name, int n, string& in);
  bool delete_resource(const string& resource_name);
  bool close_resource(const string& resource_name);
};

int find_resource_in_resource_proto_list(const resource_list& rl, const string& name);
int find_principal_in_principal_proto_list(const principal_list& pl, const string& name);

#endif

