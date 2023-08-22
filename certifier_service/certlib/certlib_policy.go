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

package certlib

import (
/*
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	b64 "encoding/base64"
	"errors"
	"fmt"
	certprotos "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/certprotos"
	"google.golang.org/protobuf/proto"
	"math/big"
	"net"
	"strings"
	"time"
 */
)

/*
certifier::framework::store_entry::store_entry() {}

certifier::framework::store_entry::~store_entry() {}

void certifier::framework::store_entry::print() {
  printf("Tag: %s, type: %s, value: ", tag_.c_str(), type_.c_str());
  if (type_ == "string") {
    printf("%s\n", value_.c_str());
  } else {
    print_bytes((int)value_.size(), (byte *)value_.data());
  }
}

certifier::framework::policy_store::policy_store(unsigned max_ents) {
  max_num_ents_ = max_ents;
  num_ents_ = 0;
  entry_ = new store_entry *[max_ents];
}

certifier::framework::policy_store::policy_store() {
  max_num_ents_ = MAX_NUM_ENTRIES;
  num_ents_ = 0;
  entry_ = new store_entry *[MAX_NUM_ENTRIES];
}

certifier::framework::policy_store::~policy_store() {
  for (unsigned i = 0; i < num_ents_; i++) {
    delete entry_[i];
    entry_[i] = nullptr;
  }
  num_ents_ = 0;
}

unsigned certifier::framework::policy_store::get_num_entries() {
  return num_ents_;
}
bool certifier::framework::policy_store::add_entry(const string &tag,
                                                   const string &type,
                                                   const string &value) {
  if (num_ents_ >= max_num_ents_)
    return false;
  entry_[num_ents_] = new store_entry;
  entry_[num_ents_]->tag_ = tag;
  entry_[num_ents_]->type_ = type;
  entry_[num_ents_]->value_.assign(value.data(), value.size());
  num_ents_++;
  return true;
}

int certifier::framework::policy_store::find_entry(const string &tag,
                                                   const string &type) {
  for (unsigned i = 0; i < num_ents_; i++) {
    if (entry_[i]->tag_ == tag && entry_[i]->type_ == type)
      return (int)i;
  }
  return -1;
}

bool certifier::framework::policy_store::get(unsigned ent, string *v) {
  if (ent >= num_ents_)
    return false;
  *v = entry_[ent]->value_;
  return true;
}

bool certifier::framework::policy_store::put(unsigned ent, const string v) {
  if (ent < 0 || ent >= num_ents_)
    return false;
  entry_[ent]->value_ = v;
  return true;
}

const string *certifier::framework::policy_store::tag(unsigned ent) {
  if (ent >= num_ents_)
    return nullptr;
  return &entry_[ent]->tag_;
}

const string *certifier::framework::policy_store::type(unsigned ent) {
  if (ent >= num_ents_)
    return nullptr;
  return &entry_[ent]->type_;
}
store_entry *certifier::framework::policy_store::get_entry(unsigned ent) {
  if (ent >= num_ents_)
    return nullptr;
  return entry_[ent];
}

bool certifier::framework::policy_store::update_or_insert(const string &tag,
                                                          const string &type,
                                                          const string &value) {
  int ent = find_entry(tag, type);
  if (ent < 0) {
    return add_entry(tag, type, value);
  }
  if (!put(ent, value))
    return false;
  return true;
}

bool certifier::framework::policy_store::delete_entry(unsigned ent) {
  if (ent >= num_ents_)
    return false;

  delete entry_[ent];
  for (unsigned i = ent; i < num_ents_; i++) {
    entry_[i] = entry_[i + 1];
  }
  entry_[num_ents_ - 1] = nullptr;
  num_ents_--;
  return true;
}

void certifier::framework::policy_store::print() {
  printf("Number of entries: %d, max number of ents: %d\n",
         num_ents_,
         max_num_ents_);

  for (unsigned i = 0; i < num_ents_; i++) {
    printf("  Entry %3d: ", i);
    entry_[i]->print();
    printf("\n");
  }
}

ool certifier::framework::policy_store::Serialize(string *psout) {
  policy_store_message psm;

  psm.set_max_ents(max_num_ents_);

  for (unsigned i = 0; i < num_ents_; i++) {
    policy_store_entry *pe = psm.add_entries();
    store_entry *       se = entry_[i];
    pe->set_tag(se->tag_);
    pe->set_type(se->type_);
    pe->set_value(se->value_);
  }

  return (psm.SerializeToString(psout));
}

bool certifier::framework::policy_store::Deserialize(string &in) {

  policy_store_message psm;

  if (!psm.ParseFromString(in))
    return false;

  if (psm.has_max_ents()) {
    max_num_ents_ = psm.max_ents();
  } else {
    max_num_ents_ = MAX_NUM_ENTRIES;
  }

  for (int i = 0; i < psm.entries_size(); i++) {
    const policy_store_entry &pe = psm.entries(i);
    store_entry *             se = new store_entry();
    entry_[i] = se;
    se->tag_ = pe.tag();
    se->type_ = pe.type();
    se->value_ = pe.value();
  }
  num_ents_ = psm.entries_size();

  return true;
}
 */

//  --------------------------------------------------------------------

