// Copyright 2025 John Manferdelli, All Rights Reserved.
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
// File: acl_rpc.h

#ifndef _ACL_RPC_H__
#define _ACL_RPC_H__

#include "acl_support.h"
#include "acl.h"

class acl_client_dispatch {
private:
  bool initialized_;
  SSL* channel_descriptor_;

public:
  acl_client_dispatch(SSL* channel);
  ~acl_client_dispatch();
  bool rpc_authenticate_me(const string& principal_name, string* output);
  bool rpc_verify_me(const string& principal_name, const string& signed_nonce);
  bool rpc_open_resource(const string& resource_name, const string& access_right);
  bool rpc_read_resource(const string& resource_name, int num_bytes, string* bytes_read);
  bool rpc_write_resource(const string& resource_name, const string& bytes_to_write);
  bool rpc_close_resource(const string& resource_name);
  bool rpc_add_access_right(const string& resource_name, const string& delegated_principal,
                          const string& right);
};

class acl_server_dispatch {
private:
  bool initialized_;
  SSL* channel_descriptor_;
  principal_list principal_list_;
  resource_list resource_list_;

public:
  channel_guard guard_;
  acl_server_dispatch(SSL* channel);
  ~acl_server_dispatch();

  bool load_principals(principal_list& pl);
  bool load_resources(resource_list& pl);
  bool service_request();
};
#endif

