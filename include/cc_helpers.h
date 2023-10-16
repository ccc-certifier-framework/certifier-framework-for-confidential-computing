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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "support.h"
#include "certifier.h"
#include "simulated_enclave.h"
#include "certifier_framework.h"

#ifndef _CC_HELPERS_CC_
#  define _CC_HELPERS_CC_

bool open_client_socket(const string &host_name, int port, int *soc);
bool open_server_socket(const string &host_name, int port, int *soc);

bool construct_platform_evidence_package(string &          enclave_type,
                                         const string &    purpose,
                                         evidence_list &   list,
                                         string &          the_attestation,
                                         evidence_package *ep);
bool add_policy_key_says_platform_key_is_trusted(
    signed_claim_message &platform_key_is_trusted,
    evidence_package *    ep);
void print_cn_name(X509_NAME *name);
void print_org_name(X509_NAME *name);
void print_ssl_error(int code);

bool load_server_certs_and_key(X509 *        x509_root_cert,
                               key_message & private_key,
                               const string &private_key_cert,
                               SSL_CTX *     ctx);
bool load_server_certs_and_key(X509 *        peer_root_cert,
                               X509 *        root_cert,
                               int           cert_chain_length,
                               string *      cert_chain,
                               key_message & private_key,
                               const string &private_key_cert,
                               SSL_CTX *     ctx);

// The functions below are used by BORING_SSL
// Eventually they will be deprecated
#  if 1
bool init_client_ssl(X509 *        x509_root_cert,
                     key_message & private_key,
                     const string &private_key_cert,
                     const string &host_name,
                     int           port,
                     int *         p_sd,
                     SSL_CTX **    p_ctx,
                     SSL **        p_ssl);
void close_client_ssl(int sd, SSL_CTX *ctx, SSL *ssl);
#  endif

#endif
