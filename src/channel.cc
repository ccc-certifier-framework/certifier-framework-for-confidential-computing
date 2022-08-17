// This file is temporary

// ----------------------------------------------------------------------------------

#define DEBUG

// Socket and SSL support

void print_cn_name(X509_NAME* name) {
  char name_buf[1024];
  if (X509_NAME_get_text_by_NID(name, NID_commonName, name_buf, 1024) > 0) {
    printf(" %s", name_buf);
  }
  printf("\n");
}

void print_org_name(X509_NAME* name) {
  char name_buf[1024];
  if (X509_NAME_get_text_by_NID(name, NID_organizationName, name_buf, 1024) > 0) {
    printf(" %s", name_buf);
  }
  printf("\n");
}

void print_ssl_error(int code) {
  switch(code) {
  case SSL_ERROR_NONE:
    printf("No ssl error\n");
    break;
  case SSL_ERROR_WANT_READ:
    printf("want read ssl error\n");
    break;
  case SSL_ERROR_WANT_WRITE:
    printf("want write ssl error\n");
    break;
  case SSL_ERROR_WANT_CONNECT:
    printf("want connect ssl error\n");
    break;
  case SSL_ERROR_WANT_ACCEPT:
    printf("want accept ssl error\n");
    break;
  case SSL_ERROR_WANT_X509_LOOKUP:
    printf("want lookup ssl error\n");
    break;
  case SSL_ERROR_WANT_ASYNC:
    printf("want async ssl error\n");
    break;
  case SSL_ERROR_WANT_CLIENT_HELLO_CB:
    printf("wantclient hello  ssl error\n");
    break;
  case SSL_ERROR_SSL:
    printf("ssl error error\n");
    break;
  default:
    printf("Unknown ssl error, %d\n", code);
    break;
  }
}

bool open_client_socket(const string& host_name, int port, int* soc) {
  // dial service
  struct sockaddr_in address;
  memset((byte*)&address, 0, sizeof(struct sockaddr_in));
  *soc = socket(AF_INET, SOCK_STREAM, 0);
  if (*soc < 0) {
    return false;
  }
  struct hostent* he = gethostbyname(host_name.c_str());
  if (he == nullptr) {
    return false;
  }
  memcpy(&(address.sin_addr.s_addr), he->h_addr, he->h_length);
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  if(connect(*soc, (struct sockaddr *) &address, sizeof(address)) != 0) {
    return false;
  }
  return true;
}

bool open_server_socket(const string& host_name, int port, int* soc) {
  const char* hostname = host_name.c_str();
  struct sockaddr_in addr;

  struct hostent *he = nullptr;
  if ((he = gethostbyname(hostname)) == NULL) {
    printf("gethostbyname failed\n");
    return false;
  }
  *soc= socket(AF_INET, SOCK_STREAM, 0);
  if (*soc < 0) {
    printf("socket call failed\n");
    return false;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long*)(he->h_addr);
  if (bind(*soc, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    printf("bind failed\n");
    return false;
  }
  if (listen(*soc, 10) != 0) {
    printf("listen failed\n");
    return false;
  }
  return true;
}

// This is only for debugging.
int SSL_my_client_callback(SSL *s, int *al, void *arg) {
  printf("callback\n");
  return 1;
}

// This is used to test the signature chain is verified properly
int verify_callback(int preverify, X509_STORE_CTX* x509_ctx) {
  int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
  int err = X509_STORE_CTX_get_error(x509_ctx);

  X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
  X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

  printf("Depth %d, Preverify: %d\n", depth, preverify);
  printf("Issuer CN : ");
  print_cn_name(iname);
  printf("Subject CN: ");
  print_cn_name(sname);

  if(depth == 0) {
    /* If depth is 0, its the server's certificate. Print the SANs too */
    printf("Subject ORG: ");
    print_org_name(sname);
  }

  return preverify;
}

// ----------------------------------------------------------------------------------

// Loads server side certs and keys.
bool load_server_certs_and_key(
      X509* x509_root_cert, key_message& private_key,
      SSL_CTX* ctx) {
  // load auth key, policy_cert and certificate chain
  RSA* r = RSA_new();
  if (!key_to_RSA(private_key, r)) {
    return false;
  }
  EVP_PKEY* auth_private_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(auth_private_key, r);

  X509* x509_auth_key_cert= X509_new();
  string auth_cert_str;
  auth_cert_str.assign((char*)private_key.certificate().data(),
        privatekey_.certificate().size());
  if (!asn1_to_x509(auth_cert_str, x509_auth_key_cert)) {
      return false;
  }

  STACK_OF(X509)* stack = sk_X509_new_null();
  if (sk_X509_push(stack, root_cert) == 0) {
    return false;
  }

  if (SSL_CTX_use_cert_and_key(ctx, x509_auth_key_cert, auth_private_key, stack, 1) <= 0 ) {
      return false;
  }
  if (!SSL_CTX_check_private_key(ctx) ) {
      return false;
  }
  SSL_CTX_add_client_CA(ctx, root_cert);
  SSL_CTX_add1_to_CA_list(ctx, root_cert);
  return true;
}


void server_dispatch(const string& host_name, int port,
      x509* root_cert, key_message& private_key,
      void (*)(secure_authenticated_channel&)) {
  SSL_load_error_strings();

  // Get a socket.
  int sock = -1;
  if (!open_server_socket(host_name, port, &sock)) {
    printf("Can't open server socket\n");
    return false;
  }

  // Set up TLS handshake data.
  SSL_METHOD* method = (SSL_METHOD*) TLS_server_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if (ctx == NULL) {
    printf("SSL_CTX_new failed\n");
    return false;
  }
  X509_STORE* cs = SSL_CTX_get_cert_store(ctx);
  X509_STORE_add_cert(cs, x509_policy_cert);

  if (!load_server_certs_and_key(x509_policy_cert, private_key, ctx)) {
    printf("SSL_CTX_new failed\n");
    return false;
  }

  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);

#if 0
  // This is unnecessary usually.
  if(!isRoot()) {
    printf("This program must be run as root/sudo user!!");
    return false;
  }
#endif

  unsigned int len = 0;
  while (1) {
#ifdef DEBUG
    printf("at accept\n");
#endif
    struct sockaddr_in addr;
    int client = accept(sock, (struct sockaddr*)&addr, &len);
    secure_authenticated_channel* nc = new(secure_authenticated_channel("server"));
    if (!nc->init_server_ssl(host_name, port, root_cert, private_key)) {
      continue;
    }
    nc->ssl_ = SSL_new(ctx);
    SSL_set_fd(nc->ssl_, client);
    nc->sock_ = client;
    nc->server_channel_accept_and_auth(func);
  }
}

secure_authenticated_channel::secure_authenticated_channel(string& role) {
  role_ = role;
  channel_initialized_ = false;
  ssl_ctx_= nullptr;
  store_ctx_= nullptr;
  ssl_= nullptr;
  sock_ = -1;
  my_cert_= nullptr;
  peer_cert_= nullptr;
  peer_id_.clear();
}

secure_authenticated_channel::~secure_authenticated_channel() {
  role_clear();
  channel_initialized_ = false;
  // delete?
  ssl_ctx_= nullptr;
  store_ctx_= nullptr;
  // delete?
  ssl_= nullptr;
  sock_ = -1;
  // delete?
  my_cert_= nullptr;
  // delete?
  peer_cert_= nullptr;
  peeri_id_.clear();
}

// Generates client challenge and checks response.
bool secure_authenticated_channel::client_auth_server() {
  bool ret = true;
  int res = 0;

  int size_nonce = 64;
  byte nonce[size_nonce];
  int size_sig = 256;
  string sig_str;

  X509* x = nullptr;
  EVP_PKEY* client_auth_public_key = nullptr;
  EVP_PKEY* subject_pkey = nullptr;
  RSA* r = nullptr;

  // prepare for verify 
  X509_STORE* cs = X509_STORE_new();
  X509_STORE_add_cert(cs, x509_policy_cert);
  store_ctx_ = X509_STORE_CTX_new();

  // get cert
  string asn_cert;
  if (sized_ssl_read(ssl_, &asn_cert) < 0) {
    ret = false;
    goto done;
  }

  x = X509_new();
  if (!asn1_to_x509(asn_cert, x)) {
    ret = false;
    goto done;
  }

  subject_pkey = X509_get_pubkey(x);
  if (subject_pkey == nullptr) {
    ret = false;
    goto done;
  }
  r = EVP_PKEY_get1_RSA(subject_pkey);
  if (r == nullptr) {
    ret = false;
    goto done;
  }
  
  memset(nonce, 0, 64);
  if (!get_random(64 * 8, nonce)) {
    ret = false;
    goto done;
  }
  SSL_write(ssl, nonce, size_nonce);

  // get signature
  size_sig = sized_ssl_read(ssl, &sig_str);
  if (size_sig < 0 ) {
    ret = false;
    goto done;
  }

  // verify chain
  res = X509_STORE_CTX_init(store_ctx_, cs, x, nullptr);
  X509_STORE_CTX_set_cert(store_ctx_, x);
  res = X509_verify_cert(store_ctx_);
  if (res != 1) {
    ret = false;
    goto done;
  }

  // verify signature
  if (!rsa_sha256_verify(r, size_nonce, nonce,
          sig_str.size(), (byte*)sig_str.data())) {
    ret = false;
    goto done;
  }

#ifdef DEBUG
  printf("client_auth_server succeeds\n");
#endif

done:
  if (x != nullptr)
    X509_free(x);
  if (r != nullptr)
    RSA_free(r);
  if (subject_pkey != nullptr)
    EVP_PKEY_free(subject_pkey);
  if (store_ctx_ != nullptr) {
    store_ctx_ = nullptr;
    X509_STORE_CTX_free(store_ctx_);
  }
  
  return ret;
}

// Responds to Server challenge
bool secure_authenticated_channel::client_auth_client() {
  if (ssl_ == nullptr)
    return false;

  // private key should have been initialized
  bool ret = true;
  int size_nonce = 128;
  byte nonce[size_nonce];
  int size_sig = 256;
  byte sig[size_sig];
  RSA* r = nullptr;

  // send cert
  SSL_write(ssl_, private_key_.certificate().data(),
      private_key_.certificate().size());
  size_nonce = SSL_read(ssl_, nonce, size_nonce);

  r = RSA_new();
  if (!key_to_RSA(private_key_, r)) {
    ret = false;
    goto done;
  }

  if (!rsa_sha256_sign(r, size_nonce, nonce, &size_sig, sig)) {
    ret = false;
    goto done;
  }
  SSL_write(ssl_, sig, size_sig);
#ifdef DEBUG
  printf("client_auth_client succeeds\n");
#endif

done:
  if (r != nullptr)
    RSA_free(r);
  return ret;
}

bool secure_authenticated_channel::init_client_ssl(string& host_name, int port,
        x509* root_cert, key_message& private_key) {

  SSL_load_error_strings();
  int sd = 0;
  SSL_CTX* ctx = nullptr;
  SSL* ssl = nullptr;
  OPENSSL_init_ssl(0, NULL);;

  int sock = -1;
  if (!open_client_socket(host_name, port, &sock_)) {
    printf("Can't open client socket\n");
    return false;
  }

  const SSL_METHOD* method = TLS_client_method();
  if(method == nullptr) {
    printf("Can't get method\n");
    return false;
  }
  ssl_ctx_ = SSL_CTX_new(method);
  if(ssl_ctx_ == nullptr) {
    printf("Can't get SSL_CTX\n");
    return false;
  }
  X509_STORE* cs = SSL_CTX_get_cert_store(ssl_ctx_);
  X509_STORE_add_cert(cs, x509_policy_cert);

  // For debugging: SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER, nullptr);

  SSL_CTX_set_verify_depth(ctx, 4);
  const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);

  ssl_ = SSL_new(ctx);
  SSL_set_fd(ssl_, sock_);
  int res = SSL_set_cipher_list(ssl, "TLS_AES_256_GCM_SHA384");  // Change?

  if (!load_client_certs_and_key(root_cert_, private_key_, ssl_ctx_)) {
    printf("load_client_certs_and_key failed\n");
    return false;
  }

  // SSL_connect - initiate the TLS/SSL handshake with an TLS/SSL server
  if (SSL_connect(ssl_ctx_) == 0) {
    printf("ssl_connect failed\n");
    return false;
  }

  // Verify a server certificate was presented during the negotiation
  X509* cert = SSL_get_peer_certificate(ssl_);

#ifdef DEBUG
  if(cert) {
    printf("Client: Peer cert presented in nego\n");
  } else {
    printf("Client: No peer cert presented in nego\n");
  }
#endif
  return true;
}

// Loads client side certs and keys.  Note: key for private_key is in
//    the key.
bool secure_authenticated_channel::load_client_certs_and_key() {
  RSA* r = RSA_new();
  if (!key_to_RSA(private_key, r)) {
    printf("load_client_certs_and_key, error 1\n");
    return false;
  }
  EVP_PKEY* auth_private_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(auth_private_key, r);

  X509* x509_auth_key_cert= X509_new();
  string auth_cert_str;
  auth_cert_str.assign((char*)private_key_.certificate().data(), private_key_.certificate().size());
  if (!asn1_to_x509(auth_cert_str, x509_auth_key_cert)) {
    printf("load_client_certs_and_key, error 2\n");
      return false;
  }

  STACK_OF(X509)* stack = sk_X509_new_null();
  if (sk_X509_push(stack, root_cert_) == 0) {
    printf("load_client_certs_and_key, error 3\n");
    return false;
  }

  if (SSL_CTX_use_cert_and_key(ssl_ctx_, x509_auth_key_cert, auth_private_key, stack, 1) <= 0 ) {
    printf("load_client_certs_and_key, error 5\n");
      return false;
  }
  if (!SSL_CTX_check_private_key(ssl_ctx_) ) {
    printf("load_client_certs_and_key, error 6\n");
    return false;
  }
  SSL_CTX_add_client_CA(ssl_ctx_, root_cert_);
  SSL_CTX_add1_to_CA_list(ssl_ctx_, root_cert_);
  return true;
}

//  void (*func)(secure_authenticated_channel& channel)
bool secure_authenticated_channel::server_channel_accept_and_auth(
    void (*func)(secure_authenticated_channel& channel)) {

  // accept and carry out auth
  int res = SSL_accept(ssl_);
  if (res != 1) {
    printf("Server: Can't SSL_accept connection\n");
    unsigned long code = ERR_get_error();
    printf("Accept error: %s\n", ERR_lib_error_string(code));
    print_ssl_error(SSL_get_error(ssl, res));
    SSL_free(ssl_);
    return;
  }
  sock_ = SSL_get_fd(ssl_);
#ifdef DEBUG
  printf("Accepted ssl connection using %s \n", SSL_get_cipher(ssl));
#endif

    // Verify a client certificate was presented during the negotiation
    peer_cert_ = SSL_get_peer_certificate(ssl_);
    if(peer_cert_) {
      printf("Server: Peer cert presented in nego\n");
    } else {
      printf("Server: No peer cert presented in nego\n");
    }
  
  if (!client_auth_server(root_cert_, ssl_)) {
    printf("Client auth failed at server\n");
    return;
  }
  channel_initialized_ = true;
  func(this);
  return true;
}

bool secure_authenticated_channel::init_server_ssl(string& host_name, int port,
      x509* root_cert, key_message& private_key) {
  SSL_load_error_strings();

  // set keys and cert
  return true;
}

int secure_authenticated_channel::read(int size, byte* b) {
  return sized_ssl_read(ssl_, b);
}

int secure_authenticated_channel::write(int size, byte* b) {
  return SSL_write(ssl_, b, size);
}

void secure_authenticated_channel::close() {
  close(sock_);
  SSL_free(ssl_);
}

bool secure_authenticated_channel::get_peer_id(string* out) {
  out->assign((char*)peer_id_.data(), peer_id_.size());
  return true;
}

// ---------------------------------------------------------------------------------

void server_application(secure_authenticated_channel& channel) {

  // Read message from client over authenticated, encrypted channel
  string out;
  int n = channel.read(&out);
  printf("SSL server read: %s\n", (const char*) out.data());

  // Reply over authenticated, encrypted channel
  const char* msg = "Hi from your secret server\n";
  channel.write(strlen(msg), (byte*)msg);
}

bool run_me_as_server( const string& host_name, int port,
      X509* x509_policy_cert, key_message& private_key) {

  server_dispatch(server_application, channel)
  return true;
}

void client_application(secure_authenticated_channel& channel) {

  // client sends a message over authenticated, encrypted channel
  const char* msg = "Hi from your secret client\n";
  channel.write(strlen(msg), (byte*)msg);

  // Get server response over authenticated, encrypted channel and print it
  string out;
  int n = channel.read(&out);
  printf("SSL client read: %s\n", out.data());
}

bool run_me_as_client( const string& host_name, int port,
      X509* x509_policy_cert, key_message& private_key) {

  secure_authenticated_channel channel("client");
  if (!channel.init_client_ssl(host_name, port, x509_policy_cert, private_key)) {
  }

  // This is the actual application code.
  client_application(channel);
  return true;
}

int main(int an, char** av) {
  gflags::ParseCommandLineFlags(&an, &av, true);
  an = 1;
  ::testing::InitGoogleTest(&an, av);

  if (FLAGS_operation == "") {
    printf("example_app.exe --print_all=true|false --operation=op --policy_host=policy-host-address --policy_port=policy-host-port\n");
    printf("\t --data_dir=-directory-for-app-data --server_app_host=my-server-host-address --server_app_port=server-host-port\n");
    printf("\t --policy_cert_file=self-signed-policy-cert-file-name --policy_store_file=policy-store-file-name\n");
    printf("Operations are: cold-init, warm-restart, get-certifier, run-app-as-client, run-app-as-server\n");
    return 0;
  }

  SSL_library_init();

#if 0
  string store_file(FLAGS_data_dir);
  store_file.append(FLAGS_policy_store_file);
  app_trust_data = new cc_trust_data(enclave_type, purpose, store_file);
  if (app_trust_data == nullptr) {
    printf("couldn't initialize trust object\n");
    return 1;
  }

  // Init policy key info
  if (!app_trust_data->init_policy_key(initialized_cert_size, initialized_cert)) {
    printf("Can't init policy key\n");
    return false;
  }

    if (!run_me_as_client(FLAGS_policy_host.c_str(), FLAGS_policy_port
app_trust_data->x509_policy_cert_,
          app_trust_data->private_auth_key_,
)) {
      printf("run-me-as-client failed\n");
      ret = 1;
      goto done;
    }
  } else if (FLAGS_operation == "run-app-as-server") {
    if (!app_trust_data->warm_restart()) {
      printf("warm-restart failed\n");
      ret = 1;
      goto done;
    }
    if (!run_me_as_server(app_trust_data->x509_policy_cert_,
          app_trust_data->private_auth_key_,
          FLAGS_policy_host.c_str(), FLAGS_policy_port)) {
      printf("run-me-as-server failed\n");
      ret = 1;
      goto done;
    }
  } else {
    printf("Unknown operation\n");
  }
#endif

done:
  return ret;
}
