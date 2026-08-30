# Programmer Guide: APIs Used by sample_apps and vm_model_tools

This guide documents library functions that are actively used by application code under `sample_apps/` and `vm_model_tools/`.

Scope:
- Runtime trust setup and certification
- Authenticated channel setup and I/O
- File and sized-socket helpers

Primary headers for these APIs:
- `include/certifier_framework.h`
- `include/certifier_utilities.h`
- `include/support.h`
- `include/cc_helpers.h`

Representative call sites:
- `sample_apps/common/example_app.cc`
- `sample_apps/simple_app_under_app_service/start_program.cc`
- `sample_apps/simple_app_under_tpm/first_pass.cc`
- `vm_model_tools/src/cf_utility.cc`
- `vm_model_tools/src/cf_key_client.cc`

## 1) Trust manager lifecycle APIs

The dominant pattern in both application trees is:
1. Build enclave parameter list from files.
2. Create a `cc_trust_manager`.
3. Initialize enclave, store, and keys.
4. Initialize or load domain.
5. Certify domain when needed.
6. Use admissions material to open secure channels.

### 1.1 `cc_trust_manager` constructor

Header:
```cpp
cc_trust_manager(const string& enclave_type,
                 const string& purpose,
                 const string& policy_store_name);
```

What it does:
- Creates the main trust-state object for one process.
- Binds it to an enclave type, intended purpose, and local store file.

Parameters:
- `enclave_type`: platform adapter selector, typically `simulated-enclave`, `sev-enclave`, `tpm-enclave`, `gramine-enclave`, `oe-enclave`.
- `purpose`: commonly `authentication` in sample apps.
- `policy_store_name`: path to the persisted policy store.

Snippet (used in both sample apps and vm tools):
```cpp
string purpose("authentication");
string store_file(FLAGS_data_dir);
store_file.append(FLAGS_policy_store_file);

cc_trust_manager* trust_mgr =
    new cc_trust_manager(enclave_type, purpose, store_file);
```

### 1.2 `initialize_enclave`

Header:
```cpp
bool initialize_enclave(int n, string* params);
```

What it does:
- Platform-neutral enclave/provider initialization entrypoint.
- Dispatches to platform-specific initialization based on `enclave_type` and `params`.

Parameters:
- `n`: number of parameter strings in `params`.
- `params`: ordered platform-specific arguments.
  - Simulated enclave examples: attestation key, measurement, endorsement.
  - SEV examples: ARK cert, ASK cert, VCEK cert.

Snippet:
```cpp
string* params = nullptr;
int n = 0;
if (!get_enclave_parameters(&params, &n)) {
  return 1;
}
if (!trust_mgr->initialize_enclave(n, params)) {
  return 1;
}
delete[] params;
```

### 1.3 `initialize_store` and `initialize_keys`

Headers:
```cpp
bool initialize_store();
bool initialize_keys(const string& public_key_alg,
                     const string& symmetric_key_alg,
                     bool force = false);
```

What they do:
- `initialize_store`: loads/creates and wires the policy store state.
- `initialize_keys`: generates or loads auth/service/symmetric key material.

Parameters (`initialize_keys`):
- `public_key_alg`: public/signing algorithm name string (for example RSA-2048 family constants).
- `symmetric_key_alg`: authenticated symmetric algorithm string.
- `force`: when true, forces key regeneration/reinitialization.

Snippet:
```cpp
if (!trust_mgr->initialize_store()) {
  return 1;
}
if (!trust_mgr->initialize_keys(FLAGS_public_key_algorithm,
                                FLAGS_symmetric_key_algorithm,
                                false)) {
  return 1;
}
```

### 1.4 Domain setup: `initialize_new_domain`, `initialize_existing_domain`, `certify`

Headers:
```cpp
bool initialize_new_domain(const string& domain_name,
                           const string& purpose,
                           const string& symmetric_key_alg,
                           const string& host_url,
                           int port);

bool initialize_existing_domain(const string& domain_name);

bool certify(const string& domain_name);
```

What they do:
- `initialize_new_domain`: creates domain metadata and policy anchor data for a new domain.
- `initialize_existing_domain`: loads an existing domain entry from store.
- `certify`: performs admission certification with certifier service for that domain.

Parameters:
- `domain_name`: policy domain label (for example `dom0`).
- `purpose`: generally `authentication`.
- `symmetric_key_alg`: authenticated symmetric algorithm for domain operations.
- `host_url`, `port`: certifier service endpoint.

Snippet:
```cpp
if (!trust_mgr->initialize_new_domain(FLAGS_domain_name,
                                      purpose,
                                      serialized_policy_cert,
                                      FLAGS_policy_host,
                                      FLAGS_policy_port)) {
  return 1;
}

if (!trust_mgr->initialize_existing_domain(FLAGS_domain_name)) {
  return 1;
}

if (!trust_mgr->certify(FLAGS_policy_domain_name)) {
  return 1;
}
```

### 1.5 Domain lookup and persistence: `find_certifier_by_domain_name`, `save_store`

Headers:
```cpp
certifiers* find_certifier_by_domain_name(const string& domain_name);
bool save_store();
```

What they do:
- Finds a domain record (`certifiers`) for status checks or updates.
- Persists updated trust data to the policy store file.

Snippet:
```cpp
certifiers* c = trust_mgr->find_certifier_by_domain_name(FLAGS_policy_domain_name);
if (c == nullptr) {
  return false;
}
if (!c->is_certified_) {
  return false;
}
if (!trust_mgr->save_store()) {
  return false;
}
```

### 1.6 Teardown: `close_enclave`, `clear_sensitive_data`

Headers:
```cpp
bool close_enclave();
void clear_sensitive_data();
```

What they do:
- `close_enclave`: platform shutdown/cleanup.
- `clear_sensitive_data`: zero/clear in-memory key material maintained by manager.

Snippet:
```cpp
trust_mgr->close_enclave();
trust_mgr->clear_sensitive_data();
delete trust_mgr;
```

## 2) Authenticated channel APIs

These APIs are used for app-to-app secure communication after certification.

### 2.1 `secure_authenticated_channel` constructor

Header:
```cpp
secure_authenticated_channel(string& role);
```

What it does:
- Creates channel wrapper in `client` or `server` role.

Parameter:
- `role`: usually `"client"` or `"server"`.

Snippet:
```cpp
string my_role("client");
secure_authenticated_channel channel(my_role);
```

### 2.2 `init_client_ssl` (domain + trust manager overload)

Header:
```cpp
bool init_client_ssl(const string& domain_name,
                     const string& host_name,
                     int port,
                     cc_trust_manager& mgr);
```

What it does:
- Builds TLS context and client socket.
- Uses domain cert chain and key material tracked in `mgr`.
- Authenticates peer according to certifier trust anchors.

Parameters:
- `domain_name`: which certified domain configuration to use.
- `host_name`: server hostname/IP.
- `port`: server TCP port.
- `mgr`: initialized and certified trust manager.

Snippet:
```cpp
if (!channel.init_client_ssl(FLAGS_domain_name,
                             FLAGS_server_app_host,
                             FLAGS_server_app_port,
                             *trust_mgr)) {
  return 1;
}
```

### 2.3 `read`, `write`, `close`

Headers:
```cpp
int read(string* out);
int write(int size, byte* b);
void close();
```

What they do:
- `write`: sends encrypted/authenticated application bytes.
- `read`: reads one framed message into `out`.
- `close`: closes TLS/session resources.

Parameters:
- `write(size, b)`:
  - `size`: bytes to send.
  - `b`: pointer to bytes.
- `read(out)`:
  - `out`: destination string for received bytes.

Snippet:
```cpp
const char* msg = "Hi from your secret client\n";
channel.write(strlen(msg), (byte*)msg);

string out;
int n = channel.read(&out);
channel.close();
```

### 2.4 `server_dispatch`

Header (NEW_API overload):
```cpp
bool server_dispatch(const string& domain_name,
                     const string& host_name,
                     int port,
                     cc_trust_manager& mgr,
                     void (*func)(secure_authenticated_channel&));
```

What it does:
- Creates authenticated server endpoint and dispatches accepted channels to callback.

Parameters:
- `domain_name`: domain identity to present for server side.
- `host_name`: bind host/IP.
- `port`: bind port.
- `mgr`: certified trust manager.
- `func`: callback invoked per accepted authenticated channel.

Snippet:
```cpp
if (!server_dispatch(FLAGS_domain_name,
                     FLAGS_server_app_host,
                     FLAGS_server_app_port,
                     *trust_mgr,
                     server_application)) {
  return 1;
}
```

## 3) File and data helper APIs used by apps/tools

### 3.1 `read_file_into_string`

Header:
```cpp
bool read_file_into_string(const string& file_name, string* out);
```

What it does:
- Reads entire file contents into a C++ string.
- Used heavily to load enclave parameters, certs, endorsements, and request payloads.

Parameters:
- `file_name`: file path.
- `out`: destination buffer.

Snippet:
```cpp
if (!read_file_into_string(FLAGS_data_dir + FLAGS_attest_key_file, &args[0])) {
  return false;
}
if (!read_file_into_string(FLAGS_data_dir + FLAGS_measurement_file, &args[1])) {
  return false;
}
if (!read_file_into_string(FLAGS_data_dir + FLAGS_platform_attest_endorsement,
                           &args[2])) {
  return false;
}
```

### 3.2 `write_file_from_string`

Header:
```cpp
bool write_file_from_string(const string& file_name, const string& in);
```

What it does:
- Writes a string payload to disk.
- Used by vm tools and TPM first-pass flow to persist certs/keys/results.

Parameters:
- `file_name`: output file path.
- `in`: bytes/string to write.

Snippet:
```cpp
if (!write_file_from_string(FLAGS_output_file, serialized_cryptstore_entry)) {
  return false;
}
```

### 3.3 `file_size`

Header:
```cpp
int file_size(const string& file_name);
```

What it does:
- Returns size of a file or negative on failure.
- Used in vm_model_tools to decide create-vs-open behavior for stores.

Parameter:
- `file_name`: path to check.

Snippet:
```cpp
if (file_size(cryptstore_file_name) < 0) {
  // create cryptstore
} else {
  // open existing cryptstore
}
```

## 4) Sized socket helpers used by app service and TPM flows

### 4.1 `sized_socket_write` and `sized_socket_read`

Headers:
```cpp
int sized_socket_write(int fd, int size, byte* buf);
int sized_socket_read(int fd, string* out);
```

What they do:
- Implement length-prefixed socket framing used by non-TLS request/response paths.
- `write` sends exactly one framed message.
- `read` receives one framed message.

Parameters:
- `fd`: connected TCP socket descriptor.
- `size`: number of bytes in outgoing message.
- `buf`: outgoing bytes.
- `out`: destination string for incoming bytes.

Snippet from app-service launcher:
```cpp
if (sized_socket_write(sock,
                       serialized_request.size(),
                       (byte*)serialized_request.data()) < 0) {
  return 1;
}

string serialized_response;
int n = sized_socket_read(sock, &serialized_response);
if (n < 0) {
  return 1;
}
```

Snippet from TPM activation pass:
```cpp
int sized_write_len = sized_socket_write(sock,
                                         serialized_request.size(),
                                         (byte*)serialized_request.data());
if (sized_write_len < (int)serialized_request.size()) {
  return false;
}

string serialized_response;
int resp_size = sized_socket_read(sock, &serialized_response);
if (resp_size < 0) {
  return false;
}
```

## 5) Common usage checklist

When writing a new tool or sample with this library, the same sequence usually works:

1. Load enclave/cert inputs with `read_file_into_string`.
2. Build `cc_trust_manager` with correct enclave type and store path.
3. Call `initialize_enclave`, `initialize_store`, `initialize_keys`.
4. Call `initialize_new_domain` (first boot) or `initialize_existing_domain` (restart).
5. Ensure certification (`certify` or existing `is_certified_` status).
6. Use `secure_authenticated_channel` or `server_dispatch` for secure app traffic.
7. Persist updates with `save_store` and clean up with `close_enclave` and `clear_sensitive_data`.

## 6) Notes

- Most code paths in these directories use the NEW_API model.
- Many policy/claim generation steps in scripts call utility executables (for example `make_signed_claim_from_vse_clause.exe`) rather than direct C++ function calls.
- For additional end-to-end examples, see `sample_apps/common/example_app.cc` and `vm_model_tools/src/cf_utility.cc`.
