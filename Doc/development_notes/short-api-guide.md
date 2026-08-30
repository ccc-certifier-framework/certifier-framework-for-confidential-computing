# Programmer Guide: APIs Used by sample_apps and vm_model_tools

This guide documents library functions that are actively used by application code under `sample_apps/` and `vm_model_tools/`.

The Cerrtifier API has changed slightly over time to support multiple security domains and new enclaves.  I'll try
to keep this description "up-to-date."  As always, the actual sample and tests (like those in "certifier_tests.cc"
built by "certifier_tests.mak" provide the most detailed guide on employing the certifier library.

This document does not include a descrtiption of the structure or libraries for the Certification Server.
Developers are generally not expected to modify or add to this code but the instructions and files in "certifier_service"
and the tests in "certlib" have some information.  The Certifier uses protobufs for serializing wire formats and files.
The directory "certifier_service/certoprotos" has these definitions.

The Certifier is organized around two core concepts:
- Runtime trust setup and certification 
- Authenticated channel setup and I/O

There are a bunch of supporting functions (like secure storage) that a developer may find generally useful.
All developer accessible functions are contained in the header files:
- `include/certifier_framework.h`
- `include/certifier_utilities.h`
These, in turn, rely on implementing function in, for example,
- `include/support.h`
- `include/cc_helpers.h`

Almost all important call can be seen in action in the consolidated app:
- `sample_apps/common/example_app.cc`
Almost all the sample apps use this common code as the basis for the applications.
"vm_model_tool" utilities" are also instructive, they are in:
- `vm_model_tools/src/cf_utility.cc`
- `vm_model_tools/src/cf_key_client.cc`
- `vm_model_tools/src/cf_key_server.cc`
The utilites to generate keys and build policy are in the "utilities" directory.
Hopefully, developers won't need to understand the details of these but they may
be generally worth a glance.

Finally, there are support programs like:
- `sample_apps/simple_app_under_app_service/start_program.cc` which implements the application service application initialization
for testing.
TPM based applications, employ a two-pass certification process (unlike any other enclaves), the file
- `sample_apps/simple_app_under_tpm/first_pass.cc` implements this protocol.


## Trust manager lifecycle APIs

The dominant application pattern is:
1. Build enclave parameter list from files.  This includes locating and copying existing files (like the ARK, ASK and VCEK certs, in
the case of SEV)
2. Create a `cc_trust_manager` object which serves as a "full service" interface to certification.  The declaration of this
object names the enclave type (e.g., sev-enclave, tpm-enclave), cipher suite used for authentication, confidentiality and integrity, and
the enclave purpose.  There are two purposes: authentication and attestation.  Authentication is the most common purpose it refers to
the process of provisioning and certifying a public key for authenticating the enclave to other enclaves in the Security Domain.
The other purpose, "attestation", refers to the certifying an attestation key for a subordinate enclave (like the application-enclave)
within another enclave liek SEV.
3. The calls to the cc_trust manager interacts with the enclave, providing uniform access to "attest." "seal," and "unseal."  It
generates keys used in common Confidential Computing workflows and cans store the keys safely in a "secure store" between enclave
acctivations.
5. The most important functionality provided by this object is "certification".  Certification consiste of generating an authentication key,
assembling security domain evidence (including an attestation" that allows it to "prove" to a "certification service" that it conforms to
all "security domain" rules.  Certification results in an "admissions certificate," signed by the "policy key" for a security domain that
can be used in interattions with other enclave in the domain to establish trust using the public key named in the "admissions certificate."
Typically, this certificate as well as the cprresponding public and private keys maintained by the cc_trust_manager to
open secure channels.  Opening and using these secure channels between enclaves in a security domain is handled by another important object
in the Certifier API, the "secure_authenticated_channel" described below.

### `cc_trust_manager` constructor

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

### `initialize_enclave`
Header: ```cpp bool initialize_enclave(int n, string* params); ``` What it does: - Platform-neutral enclave/provider initialization entrypoint.  - Dispatches to platform-specific initialization based on `enclave_type` and `params`.  Parameters are enclave specific and are generally strings (for example, the files containing the ARK, ASK and VCEK certs in the case of SAV):
- `n`: number of parameter strings in `params`.
- `params`: ordered platform-specific arguments.
  - Simulated enclave examples: attestation key, measurement, endorsement.
  - SEV examples: ARK cert, ASK cert, VCEK cert.
Since the arguments are enclave specific, the API arguments can not be described in a general way.

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

### `initialize_store` and `initialize_keys`

Headers:
```cpp
bool initialize_store();
bool initialize_keys(const string& public_key_alg,
                     const string& symmetric_key_alg,
                     bool force = false);
```

What they do:
- `initialize_store`: loads/creates the policy store state.
- `initialize_keys`: generates or loads auth/service/symmetric key material.  This includes the
keys to encrypt the policy-store and app-specific information as well as the "authentication" key
for the enclave.

Parameters (`initialize_keys`):
- `public_key_alg`: public/signing algorithm name string (for example RSA-2048 family constants).
- `symmetric_key_alg`: authenticated symmetric algorithm string.
- `force`: when true, forces key regeneration/reinitialization, even if there are existing keys.

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

### Domain setup: `initialize_new_domain`, `initialize_existing_domain`, `certify`

Headers:
```cpp
bool initialize_new_domain(const string& domain_name,
                           const string& purpose,
                           const string& symmetric_key_alg,
                           const string& host_url,
                           int port);

bool initialize_existing_domain(const string& domain_name);
```

What they do:
- `initialize_new_domain`: creates domain metadata and policy anchor data for a new domain.  This includes generating keys, interacting with
the certification service, obtaining an admissions certificate and storing all this material afely in the "policy-store."
- `initialize_existing_domain`: loads an existing domain entry from material in the policy store.  This includes authentication keys and related

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


### ` certify

Header:
```cpp
bool certify(const string& domain_name)
```

What it does:
- 

Parameters:
- ``: 
```

## More  cc_trust_manager methods

### `
 find_certifier

Header:
```cpp
certifiers *find_certifier_by_domain_name(const string &domain_name);
```

What it does:
- 

Parameters:
- ``: 
```


### save_store`

Headers:
```cpp
certifiers* find_certifier_by_domain_name(const string& domain_name);
bool save_store();
```

What they do:
- Finds a domain record (`certifiers`) for in the policy-store and performs status checks or updates.
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

### Teardown: `close_enclave`, `clear_sensitive_data`

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

Most enclaves handle teardown without calling "close-enclave" gracefully but some (like the tpm-enclave) do not.

## 2) Authenticated channel APIs

These APIs are used for app-to-app secure communication after certification.

### `secure_authenticated_channel` constructor

Header:
```cpp
secure_authenticated_channel(string& role);
```

What it does:
- Creates channel wrapper in `client` or `server` role using the application authentication keys and admissions
certificates in the policy store.  The secure channels are established using TLS with mutual auth.  As a result,
a channel has a server side and client side just like TLS.

Parameter:
- `role`: usually `"client"` or `"server"`.

Snippet:
```cpp
string my_role("client");
secure_authenticated_channel channel(my_role);
```

### `init_client_ssl` (domain + trust manager overload)

Header:
```cpp
bool init_client_ssl(const string& domain_name,
                     const string& host_name,
                     int port,
                     cc_trust_manager& mgr);
```

What it does:
- Builds TLS context and client socket using the relevant authentication keys and admissions certificates in the policy store.
It used the cc_trust_manager to interact with the policy store.
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

### Using the secure channel: `read`, `write`, `close`

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

### `server_dispatch`

Header (NEW_API overload):
```cpp
bool server_dispatch(const string& domain_name,
                     const string& host_name,
                     int port,
                     cc_trust_manager& mgr,
                     void (*func)(secure_authenticated_channel&));
```

What it does:
- Creates authenticated server endpoint and dispatches accepted channels to callback.  This allows developers
to avoid creating a "server endpoint" on their own.

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

## File and data helper APIs used by apps/tools

These are optional (but useful) utility API's.

### `read_file_into_string`

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

### `write_file_from_string`

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

## Additional API calls

Most applications will just use the functions above but here are other useful functions that
you can use in special circumstances.


##  Policy Store methods

### `policy_store` constructor

Header:
```cpp
policy_store((unsigned max_ents);
```

What it does:
- 

Parameters:
- ``: 

policy_store* ps =
    new policy_store(500);
```

### `get_num_entries

Header:
```cpp
  unsigned      get_num_entries();
```

What it does:
- 

Parameters:
- ``: 
```

### ` find_entry

Header:
```cpp
  int           find_entry(const string &tag, const string &type);
```

What it does:
- 

Parameters:
- ``: 
```

### tag `

Header:
```cpp
  const string *tag(unsigned ent);
```

What it does:
- 

Parameters:
- ``: 
```

### `type

Header:
```cpp
  const string *type(unsigned ent);
```

What it does:
- 

Parameters:
- ``: 
```

### ` get_entry

Header:
```cpp
  store_entry  *get_entry(unsigned ent);
```

What it does:
- 

Parameters:
- ``: 
```

### ` delete_entry

Header:
```cpp
  bool          delete_entry(unsigned ent);
```

What it does:
- 

Parameters:
- ``: 
```

### ` get

Header:
```cpp
  bool          get(unsigned ent, string *v);
```

What it does:
- 

Parameters:
- ``: 
```

### ` put

Header:
```cpp
  bool          put(unsigned ent, const string v);
```

What it does:
- 

Parameters:
- ``: 
```

### ` update_or_insert

Header:
```cpp
  bool          update_or_insert(const string &tag,
                                 const string &type,
                                 const string &value);
```

What it does:
- 

Parameters:
- ``: 
```

### ` print();

Header:
```cpp
  void          print();
```

What it does:
- 

Parameters:
- ``: 
```

### ` Serialize

Header:
```cpp
  bool          Serialize(string *psout);
```

What it does:
- 

Parameters:
- ``: 
```

### ` Deserialize

Header:
```cpp
  bool          Deserialize(string &in);
```

What it does:
- 

Parameters:
- ``: 
```



## Low level trust support functions


### Seal

Header:
```cpp
bool Seal(const string &enclave_type,
          const string &enclave_id,
          int           in_size,
          byte         *in,
          int          *size_out,
          byte         *out);
```

What it does:
- 

Parameters:
- ``: 
```


### Unseal

Header:
```cpp
bool Unseal(const string &enclave_type,
            const string &enclave_id,
            int           in_size,
            byte         *in,
            int          *size_out,
            byte         *out);
```

What it does:
- 

Parameters:
- ``: 
```


### Attest

Header:
```cpp
bool Attest(const string &enclave_type,
            int           what_to_say_size,
            byte         *what_to_say,
            int          *size_out,
            byte         *out);
```

What it does:
- 

Parameters:
- ``: 
```

## Utilities


### protect_blob

Header:
```cpp
bool protect_blob(const string &enclave_type,
                  key_message  &key,
                  int           size_unencrypted_data,
                  byte         *unencrypted_data,
                  int          *size_protected_blob,
                  byte         *blob);
```

What it does:
- 

Parameters:
- ``: 
```


### unprotect_blob


Header:
```cpp
bool unprotect_blob(const string &enclave_type,
                    int           size_protected_blob,
                    byte         *protected_blob,
                    key_message  *key,
                    int          *size_of_unencrypted_data,
                    byte         *data);
```

What it does:
- 

Parameters:
- ``: 
```


###  reportect_blob

Header:
```cpp
bool reprotect_blob(const string &enclave_type,
                    key_message  *key,
                    int           size_protected_blob,
                    byte         *protected_blob,
                    int          *size_new_encrypted_blob,

                    byte         *data);
```

What it does:
- 

Parameters:
- ``: 
```


## Still nore on trust manager object data and methods

### ` accelerator accelerators_

Header:
```cpp
  accelerator accelerators_[max_accerlerators];
```

What it does:
- 

Parameters:
- ``: 
```


### ` add_accelerator

Header:
```cpp
  bool add_accelerator(const string &acc_type, int num_certs, string *certs);
```

What it does:
- 

Parameters:
- ``: 
```

### ` accelerator_verified

Header:
```cpp
  bool accelerator_verified(const string &acc_type);
```

What it does:
- 

Parameters:
- ``: 
```


### ` cc_auth_key_initialized_

Header:
```cpp
  bool        cc_auth_key_initialized_;
```

What it does:
- 

Parameters:
- ``: 
```

### ` private_auth_key_;

Header:
```cpp
  key_message private_auth_key_;
```

What it does:
- 

Parameters:
- ``: 
```

### ` public_auth_key_;

Header:
```cpp
  key_message public_auth_key_;
```

What it does:
- 

Parameters:
- ``: 
```


### ` cc_service_key_initialized_;

Header:
```cpp
  bool        cc_service_key_initialized_;
```

What it does:
- 

Parameters:
- ``: 
```

### ` private_service_key_;

Header:
```cpp
  key_message private_service_key_;
```

What it does:
- 

Parameters:
- ``: 
```

### ` public_service_key_;

Header:
```cpp
  key_message public_service_key_;
```

What it does:
- 

Parameters:
- ``: 
```


### ` cc_service_cert_initialized_

Header:
```cpp
  bool   cc_service_cert_initialized_;
```

What it does:
- 

Parameters:
- ``: 
```

### ` serialized_service_cert_

Header:
```cpp
  string serialized_service_cert_;
```

What it does:
- 

Parameters:
- ``: 
```

### ` cc_service_platform_rule_initialized_;

Header:
```cpp
  bool                 cc_service_platform_rule_initialized_;
```

What it does:
- 

Parameters:
- ``: 
```

### ` cc_symmetric_key_initialized_

Header:
```cpp
  bool        cc_symmetric_key_initialized_;
```

What it does:
- 

Parameters:
- ``: 
```

### ` symmetric_key_bytes_

Header:
```cpp
  byte        symmetric_key_bytes_[max_symmetric_key_size_];
```

What it does:
- 

Parameters:
- ``: 
```

### ` symmetric_key_

Header:
```cpp
  key_message symmetric_key_;
```

What it does:
- 

Parameters:
- ``: 
```

### ` cc_sealing_key_initialized_

Header:
```cpp
  bool        cc_sealing_key_initialized_;
```

What it does:
- 

Parameters:
- ``: 
```

### ` sealing_key_bytes_

Header:
```cpp
  byte        sealing_key_bytes_[max_symmetric_key_size_];
```

What it does:
- 

Parameters:
- ``: 
```

### `
  num_certified_domains_

Header:
```cpp
  int          num_certified_domains_;
```

What it does:
- 

Parameters:
- ``: 
```


### `python_initialize_simulated_enclave

Header:
```cpp
  bool python_initialize_simulated_enclave(
      const byte *serialized_attest_key,
      int         attest_key_size,
      const byte *measurement,
      int         measurement_size,
      const byte *serialized_attest_endorsement,
      int         attest_key_signed_claim_size);
```

What it does:
- 

Parameters:
- ``: 
```

### ` initialize_sev_enclave

Header:
```cpp
  bool initialize_sev_enclave(const string &ark_der_cert,
                              const string &ask_der_cert,
                              const string &vcek_der_cert);
```

What it does:
- 

Parameters:
- ``: 
```

### ` initialize_tpm_enclave

Header:
```cpp
  bool initialize_tpm_enclave(const string &device_name,
                              const string &endorsement_cert_file_name,
                              const string &endorsement_cert_chain_file_name,
                              const string &seal_hierarchy_file_name,
                              const string &quote_hierarchy_file_name,
                              const string &tpm_pcr_list,
                              const string &quote_cert_file_name);
```

What it does:
- 

Parameters:
- ``: 
```

### ` initialize_gramine_enclave

Header:
```cpp
  bool initialize_gramine_enclave(const int size, byte *cert);
```

What it does:
- 

Parameters:
- ``: 
```

### ` initialize_oe_enclave

Header:
```cpp
  bool initialize_oe_enclave(const string &cert);
```

What it does:
- 

Parameters:
- ``: 
```

### ` initialize_application_enclave

Header:
```cpp
  bool initialize_application_enclave(const string &parent_enclave_type,
                                      int           in_fd,
                                      int           out_fd);
```

What it does:
- 

Parameters:
- ``: 
```

### ` put_trust_data_in_store

Header:
```cpp
  bool put_trust_data_in_store();
```

What it does:
- 

Parameters:
- ``: 
```

### ` get_trust_data_from_store

Header:
```cpp
  bool get_trust_data_from_store();
```

What it does:
- 

Parameters:
- ``: 
```

### ` initialize_store

Header:
```cpp
  bool initialize_store();
```

What it does:
- 

Parameters:
- ``: 
```

### ` fetch_store

Header:
```cpp
  bool fetch_store();
```

What it does:
- 

Parameters:
- ``: 
```

### ` save_store

Header:
```cpp
  bool save_store();
```

What it does:
- 

Parameters:
- ``: 
```

### ` clear_sensitive_data

Header:
```cpp
  void clear_sensitive_data();
```

What it does:
- 

Parameters:
- ``: 
```

### ` generate_symmetric_key

Header:
```cpp
  bool generate_symmetric_key(bool regen);
```

What it does:
- 

Parameters:
- ``: 
```

### ` generate_sealing_key

Header:
```cpp
  bool generate_sealing_key(bool regen);
```

What it does:
- 

Parameters:
- ``: 
```

### ` generate_auth_key

Header:
```cpp
  bool generate_auth_key(bool regen);
```

What it does:
- 

Parameters:
- ``: 
```

### ` generate_service_key

Header:
```cpp
  bool generate_service_key(bool regen);
```

What it does:
- 

Parameters:
- ``: 
```

### ` find_certifier_by_domain_name

Header:
```cpp
  certifiers *find_certifier_by_domain_name(const string &domain_name);
```

What it does:
- 

Parameters:
- ``: 
```

### ` initialize_keys

Header:
```cpp
  bool        initialize_keys(const string &public_key_alg,
                              const string &symmetric_key_alg,
                              bool          force = false);
```

What it does:
- 

Parameters:
- ``: 
```

### ` certify

Header:
```cpp
  bool        certify(const string &domain_name);
```

What it does:
- 

Parameters:
- ``: 
```

### ` get_admissions_cert(

Header:
```cpp
  bool get_admissions_cert(const string &domain_name, string *admin_cert);
```

What it does:
- 

Parameters:
- ``: 
```

### ` admissions_cert_valid_status

Header:
```cpp
  bool admissions_cert_valid_status(const string &domain_name);
```

What it does:
- 

Parameters:
- ``: 
```


### ` print_trust_data

Header:
```cpp
  void print_trust_data();
```

What it does:
- 

Parameters:
- ``: 
```


### ` init_peer_certification_data

Header:
```cpp
  bool init_peer_certification_data(const string &public_key_alg);
```

What it does:
- 

Parameters:
- ``: 
```

### ` recover_peer_certification_data

Header:
```cpp
  bool recover_peer_certification_data();
```

What it does:
- 

Parameters:
- ``: 
```

### ` get_peer_certification

Header:
```cpp
  bool get_peer_certification(const string &host_name, int port);
```

What it does:
- 

Parameters:
- ``: 
```

### ` run_peer_certification_service

Header:
```cpp
  bool run_peer_certification_service(const string &host_name, int port);
```

What it does:
- 

Parameters:
- ``: 
```

### ` add_or_update_new_domain

Header:
```cpp
  bool add_or_update_new_domain(const string &domain_name,
                                const string &purpose,
                                const string &policy_cert,
                                const string &host,
                                int           port);
```

What it does:
- 

Parameters:
- ``: 
```


## Certifiers object 

class certifiers {
 private:
  cc_trust_manager *owner_;

 public:
  string signed_rule_;
  string purpose_;
  string domain_name_;

  string domain_policy_cert_;
  bool        is_initialized_;
  X509       *x509_policy_cert_;
  key_message public_policy_key_;
  string host_;
  int    port_;
  string admissions_cert_;
  bool   is_certified_;

  certifiers(cc_trust_manager *owner);
  bool init_certifiers_data_new(const string &domain_name,
                                const string &purpose,
                                const string &cert,
                                const string &host,
                                int           port);
};

## Crypto helpers


### make_certifier_rsa_key

Header:
```cpp
bool make_certifier_rsa_key(int n, key_message *k);
```

What it does:
- 

Parameters:
- ``: 
```

### make_certifier_ecc_key

Header:
```cpp
bool make_certifier_ecc_key(int n, key_message *k);

What it does:
- 

Parameters:
- ``: 
```

### key_to_RSA

Header:
```cpp
bool key_to_RSA(const key_message &k, RSA *r);
```

What it does:
- 

Parameters:
- ``: 
```



### RSA_to_key

Header:
```cpp
bool RSA_to_key(const RSA *r, key_message *k);
```

What it does:
- 

Parameters:
- ``: 
```



### generate_new_ecc_key

Header:
```cpp
EC_KEY *generate_new_ecc_key(int num_bits);
```

What it does:
- 

Parameters:
- ``: 
```


### key_to_ECC

Header:
```cpp
EC_KEY *key_to_ECC(const key_message &kr);

What it does:
- 

Parameters:
- ``: 
```


###  ECC_to_key

Header:
```cpp
bool    ECC_to_key(const EC_KEY *e, key_message *k);
```

What it does:
- 

Parameters:
- ``: 
```


### digest_message
Header:
```cpp
bool digest_message(const char  *alg,
                    const byte  *message,
                    int          message_len,
                    byte        *digest,
                    unsigned int digest_len);
```

What it does:
- 

Parameters:
- ``: 
```


### authenticated_encrypt

### `

Header:
```cpp
bool authenticated_encrypt(const char *alg,
                           byte       *in,
                           int         in_len,
                           byte       *key,
                           int         key_len,
                           byte       *iv,
                           int         iv_len,
                           byte       *out,
                           int        *out_size);
```

What it does:
- 

Parameters:
- ``: 
```


###  authenticated_decrypt

Header:
```cpp
bool authenticated_decrypt(const char *alg,
                           byte       *in,
                           int         in_len,
                           byte       *key,
                           int         key_len,
                           byte       *out,
                           int        *out_size);
```

What it does:
- 

Parameters:
- ``: 
```


### get_random

Header:
```cpp
bool get_random(int num_bits, byte *out);

What it does:
- 

Parameters:
- ``: 
```



### cipher_block_byte_size

Header:
```cpp
int cipher_block_byte_size(const char *alg_name);
```

What it does:
- 

Parameters:
- ``: 
```


### cipher_key_byte_size

Header:
```cpp
int cipher_key_byte_size(const char *alg_name);
```

What it does:
- 

Parameters:
- ``: 
```


### digest_output_byte_size

Header:
```cpp
int digest_output_byte_size(const char *alg_name);
```

What it does:
- 

Parameters:
- ``: 
```


### mac_output_byte_size

Header:
```cpp
int mac_output_byte_size(const char *alg_name);

What it does:
- 

Parameters:
- ``: 
```


## Specialized time structures


### time_t_to_tm_time

Header:
```cpp
bool time_t_to_tm_time(time_t *t, struct tm *tm_time);

What it does:
- 

Parameters:
- ``: 
```


### tm_time_to_time_point

Header:
```cpp
bool tm_time_to_time_point(struct tm *tm_time, time_point *tp);

What it does:
- 

Parameters:
- ``: 
```

### asn1_time_to_tm_time

Header:
```cpp
bool asn1_time_to_tm_time(const ASN1_TIME *s, struct tm *tm_time);

What it does:
- 

Parameters:
- ``: 
```


### get_not_before_from_cert

Header:
```cpp
bool get_not_before_from_cert(X509 *c, time_point *tp);

What it does:
- 

Parameters:
- ``: 
```


### get_not_after_from_cert

Header:
```cpp
bool get_not_after_from_cert(X509 *c, time_point *tp);

What it does:
- 

Parameters:
- ``: 
```


### time_now

Header:
```cpp
bool time_now(time_point *t);
```

What it does:
- 

Parameters:
- ``: 
```


### time_to_string

Header:
```cpp
bool time_to_string(time_point &t, string *s);

What it does:
- 

Parameters:
- ``: 
```


### string_to_time

Header:
```cpp
bool string_to_time(const string &s, time_point *t);

What it does:
- 

Parameters:
- ``: 
```


### add_interval_to_time_point

Header:
```cpp
bool add_interval_to_time_point(time_point &t_in,
                                double      hours,
                                time_point *out);

What it does:
- 

Parameters:
- ``: 
```


### Compare_time

Header:
```cpp
int  compare_time(time_point &t1, time_point &t2);

What it does:
- 

Parameters:
- ``: 
```

### print_time_point

Header:
```cpp
void print_time_point(time_point &t);
```

What it does:
- 

Parameters:
- ``: 
```

### print_entity

Header:
```cpp
void print_entity(const entity_message &em);
```

What it does:
- 

Parameters:
- ``: 
```

### `

Header:
```cpp
void print_key(const key_message &k);

What it does:
- 

Parameters:
- ``: 
```



## Certificates


### produce_artifact

Header:
```cpp
bool produce_artifact(key_message &signing_key,
                      string      &issuer_name_str,
                      string      &issuer_description_str,
                      key_message &subject_key,
                      string      &subject_name_str,
                      string      &subject_description_str,
                      uint64_t     sn,
                      double       secs_duration,
                      X509        *x509,
                      bool         is_root,
                      bool         vcek = false);

What it does:
- 

Parameters:
- ``: 
```

### verify_artifact

Header:
```cpp
bool verify_artifact(X509        &cert,
                     key_message &verify_key,
                     string      *issuer_name_str,
                     string      *issuer_description_str,
                     key_message *subject_key,
                     string      *subject_name_str,
                     string      *subject_description_str,
                     uint64_t    *sn);

What it does:
- 

Parameters:
- ``: 
```



### asn1_to_x509

Header:
```cpp
bool asn1_to_x509(const string &in, X509 *x);

What it does:
- 

Parameters:
- ``: 
```


### x509_to_asn1

Header:
```cpp
bool x509_to_asn1(X509 *x, string *out);

What it does:
- 

Parameters:
- ``: 
```

### check_date_range

Header:
```cpp
bool check_date_range(const string &nb, const string &na);

What it does:
- 

Parameters:
- ``: 
```


### file_size

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

## socket based helpers used by app service and TPM flows

### `sized_socket_write` and `sized_socket_read`

Headers:
```cpp
int sized_socket_write(int fd, int size, byte* buf);
int sized_socket_read(int fd, string* out);

What they do:
- Implement length-prefixed socket framing used by non-TLS request/response paths.
- `write` sends exactly one framed message.
- `read` receives one framed message.

Parameters:
- `fd`: connected TCP socket descriptor.
- `size`: number of bytes in outgoing message.
- `buf`: outgoing bytes.
- `out`: destination string for incoming bytes.
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

1. Instantiate `cc_trust_manager` with correct enclave type and store path.
2. Call `initialize_enclave`, `initialize_store`, `initialize_keys`, if needed.
3. Call `initialize_new_domain` (first boot) or `initialize_existing_domain` (on restart).
4. Ensure certification has occured (`certify` or check `is_certified_` status).
5. Use `secure_authenticated_channel` to establish a secure, policy-compliant encrypted and integrity protected secure channel between two enclaves.
6. Persist updates with `ave_store` and clean up with `close_enclave` and `clear_sensitive_data`.

## 6) Notes

- This document covers the most recent API.  The old API is still supported but is depricated.  The flag  NEW_API in the make files signals the use of the new API in a bluild.
- For additional end-to-end examples, see `sample_apps/common/example_app.cc` and `vm_model_tools/src/cf_utility.cc`.
