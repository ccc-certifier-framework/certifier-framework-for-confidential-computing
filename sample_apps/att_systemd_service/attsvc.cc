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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <filesystem>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include <certifier_framework.h>

using namespace certifier::framework;

#ifdef ATT_DEBUG
#  define ATT_LOG(priority, format, ...) printf(format "\n", ##__VA_ARGS__)
#else
#  define ATT_LOG(priority, format, ...)                                       \
    do {                                                                       \
      openlog("VMware Attestation Service",                                    \
              LOG_CONS | LOG_PID | LOG_NDELAY,                                 \
              LOG_LOCAL1);                                                     \
      syslog(priority, format, ##__VA_ARGS__);                                 \
      closelog();                                                              \
    } while (0);
#endif

#define ATTSERVICE_DATA_DIR          "/etc/attsvc/"
#define ATTSERVICE_POLICY_STORE_FILE "store.bin"
#define ATTSERVICE_CONFIG_FILE       "config"

#ifdef USE_SIMULATED_ENCLAVE
#  define ATTEST_KEY_FILE              "attest_key_file.bin"
#  define PLAT_ATTEST_ENDORSEMENT_FILE "platform_attest_endorsement.bin"
#  define MEASUREMENT_FILE             "example_app.measurement"
#else
#  define ARK_CERT_FILE  "ark_cert.der"
#  define ASK_CERT_FILE  "ask_cert.der"
#  define VCEK_CERT_FILE "vcek_cert.der"
#endif

#include "policy_key.cc"
cc_trust_data *app_trust_data = nullptr;

static struct _app_config {
  string certifier_host = string("localhost");
  int    certifier_port = 80;
  string client = string("localhost");
  int    client_port = 80;
  int    check_disk = 0;
} app_config;

static bool file_exists(const std::string &name) {
  return (access(name.c_str(), F_OK) != -1);
}

static bool check_disk_encryption() {
  // TODO: Check LUKS encryption first
  ATT_LOG(LOG_INFO, "Disk Encryption Check not implemented yet.");
  return false;
}

static bool certifier_notification(cc_trust_data *app_trust_data,
                                   bool           disk_encrypted) {
  if (app_config.check_disk && !disk_encrypted) {
    ATT_LOG(LOG_INFO, "Disk is not encrypted!");
  }
  if (!app_trust_data->cc_is_certified_) {
    ATT_LOG(LOG_INFO, "Virtual appliance is not certified!");
  } else {
    ATT_LOG(LOG_INFO, "Virtual appliance is certified!");
  }

  if (!app_trust_data->cc_auth_key_initialized_
      || !app_trust_data->cc_policy_info_initialized_) {
    ATT_LOG(LOG_INFO, "Trust data not initialized.");
    return false;
  }

  string                       my_role("client");
  secure_authenticated_channel channel(my_role);
  if (!channel.init_client_ssl(
          app_config.client,
          app_config.client_port,
          app_trust_data->serialized_policy_cert_,
          app_trust_data->private_auth_key_,
          app_trust_data->private_auth_key_.certificate())) {
    ATT_LOG(LOG_INFO,
            "Failed to initialize SSL channel to notification agent.");
    return false;
  }

  // TODO: Dummy agent protocol. Just send SUCCESS/FAILURE.
  const char *msg = "\n";
  if (app_trust_data->cc_is_certified_) {
    msg = "SUCCESS\n";
  } else {
    msg = "FAILURE\n";
  }
  channel.write(strlen(msg), (byte *)msg);
  string out;
  int    n = channel.read(&out);
  ATT_LOG(LOG_INFO, "Agent says: %s\n", out.data());

  return true;
}

static char *trim_space(char *str, int size) {
  int end = strnlen(str, size) - 1;
  while (isspace(str[0]))
    str++;
  while (isspace(str[end])) {
    str[end] = '\0';
    end--;
  }
  return str;
}

static bool parse_config(const string &config_file) {
#define BUFFER_SIZE 1024
  FILE *file = fopen(config_file.c_str(), "r");
  char  buffer[BUFFER_SIZE];
  char *conf_str = NULL;
  char  addr[BUFFER_SIZE];

  if (!file) {
    return false;
  }
  while (fgets(buffer, sizeof(buffer), file) != NULL) {
    conf_str = trim_space(buffer, BUFFER_SIZE);
    if (sscanf(conf_str, "%s", addr) == EOF) {
      /* Skip empty line */
      continue;
    }
    if (sscanf(conf_str, "%[#]", addr) == 1) {
      /* Skip comments */
      continue;
    }
    if (sscanf(conf_str, "certifier_host = %s", addr) == 1) {
      app_config.certifier_host = string(addr);
      continue;
    }
    if (sscanf(conf_str, "client = %s", addr) == 1) {
      app_config.client = string(addr);
      continue;
    }
    if (sscanf(conf_str, "certifier_port = %d", &app_config.certifier_port)
        == 1) {
      continue;
    }
    if (sscanf(conf_str, "client_port = %d", &app_config.client_port) == 1) {
      continue;
    }
    if (sscanf(conf_str, "check_disk = %d", &app_config.check_disk) == 1) {
      continue;
    }
    ATT_LOG(LOG_INFO, "Parsing syntax error: %s", conf_str);
  }

  return true;
#undef BUFFER_SIZE
}

int main(int argc, char *argv[]) {
  int  ret = 0;
  bool disk_encrypted = false;

  SSL_library_init();
#ifdef USE_SIMULATED_ENCLAVE
  string enclave_type("simulated-enclave");
#else
  string enclave_type("sev-enclave");
#endif
  string purpose("authentication");

  string store_file(ATTSERVICE_DATA_DIR);
  store_file.append(ATTSERVICE_POLICY_STORE_FILE);
  string config_file(ATTSERVICE_DATA_DIR);
  config_file.append(ATTSERVICE_CONFIG_FILE);

  if (!file_exists(ATTSERVICE_DATA_DIR)) {
    ATT_LOG(LOG_INFO,
            "Creating configuration directory: %s",
            ATTSERVICE_DATA_DIR);
    if (mkdir(ATTSERVICE_DATA_DIR, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)
        != 0) {
      ATT_LOG(LOG_INFO, "Failed to create configuration directory.");
      return 1;
    }
  }

  app_trust_data = new cc_trust_data(enclave_type, purpose, store_file);
  if (app_trust_data == nullptr) {
    ATT_LOG(LOG_INFO, "Couldn't initialize trust object");
    return 1;
  }

  // Init policy key info
  if (!app_trust_data->init_policy_key(initialized_cert,
                                       initialized_cert_size)) {
    ATT_LOG(LOG_INFO, "Can't init policy key.");
    return 1;
  }

#ifdef USE_SIMULATED_ENCLAVE
  // Init simulated enclave
  string attest_key_file_name(ATTSERVICE_DATA_DIR);
  attest_key_file_name.append(ATTEST_KEY_FILE);
  string platform_attest_file_name(ATTSERVICE_DATA_DIR);
  platform_attest_file_name.append(PLAT_ATTEST_ENDORSEMENT_FILE);
  string measurement_file_name(ATTSERVICE_DATA_DIR);
  measurement_file_name.append(MEASUREMENT_FILE);
  string attest_endorsement_file_name(ATTSERVICE_DATA_DIR);
  attest_endorsement_file_name.append(PLAT_ATTEST_ENDORSEMENT_FILE);

  if (!app_trust_data->initialize_simulated_enclave_data(
          attest_key_file_name,
          measurement_file_name,
          attest_endorsement_file_name)) {
    printf("Can't init simulated enclave\n");
    return 1;
  }
#else
  // Init SEV enclave
  string ark_cert_file_name(ATTSERVICE_DATA_DIR);
  ark_cert_file_name.append(ARK_CERT_FILE);
  string ask_cert_file_name(ATTSERVICE_DATA_DIR);
  ask_cert_file_name.append(ASK_CERT_FILE);
  string vcek_cert_file_name(ATTSERVICE_DATA_DIR);
  vcek_cert_file_name.append(VCEK_CERT_FILE);
  if (!app_trust_data->initialize_sev_enclave_data(ark_cert_file_name,
                                                   ask_cert_file_name,
                                                   vcek_cert_file_name)) {
    printf("Can't init sev enclave\n");
    return 1;
  }
#endif

  // Standard algorithms for the enclave
  string public_key_alg(Enc_method_rsa_2048);
  string symmetric_key_alg(Enc_method_aes_256_cbc_hmac_sha256);

  if (!file_exists(store_file)) {
    ATT_LOG(LOG_INFO, "Performing cold initialization...");
    if (!app_trust_data->cold_init(public_key_alg,
                                   symmetric_key_alg,
                                   hash_alg,
                                   hmac_alg)) {
      ATT_LOG(LOG_INFO, "cold-init failed");
      ret = 1;
      goto done;
    }
  } else {
    ATT_LOG(LOG_INFO, "Performing warm initialization...");
    if (!app_trust_data->warm_restart()) {
      ATT_LOG(LOG_INFO, "warm-restart failed");
      /* Attemp cold init */
      if (!app_trust_data->cold_init(public_key_alg, symmetric_key_alg)) {
        ATT_LOG(LOG_INFO, "cold-init failed");
        ret = 1;
        goto done;
      }
    }
  }

  if (file_exists(config_file)) {
    // Parse config file
    if (!parse_config(config_file)) {
      ATT_LOG(LOG_INFO,
              "Failed to parse configuration file. Use default config.");
    }
  }
  ATT_LOG(LOG_INFO, "Attestation Service Configuration:");
  ATT_LOG(LOG_INFO,
          "  Certifier host: %s:%d",
          app_config.certifier_host.c_str(),
          app_config.certifier_port);
  ATT_LOG(LOG_INFO,
          "  Notification client: %s:%d",
          app_config.client.c_str(),
          app_config.client_port);
  ATT_LOG(LOG_INFO,
          "  Require Disk Encryption? : %s",
          app_config.check_disk ? "Yes" : "No");

  /*
   * Perform the certification if the appliance is not already certified.
   */
  if (app_trust_data->cc_is_certified_) {
    ATT_LOG(LOG_INFO, "Appliance was already certified");
  } else {
    ATT_LOG(LOG_INFO, "Performing certification...");
    if (!app_trust_data->certify_me(app_config.certifier_host,
                                    app_config.certifier_port)) {
      ATT_LOG(LOG_INFO, "Certification failed.");
      ret = 1;
      goto done;
    }
  }

  // Check for disk encryption status if configured
  if (app_config.check_disk) {
    disk_encrypted = check_disk_encryption();
  }

  if (!certifier_notification(app_trust_data, disk_encrypted)) {
    ATT_LOG(LOG_INFO, "Certifier notitication failed.");
    ret = 1;
    goto done;
  }

done:
  // app_trust_data->print_trust_data();
  app_trust_data->clear_sensitive_data();
  if (app_trust_data != nullptr) {
    delete app_trust_data;
  }
  return ret;
}
