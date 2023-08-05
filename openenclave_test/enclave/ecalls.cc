#include <stdio.h>
#include <sys/mount.h>
#include <openssl/rand.h>
#include <openenclave/enclave.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/report.h>
#include <openenclave/bits/module.h>
#include "certifier.h"
#include "support.h"
#include "simulated_enclave.h"

#define FLAGS_print_all false
static string measurement_file("/tmp/binary_trusted_measurements_file.bin");
#define FLAGS_trusted_measurements_file measurement_file
#define FLAGS_read_measurement_file     true
static bool simulator_initialized = false;
bool        test_local_certify(string &enclave_type,
                               bool    init_from_file,
                               string &file_name,
                               string &evidence_descriptor);

extern "C" {
bool certifier_init(void);
bool certifier_test_sim_certify(void);
bool certifier_test_local_certify(void);
bool certifier_test_seal(void);
}

bool certifier_init(void) {
  oe_result_t       result = OE_OK;
  static const char rnd_seed[] =
      "string to make the random number generator think it has entropy";

  RAND_seed(rnd_seed, sizeof rnd_seed);
  extern bool simulator_init(void);
  if (!simulator_initialized) {
    if (!simulator_init()) {
      return false;
    }
    simulator_initialized = true;
  }

  // Initialize attester and use the plugin.
  result = oe_attester_initialize();
  if (result != OE_OK) {
    printf("oe_attester_initialize failed.\n");
    return false;
  }
  // Initialize verifier and use the plugin.
  result = oe_verifier_initialize();
  if (result != OE_OK) {
    printf("oe_verifier_initialize failed.\n");
    return false;
  }

  result = oe_load_module_host_file_system();
  if (result != OE_OK) {
    printf("Failed to load host file system module: %s\n",
           oe_result_str(result));
    return false;
  }
  if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0) {
    printf("Failed to mount host file system\n");
    return false;
  }

  return true;
}

bool certifier_test_sim_certify(void) {
  string enclave_type("simulated-enclave");
  string evidence_descriptor("full-vse-support");
  return test_local_certify(enclave_type,
                            false,
                            FLAGS_trusted_measurements_file,
                            evidence_descriptor);
}

bool certifier_test_local_certify(void) {
  string enclave_type("oe-enclave");
  string evidence_descriptor("oe-evidence");
  return test_local_certify(enclave_type,
                            FLAGS_read_measurement_file,
                            FLAGS_trusted_measurements_file,
                            evidence_descriptor);
}

bool certifier_test_seal(void) {
  string enclave_type("oe-enclave");
  string enclave_id("local-machine");

  int  secret_to_seal_size = 32;
  byte secret_to_seal[secret_to_seal_size];
  int  sealed_size_out = 1024;
  byte sealed[sealed_size_out];
  int  recovered_size = 128;
  byte recovered[recovered_size];

  memset(sealed, 0, sealed_size_out);
  memset(recovered, 0, recovered_size);
  for (int i = 0; i < secret_to_seal_size; i++)
    secret_to_seal[i] = (7 * i) % 16;
  if (FLAGS_print_all) {
    printf("\nSeal\n");
    printf("to seal  (%d): ", secret_to_seal_size);
    print_bytes(secret_to_seal_size, secret_to_seal);
    printf("\n");
  }

  if (!Seal(enclave_type,
            enclave_id,
            secret_to_seal_size,
            secret_to_seal,
            &sealed_size_out,
            sealed))
    return false;
  if (FLAGS_print_all) {
    printf("sealed   (%d): ", sealed_size_out);
    print_bytes(sealed_size_out, sealed);
    printf("\n");
  }

  if (!Unseal(enclave_type,
              enclave_id,
              sealed_size_out,
              sealed,
              &recovered_size,
              recovered))
    return false;

  if (FLAGS_print_all) {
    printf("recovered: (%d)", recovered_size);
    print_bytes(recovered_size, recovered);
    printf("\n");
  }
  return true;
}
