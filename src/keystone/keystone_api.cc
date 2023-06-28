#include "keystone_api.h"
#include <cstring>
/* Dependencies: Keystone SDK, Keystone Runtime for crypto. */
extern "C" {
  #include "app/syscall.h"
}
#include "crypto/aes.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"
#define assert(x) do { if (!(x)) { printf("Custom assert failed.\n"); exit(17); } } while (false) // TODO: replace

bool keystone_Init(const int cert_size, byte *cert) {
  return true;
}

bool keystone_Attest(const int what_to_say_size, byte* what_to_say, int* attestation_size_out, byte* attestation_out) {
  /* Do not edit if at all possible.
   * The sensible way of writing this function triggers bugs in either attest_enclave or C++ compiler.
   */
  assert(what_to_say_size <= ATTEST_DATA_MAXLEN);

  byte what_to_say_copy[what_to_say_size];
  memcpy(what_to_say_copy, what_to_say, what_to_say_size);

  bool ret = attest_enclave((void *) attestation_out, what_to_say_copy, what_to_say_size) == 0;

  memcpy(what_to_say, what_to_say_copy, what_to_say_size);
  *attestation_size_out = sizeof(struct report_t);

  return ret;
}

bool keystone_Verify(const int what_to_say_size, byte* what_to_say, const int attestation_size,
      byte* attestation, int* measurement_out_size, byte* measurement_out) {
  assert(attestation_size == sizeof(struct report_t));
  Report report;
  report.fromBytes(attestation);

  if(!report.checkSignaturesOnly(_sanctum_dev_public_key)) {
    return false;
  }

  if (report.getDataSize() != (unsigned int) what_to_say_size) {
    return false;
  }
  byte* report_says = (byte*) report.getDataSection();
  if (memcmp(what_to_say, report_says, what_to_say_size) != 0) {
    return false;
  }

  *measurement_out_size = MDSIZE * 2;
  memcpy(measurement_out, report.getSmHash(), MDSIZE);
  memcpy(measurement_out + MDSIZE, report.getEnclaveHash(), MDSIZE);

  return true;
}

// (128, 44), (192, 52), or (256, 60)
#define AES_KEY_LEN 128
#define AES_SCHEDULE_LEN 44

// to share between seal and unseal
bool keystone_getSealingKey(WORD key[]) {
  struct sealing_key key_buffer; // {key, signature}
  char key_identifier[] = "sealing-key";
  int err = get_sealing_key(&key_buffer, sizeof(key_buffer),
                        (void *)key_identifier, strlen(key_identifier));
  if (err) {
    return false;
  }
  aes_key_setup(key_buffer.key, key, AES_KEY_LEN);
  return true;
}

bool keystone_Seal(int in_size, byte* in, int* size_out, byte* out) {
  WORD key[AES_SCHEDULE_LEN];
  if (!keystone_getSealingKey(key)) {
    return false;
  }
  BYTE iv[AES_BLOCK_SIZE];
  memset(iv, 0, AES_BLOCK_SIZE * sizeof(BYTE));
  *size_out = in_size;
  aes_encrypt_ctr(in, in_size, out, key, AES_KEY_LEN, iv);
  return true;
}

bool keystone_Unseal(int in_size, byte* in, int* size_out, byte* out) {
  WORD key[AES_SCHEDULE_LEN];
  if (!keystone_getSealingKey(key)) {
    return false;
  }
  BYTE iv[AES_BLOCK_SIZE];
  memset(iv, 0, AES_BLOCK_SIZE * sizeof(BYTE));
  *size_out = in_size;
  aes_decrypt_ctr(in, in_size, out, key, AES_KEY_LEN, iv);
  return true;
}
