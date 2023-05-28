#include "app/eapp_utils.h"
#include "app/syscall.h"
#include "app/string.h"
#include "crypto/aes.h"
#include "edge/edge_common.h"
#include "verifier/report.h"
#include "verifier/test_dev_key.h"
/* Dependencies: Keystone SDK, Keystone Runtime for crypto. */
#define assert(x) do {} while (false) // TODO: fix

typedef unsigned char byte;

#define KEYSTONE_CERTIFIER
#ifdef KEYSTONE_CERTIFIER
bool keystone_Init(const int cert_size, byte *cert);
bool keystone_Attest(const int what_to_say_size, byte* what_to_say, int* attestation_size_out, byte* attestation_out);
bool keystone_Verify(const int what_to_say_size, byte* what_to_say, const int attestation_size, byte* attestation, int* measurement_out_size, byte* measurement_out);
bool keystone_Seal(int in_size, byte* in, int* size_out, byte* out);
bool keystone_Unseal(int in_size, byte* in, int* size_out, byte* out);
#endif


typedef struct KeystoneFunctions {
  bool (*Attest)(const int what_to_say_size, byte* what_to_say, int* attestation_size_out, byte* attestation_out);
  bool (*Verify)(const int what_to_say_size, byte* what_to_say, const int attestation_size, byte* attestation, int* measurement_out_size, byte* measurement_out);
  bool (*Seal)(int in_size, byte* in, int* size_out, byte* out);
  bool (*Unseal)(int in_size, byte* in, int* size_out, byte* out);
} KeystoneFunctions;

bool keystone_Init(const int cert_size, byte *cert) {

}

bool keystone_Attest(const int what_to_say_size, byte* what_to_say, int* attestation_size_out, byte* attestation_out) {
    assert(what_to_say_size <= 1024);
    *attestation_size_out = 1352;
    return attest_enclave((void *) attestation_out, what_to_say, what_to_say_size);
}

bool keystone_Verify(const int what_to_say_size, byte* what_to_say, const int attestation_size, byte* attestation, int* measurement_out_size, byte* measurement_out) {
  assert(attestation_size == sizeof(struct report_t));
  Report report;
  report.fromBytes(attestation);

  if(!report.checkSignaturesOnly(_sanctum_dev_public_key)) {
    return false;
  }

  if (report.getDataSize() != (unsigned int) (what_to_say_size + 1)) {
    return false;
  }
  byte* report_says = (byte*) report.getDataSection();
  for (int i = 0; i < attestation_size; i++) {
    if (*(report_says++) != *(what_to_say++)) {
      return false;
    }
  }

  // qq: sm and enclave measurement can both be in measurement_out?
  *measurement_out_size = MDSIZE * 2;
  memcpy(measurement_out, report.getSmHash(), MDSIZE);
  memcpy(measurement_out + MDSIZE, report.getEnclaveHash(), MDSIZE);

  return true;
}

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
  if (keystone_getSealingKey(key)) {
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
  if (keystone_getSealingKey(key)) {
    return false;
  }
  BYTE iv[AES_BLOCK_SIZE];
  memset(iv, 0, AES_BLOCK_SIZE * sizeof(BYTE));
  *size_out = in_size;
  aes_decrypt_ctr(in, in_size, out, key, AES_KEY_LEN, iv);
  return true;
}
