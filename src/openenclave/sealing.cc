#include "sealing.h"
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/seal.h>
#include <string>
#include <stdio.h>

bool oe_Seal(int   seal_policy,
             int   in_size,
             byte *in,
             int   opt_size,
             byte *opt,
             int * size_out,
             byte *out) {
  oe_result_t ret;
  bool        result = false;
  uint8_t *   blob;
  size_t      blob_size;
  uint64_t    host_addr = 0;

  if (!size_out || !out) {
    return result;
  }

  const oe_seal_setting_t settings[] = {OE_SEAL_SET_POLICY(seal_policy)};
  ret = oe_seal(NULL,
                settings,
                sizeof(settings) / sizeof(*settings),
                (const uint8_t *)in,
                (size_t)in_size,
                (const uint8_t *)opt,
                (size_t)opt_size,
                &blob,
                &blob_size);
  if (ret != OE_OK) {
    OE_DEBUG_PRINTF("oe_seal() failed with %d\n", ret);
    goto exit;
  }
  if (blob_size > UINT32_MAX) {
    OE_DEBUG_PRINTF("blob_size is too large\n");
    goto exit;
  }

  if (*size_out < (int)blob_size) {
    OE_DEBUG_PRINTF("Output buffer is too small\n");
    *size_out = (int)blob_size;
    goto exit;
  }

  *size_out = (int)blob_size;
  memcpy(out, blob, blob_size);
  result = true;

exit:
  oe_free(blob);
  return result;
}

bool oe_Unseal(int   in_size,
               byte *in,
               int   opt_size,
               byte *opt,
               int * size_out,
               byte *out) {
  bool     result = false;
  uint8_t *temp_data;
  int      ret = (int)oe_unseal((const uint8_t *)in,
                           (size_t)in_size,
                           (const uint8_t *)opt,
                           (size_t)opt_size,
                           &temp_data,
                           (size_t *)size_out);
  if (ret != OE_OK) {
    OE_DEBUG_PRINTF("oe_unseal() failed with %d\n", ret);
    goto exit;
  }

  memcpy(out, temp_data, *size_out);
  result = true;

exit:
  oe_free(temp_data);
  return result;
}
