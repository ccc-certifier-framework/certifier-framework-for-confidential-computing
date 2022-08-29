#include <iostream>

#ifndef _ASYLO_API_H_
#define _ASYLO_API_H_

typedef struct AsyloCertifierServerFunctions {
  bool (*Attest)(int claims_size, byte* claims, int* size_out, byte* out);
  bool (*Verify)(int user_data_size, byte* user_data, int assertion_size, byte *assertion, int* size_out, byte* out);
  bool (*Seal)(int in_size, byte* in, int* size_out, byte* out);
  bool (*Unseal)(int in_size, byte* in, int* size_out, byte* out);
} AsyloCertifierServerFunctions;

void setFuncs(AsyloCertifierServerFunctions funcs);

#endif // #ifdef _ASYLO_API_H_
