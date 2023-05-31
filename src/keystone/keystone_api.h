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
