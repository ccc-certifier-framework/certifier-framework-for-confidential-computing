#include "key_wrapper.h"
#include "certifier.h"
#include "certifier_algorithms.h"
#include "certifier.pb.h"

using namespace std;

KeyWrapper::KeyWrapper() {}

KeyWrapper::~KeyWrapper() {}

bool KeyWrapper::generate(int key_size) {
    key_message key;
    if (!generate_rsa_key(key_size, &key))
        return false;

    key.SerializeToString(&key_bytes);
    return true;
}

bool KeyWrapper::sign(const string& message, string& signature) {
    key_message key;
    if (!key.ParseFromString(key_bytes))
        return false;

    const byte* in = reinterpret_cast<const byte*>(message.data());
    int in_size = message.size();
    byte sig[512];  // max size buffer
    int sig_size = 0;

    if (!sign_message(key, in_size, (byte*)in, &sig_size, sig))
        return false;

    signature.assign((char*)sig, sig_size);
    return true;
}

bool KeyWrapper::verify(const string& message, const string& signature) {
    key_message key;
    if (!key.ParseFromString(key_bytes))
        return false;

    const byte* in = reinterpret_cast<const byte*>(message.data());
    int in_size = message.size();
    const byte* sig = reinterpret_cast<const byte*>(signature.data());
    int sig_size = signature.size();

    return verify_message(key, in_size, (byte*)in, sig_size, (byte*)sig);
}

string KeyWrapper::export_key() {
    return key_bytes;
}

bool KeyWrapper::import_key(const string& serialized_key) {
    key_message key;
    if (!key.ParseFromString(serialized_key))
        return false;

    key_bytes = serialized_key;
    return true;
}
