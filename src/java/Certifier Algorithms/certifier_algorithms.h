bool generate_rsa_key(int key_size, key_message* key);
bool sign_message(const key_message& key, int in_size, byte* in, int* out_size, byte* out);
bool verify_message(const key_message& key, int in_size, byte* in, int sig_size, byte* sig);
