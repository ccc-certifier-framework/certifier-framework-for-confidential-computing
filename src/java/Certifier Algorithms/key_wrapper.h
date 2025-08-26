#ifndef KEY_WRAPPER_H
#define KEY_WRAPPER_H

#include <string>

class KeyWrapper {
 public:
  KeyWrapper();
  ~KeyWrapper();

  bool generate(int key_size);  // Generates RSA key
  bool sign(const std::string &message, std::string &signature);
  bool verify(const std::string &message, const s : string &signature);

  std::string export_key();  // Returns key serialized to string
  bool import_key(const std::string &serialized_key);  // Loads from string

 private:
  std::string key_bytes;  // Serialized key
};

#endif
