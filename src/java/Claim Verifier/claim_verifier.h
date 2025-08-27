#ifndef CLAIM_VERIFIER_H
#define CLAIM_VERIFIER_H

#include <string>

class ClaimVerifier {
<<<<<<< HEAD
public:
    ClaimVerifier();
    ~ClaimVerifier();

    // Accepts serialized protobufs as strings
    bool verify(const std::string& serialized_claim, const std::string& serialized_key);
=======
 public:
  ClaimVerifier();
  ~ClaimVerifier();

  // Accepts serialized protobufs as strings
  bool verify(const std::string &serialized_claim,
              const std::string &serialized_key);
>>>>>>> upstream/main
};

#endif
