#include "claim_verifier.h"
#include "certifier.pb.h"
#include "support.h"

ClaimVerifier::ClaimVerifier() {}

ClaimVerifier::~ClaimVerifier() {}

<<<<<<< HEAD
bool ClaimVerifier::verify(const std::string& serialized_claim, const std::string& serialized_key) {
    signed_claim_message claim;
    key_message key;

    if (!claim.ParseFromString(serialized_claim) || !key.ParseFromString(serialized_key)) {
        return false;
    }

    return verify_signed_claim(claim, key);


// verify_signed_claim(...) is the real framework function from support.cc
=======
bool ClaimVerifier::verify(const std::string &serialized_claim,
                           const std::string &serialized_key) {
  signed_claim_message claim;
  key_message          key;

  if (!claim.ParseFromString(serialized_claim)
      || !key.ParseFromString(serialized_key)) {
    return false;
  }

  return verify_signed_claim(claim, key);


  // verify_signed_claim(...) is the real framework function from support.cc
>>>>>>> upstream/main
