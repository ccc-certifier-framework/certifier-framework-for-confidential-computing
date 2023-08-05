#include "sealing.h"
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/seal.h>
#include <string>
#include <stdio.h>
#include <certifier.h>
#include <support.h>

using namespace certifier::utilities;

string pem_cert_chain;
bool   pem_cert_chain_initialized = false;

bool oe_Init(const string &pem_cert_chain_file) {
  extern bool   certifier_parent_enclave_type_intitalized;
  extern string certifier_parent_enclave_type;
  if (!read_file_into_string(pem_cert_chain_file, &pem_cert_chain)) {
    printf("oe_Init: No pem cert chain file. Assume empty endorsement.\n");
    pem_cert_chain = "";
  }

  pem_cert_chain_initialized = true;
  certifier_parent_enclave_type = "hardware";
  certifier_parent_enclave_type_intitalized = true;
  return true;
}
