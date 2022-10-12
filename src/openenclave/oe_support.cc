#include "sealing.h"
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/enclave.h>
#include <openenclave/seal.h>
#include <string>
#include <stdio.h>

string pem_cert_chain;
bool pem_cert_chain_initialized = false;

bool oe_Init(const string& pem_cert_chain_file) {
   if (!read_file_into_string(pem_cert_chain_file, &pem_cert_chain)) {
    printf("oe_Init: Can't read pem cert chain file\n");
    return false;
  }

  pem_cert_chain_initialized = true;
  certifier_parent_enclave_type = "hardware";
  certifier_parent_enclave_type_intitalized = true;
  return true;
}
