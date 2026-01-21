// Copyright 2015 Google Corporation, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// Portions of this code were derived TPM2.0-TSS published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// File: quote_protocol.cc

// standard buffer size

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <tpm20.h>
#include <tpm2_lib.h>
#include <errno.h>

#include <tpm2.pb.h>
#include <openssl/sha.h>
#include <openssl_helpers.h>

#include <string>
#define DEBUG

void print_quote_certifyinfo(TPMS_ATTEST& in) {
  printf("\n");
  printf("magic: %08x\n", in.magic);
  printf("type: %04x\n", in.type);
  printf("qualifiedSigner: ");
  PrintBytes(in.qualifiedSigner.size, in.qualifiedSigner.name);
  printf("\n");
  printf("extraData: ");
  PrintBytes(in.extraData.size, in.extraData.buffer);
  printf("\n");
  printf("clock: %016llx\n", in.clockInfo.clock);
  printf("resetCount: %08x\n", in.clockInfo.resetCount);
  printf("restartCount: %08x\n", in.clockInfo.restartCount);
  printf("safe: %02x\n", in.clockInfo.safe);
  printf("firmwareVersion: %016llx\n", in.firmwareVersion);
  printf("pcrSelect: %08x\n", in.attested.quote.pcrSelect.count);
  for (int i = 0; i < (int)in.attested.quote.pcrSelect.count; i++) {
    printf("  %04x %02x ", in.attested.quote.pcrSelect.pcrSelections[i].hash,
           in.attested.quote.pcrSelect.pcrSelections[i].sizeofSelect);
    PrintBytes(in.attested.quote.pcrSelect.pcrSelections[i].sizeofSelect,
               in.attested.quote.pcrSelect.pcrSelections[i].pcrSelect);
    printf("\n");
  }
  printf("Pcr Digest (%d): ", in.attested.quote.pcrDigest.size);
  PrintBytes(in.attested.quote.pcrDigest.size,
             in.attested.quote.pcrDigest.buffer);
  printf("\n");
}

bool MarshalCertifyInfo(TPMS_ATTEST& in, int* size, byte* out) {
  return true;
}

bool UnmarshalCertifyInfo(int size, byte* in, TPMS_ATTEST* out) {
  byte* current_in = in;

  ChangeEndian32((uint32_t*)current_in, &out->magic);
  current_in += sizeof(uint32_t);
  ChangeEndian16((uint16_t*)current_in, &out->type);
  current_in += sizeof(uint16_t);
  ChangeEndian16((uint16_t*)current_in, &out->qualifiedSigner.size);
  current_in += sizeof(uint16_t);
  memcpy(out->qualifiedSigner.name, current_in, out->qualifiedSigner.size);
  current_in += out->qualifiedSigner.size;
  ChangeEndian16((uint16_t*)current_in, &out->extraData.size);
  current_in += sizeof(uint16_t);
  memcpy(out->extraData.buffer, current_in, out->extraData.size);
  current_in += out->extraData.size;
  // clock
  ChangeEndian64((uint64_t*)current_in, &out->clockInfo.clock);
  current_in += sizeof(uint64_t);
  ChangeEndian32((uint32_t*)current_in, &out->clockInfo.resetCount);
  current_in += sizeof(uint32_t);
  ChangeEndian32((uint32_t*)current_in, &out->clockInfo.restartCount);
  current_in += sizeof(uint32_t);
  out->clockInfo.safe = *(current_in++);
  ChangeEndian64((uint64_t*)current_in, &out->firmwareVersion);
  current_in += sizeof(uint64_t);
  ChangeEndian32((uint32_t*)current_in, &out->attested.quote.pcrSelect.count);
  current_in += sizeof(uint32_t);
  for (int i = 0; i < (int)out->attested.quote.pcrSelect.count; i++) {
    ChangeEndian16((uint16_t*)current_in, (uint16_t*)
                   &out->attested.quote.pcrSelect.pcrSelections[i].hash);
    current_in += sizeof(uint16_t);
    out->attested.quote.pcrSelect.pcrSelections[i].sizeofSelect =
        *(current_in++);
    memcpy(out->attested.quote.pcrSelect.pcrSelections[i].pcrSelect,
           current_in,
           out->attested.quote.pcrSelect.pcrSelections[i].sizeofSelect);
    current_in += out->attested.quote.pcrSelect.pcrSelections[i].sizeofSelect;
  }
  ChangeEndian16((uint16_t*)current_in, &out->attested.quote.pcrDigest.size);
  current_in += sizeof(uint16_t);
  memcpy(out->attested.quote.pcrDigest.buffer, current_in,
         out->attested.quote.pcrDigest.size);
  current_in += out->attested.quote.pcrDigest.size;
  return true;
}

bool ProtoToCertifyInfo(quote_certification_information& message,
                        TPMS_ATTEST* out) {
  memcpy((byte*)&out->magic, (byte*)message.magic().data(), sizeof(uint32_t));
  out->type = *(uint16_t*)message.type().data();
  message.qualifiedsigner();
  out->extraData.size = 0;
  memcpy(&out->clockInfo, message.clockinfo().data(), message.clockinfo().size());
  out->firmwareVersion = message.firmwareversion();
  memcpy(&out->attested.quote.pcrSelect, message.pcr_selection().data(), message.pcr_selection().size());
  out->attested.quote.pcrDigest.size = message.digest().size();
  return true;
}

bool ComputeQuotedValue(TPM_ALG_ID alg, int credInfo_size, byte* credInfo,
                        int* size_quoted, byte* quoted) {
  if (alg == TPM_ALG_SHA1) {
    SHA_CTX sha1;
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, credInfo, credInfo_size);
    SHA1_Final(quoted, &sha1);
    *size_quoted = 20;
  } else if (alg == TPM_ALG_SHA256) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, credInfo, credInfo_size);
    SHA256_Final(quoted, &sha256);
    *size_quoted = 32;
  } else {
    printf("unsupported hash alg\n");
    return false;
  }

#ifdef DEBUG
  printf("Quote struct (%d): ", credInfo_size);
  PrintBytes(credInfo_size, credInfo);
  printf("\n");
  printf("Computed hash: ");
  PrintBytes(*size_quoted, quoted);
  printf("\n");
#endif
  return true;
}


