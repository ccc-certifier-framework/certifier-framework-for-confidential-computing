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
#include <conversions.h>

#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl_helpers.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <openssl_helpers.h>

#include <string>
using std::string;


//
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
// File: tpm2_lib.cc

// standard buffer size
#define MAX_SIZE_PARAMS 4096

bool Equal(int size_in1, byte* in1, int size_in2, byte* in2) {
  if(size_in1 != size_in2)
    return false;
  for (int i = 0; i < size_in1; i++) {
    if (in1[i] != in2[i])
      return false;
  }
  return true;
}

void ReverseCpy(int size, byte* in, byte* out) {
  out += size - 1;
  for (int i = 0; i < size; i++) *(out--) = *(in++);
}

void PrintBytes(int n, byte* in) {
  for (int i = 0; i < n; i++) printf("%02x", in[i]);
}

void ChangeEndian16(const uint16_t* in, uint16_t* out) {
  byte* p_in = (byte*)in;
  byte* p_out = (byte*)out;

  p_out[0] = p_in[1];
  p_out[1] = p_in[0];
}

void ChangeEndian32(const uint32_t* in, uint32_t* out) {
  byte* p_in = (byte*)in;
  byte* p_out = (byte*)out;

  p_out[0] = p_in[3];
  p_out[1] = p_in[2];
  p_out[2] = p_in[1];
  p_out[3] = p_in[0];
}

void ChangeEndian64(const uint64_t* in, uint64_t* out) {
  byte* p_in = (byte*)in;
  byte* p_out = (byte*)out;

  p_out[0] = p_in[7];
  p_out[1] = p_in[6];
  p_out[2] = p_in[5];
  p_out[3] = p_in[4];
  p_out[4] = p_in[3];
  p_out[5] = p_in[2];
  p_out[6] = p_in[1];
  p_out[7] = p_in[0];
}

bool ReadFileIntoBlock(const string& filename, int* size, byte* block) {
  int fd = open(filename.c_str(), O_RDONLY);
  if (fd < 0)
    return false;
  int n = read(fd, block, *size);
  *size = n;
  close(fd);
  return true;
}

bool WriteFileFromBlock(const string& filename, int size, byte* block) {
  int fd = creat(filename.c_str(), S_IRWXU | S_IRWXG);
  if (fd < 0)
    return false;
  int n = write(fd, block, size);
  close(fd);
  return n > 0;
}

// Debug routines
void printCommand(const char* name, int size, byte* buf) {
  printf("\n");
  printf("%s command: ", name);
  PrintBytes(size, buf);
  printf("\n");
}

void printResponse(const char* name, uint16_t cap, uint32_t size,
                   uint32_t code, byte* buf) {
  printf("%s response, ", name);
  printf("cap: %04x, size: %08x, error code: %08x\n", cap, size, code);
  PrintBytes(size, buf);
  printf("\n\n");
}

#define IF_LESS_THAN_RETURN_FALSE(x, y) if ((int)x < (int)y) return false;
#define IF_LESS_THAN_RETURN_MINUS1(x, y) if ((int)x < (int)y) return false;
#define IF_NEG_RETURN_FALSE(x) if (x < 0) return false;
#define IF_NEG_RETURN_MINUS1(x) if (x < 0) return -1;

void Update(int size, byte** ptr_buf, int* out_size, int* space_left) {
  *ptr_buf += size;
  *out_size += size;
  *space_left -= size;
}

LocalTpm::LocalTpm() {
  tpm_fd_ = -1;
}

LocalTpm::~LocalTpm() {
  tpm_fd_ = -1;
}

bool LocalTpm::OpenTpm(const char* device) {
  tpm_fd_ = open(device, O_RDWR);
  return tpm_fd_ > 0;
}

void LocalTpm::CloseTpm() {
  close(tpm_fd_);
  tpm_fd_ = -1;
}

bool LocalTpm::SendCommand(int size, byte* command) {
  int n = write(tpm_fd_, command, size);
  if (n < 0)
    printf("SendCommand Error: %s\n", strerror(errno));
  return n > 0;
}

bool LocalTpm::GetResponse(int* size, byte* response) {
  int n = read(tpm_fd_, response, *size);
  return n > 0;
}

int Tpm2_SetCommand(uint16_t tag, uint32_t cmd, byte* buf,
                    int size_param, byte* params) {
  uint32_t size = sizeof(TPM2_COMMAND_HEADER) + size_param;

  ChangeEndian16(&tag, &(((TPM2_COMMAND_HEADER*) buf)->tag));
  ChangeEndian32((uint32_t*)&size, &(((TPM2_COMMAND_HEADER*) buf)->paramSize));
  ChangeEndian32(&cmd, &(((TPM2_COMMAND_HEADER*) buf)->commandCode));
  memcpy(buf + sizeof(TPM2_COMMAND_HEADER), params, size_param);
  return size;
}

#pragma pack(push, 1)
struct TPM_CAP_INPUT {
  uint32_t cap_;
  uint32_t prop_;
  uint32_t count_;
};

struct TPM_RESPONSE {
  uint16_t cap_;
  uint32_t responseSize_;
  uint32_t responseCode_;
};
#pragma pack(pop)

bool FillTpmPcrData(LocalTpm& tpm, TPMS_PCR_SELECTION pcrSelection,
                    int* size, byte* buf) {
  TPML_PCR_SELECTION pcrSelect;
  uint32_t updateCounter = 0;
  TPML_PCR_SELECTION pcrSelectOut;
  TPML_DIGEST digest;

  pcrSelect.count = 1;
  pcrSelect.pcrSelections[0] = pcrSelection;

  if (!Tpm2_ReadPcrs(tpm, pcrSelect, &updateCounter,
                     &pcrSelectOut, &digest)) {
    printf("FillTpmPcrData: Tpm2_ReadPcrs fails\n");
    return false;
  }
  int total_size = 0;
  // ChangeEndian32(&digest.count, (uint32_t*)&buf[total_size]);
  // total_size += sizeof(uint32_t);
  for (int i = 0; i < (int)digest.count; i++) {
    if ((int)(total_size + digest.digests[i].size + sizeof(uint16_t))
          > *size) {
      printf("FillTpmPcrData: buffer too small\n");
      return false;
    }
    // ChangeEndian16(&digest.digests[i].size, (uint16_t*)&buf[total_size]);
    // total_size += sizeof(uint16_t);
    memcpy(&buf[total_size], digest.digests[i].buffer,
           digest.digests[i].size);
    total_size += digest.digests[i].size;
  }
  *size = total_size;
  return true;
}

bool ComputePcrDigest(TPM_ALG_ID hash, int size_in, byte* in_buf,
                      int* size_out, byte* out) {
  SHA_CTX sha1;
  SHA256_CTX sha256;

  if (hash != TPM_ALG_SHA1 && hash != TPM_ALG_SHA256) {
    printf("ComputePcrDigest: unsupported hash algorithm\n");
    return false;
  }

  if (hash == TPM_ALG_SHA1) {
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, in_buf, size_in);
    SHA1_Final(out, &sha1);
    *size_out = 20;
  } else {
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, in_buf, size_in);
    SHA256_Final(out, &sha256);
    *size_out = 32;
  }
  return true;
}

void Tpm2_InterpretResponse(int out_size, byte* out_buf, uint16_t* cap,
                           uint32_t* responseSize, uint32_t* responseCode) {
  TPM_RESPONSE* r = (TPM_RESPONSE*)out_buf;

  ChangeEndian16(&(r->cap_), cap);
  ChangeEndian32(&(r->responseSize_), responseSize);
  ChangeEndian32(&(r->responseCode_), responseCode);
}

bool Tpm2_Startup(LocalTpm& tpm) {
  byte commandBuf[MAX_SIZE_PARAMS];

  TPM_SU state = TPM_SU_CLEAR;
  TPM_SU big_endian_state;
  ChangeEndian16(&state, &big_endian_state);
  
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_Startup,
                                (byte*)commandBuf, sizeof(TPM_SU),
                                (byte*)&big_endian_state);
  if (!tpm.SendCommand(in_size, (byte*)commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  printCommand("Tpm2_Startup", in_size, commandBuf);

  int resp_size = 128;
  byte resp_buf[128];
  memset(resp_buf, 0, resp_size);
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
 
  uint16_t cap;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("Tpm2_Startup", cap, responseSize, responseCode, resp_buf);
  if (responseCode == RC_VER1) {
    printf("TPM not initialized\n");
  }
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return true;
}

bool Tpm2_Shutdown(LocalTpm& tpm) {
  return true;
}

void PrintCapabilities(int size, byte* buf) {
  uint32_t cap;
  uint32_t property;
  uint32_t value;
  uint32_t count;
  uint32_t handle;
  byte* current_in = buf;

  while (current_in < (size+buf)) {
    if (*(current_in++) == 0)
      break;
    ChangeEndian32((uint32_t*)current_in, &cap);
    current_in += sizeof(uint32_t);
    if (cap == TPM_CAP_TPM_PROPERTIES) {
      uint32_t i;
      ChangeEndian32((uint32_t*)current_in, &count);
      current_in += sizeof(uint32_t);
      printf("%d properties:\n", count);
      for (i = 0; i < count; i++) {
        ChangeEndian32((uint32_t*)current_in, &property);
        current_in += sizeof(uint32_t);
        ChangeEndian32((uint32_t*)current_in, &value);
        current_in += sizeof(uint32_t);
        printf("\tproperty: %08x  value: %08x\n",
               property, value);
      }
    } else if (cap == TPM_CAP_HANDLES) {
      uint32_t i;
      ChangeEndian32((uint32_t*)current_in, &count);
      current_in += sizeof(uint32_t);
      printf("%d properties:\n", count);
      for (i = 0; i < count; i++) {
        ChangeEndian32((uint32_t*)current_in, &handle);
        current_in += sizeof(uint32_t);
        printf("\thandle: %08x\n", handle);
      }
    } else {
      printf("unknown capability\n");
      return;
    }
  }
}

bool Tpm2_GetCapability(LocalTpm& tpm, uint32_t cap, uint32_t start,
                        int* out_size, byte* out_buf) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  uint32_t count = 20;
  uint32_t property = 0;

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params[MAX_SIZE_PARAMS];
  byte* in = params;
  int space_left = MAX_SIZE_PARAMS;

  memset(resp_buf, 0, resp_size);
  memset(out_buf, 0, *out_size);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32(&cap, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);
  if (cap == TPM_CAP_HANDLES) {
    property = start;
  }

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32(&property, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32(&count, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);
  
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_GetCapability,
                                commandBuf, size_params, params);
  printCommand("GetCapability", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap2 = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap2,
                         &responseSize, &responseCode);
  printResponse("GetCapability", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  *out_size = (int)(responseSize - sizeof(TPM_RESPONSE));
  memcpy(out_buf, resp_buf + sizeof(TPM_RESPONSE), *out_size);
  return true;
}

bool Tpm2_GetRandom(LocalTpm& tpm, int numBytes, byte* buf) {
  byte commandBuf[MAX_SIZE_PARAMS];

  uint16_t num_bytes = (uint16_t) numBytes;
  uint16_t num_bytes_big_endian;
  ChangeEndian16(&num_bytes, &num_bytes_big_endian);
  
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_GetRandom,
                                (byte*)commandBuf, sizeof(uint16_t),
                                (byte*)&num_bytes_big_endian);
  if (!tpm.SendCommand(in_size, (byte*)commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  printCommand("GetRandom", in_size, commandBuf);

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, resp_size);
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
 
  uint16_t cap;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("GetRandom", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  byte* random_bytes = resp_buf + sizeof(TPM_RESPONSE);
  int   num = responseSize - sizeof(TPM_RESPONSE);
  ReverseCpy(num, random_bytes, buf);
  return true;
}

bool Tpm2_ReadClock(LocalTpm& tpm, uint64_t* current_time, uint64_t* current_clock) {
  byte commandBuf[MAX_SIZE_PARAMS];

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_ReadClock,
                                (byte*)commandBuf, 0, nullptr);
  if (!tpm.SendCommand(in_size, (byte*)commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  printCommand("ReadClock", in_size, commandBuf);

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, resp_size);
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
 
  uint16_t cap;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("ReadClock", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  ChangeEndian64(
    &((TPMS_TIME_INFO*) (resp_buf + sizeof(TPM_RESPONSE)))->time,
    current_time);
  ChangeEndian64(
    (&((TPMS_TIME_INFO*) (resp_buf + sizeof(TPM_RESPONSE)))->
    clockInfo.clock), current_clock);
  return true;
}

void setPcrBit(int pcrNum, byte* array) {
  if (pcrNum >= 0 && pcrNum < PLATFORM_PCR)
    array[pcrNum / 8] |= (1 << (pcrNum % 8));
}

bool testPcrBit(int pcrNum, byte* array) {
  return (array[pcrNum / 8] & (1 << (pcrNum % 8))) != 0;
}

bool GetPcrValue(int size, byte* in, uint32_t* updateCounter,
                 TPML_PCR_SELECTION* pcr_out, TPML_DIGEST* values) {
  byte* current_in = in;
  ChangeEndian32((uint32_t*)current_in, updateCounter);
  current_in += sizeof(uint32_t);
  ChangeEndian32((uint32_t*)current_in, &pcr_out->count);
  current_in += sizeof(uint32_t);
  for (int i = 0; i < static_cast<int>(pcr_out->count); i++) {
    ChangeEndian16((uint16_t*)current_in, &pcr_out->pcrSelections[i].hash);
    current_in += sizeof(uint16_t);
    pcr_out->pcrSelections[i].sizeofSelect = *current_in;
    current_in += 1;
    memcpy(pcr_out->pcrSelections[i].pcrSelect, current_in,
           pcr_out->pcrSelections[i].sizeofSelect);
    current_in += pcr_out->pcrSelections[i].sizeofSelect;
  }

  ChangeEndian32((uint32_t*)current_in, &values->count);
  current_in += sizeof(uint32_t);
  for (int i = 0; i < static_cast<int>(values->count); i++) {
    ChangeEndian16((uint16_t*)current_in, &values->digests[i].size);
    current_in += sizeof(uint16_t);
    memcpy(values->digests[i].buffer, current_in, values->digests[i].size);
    current_in += values->digests[i].size;
  }

  return true;
}

void InitSinglePcrSelection(int pcrNum, TPM_ALG_ID hash,
                            TPML_PCR_SELECTION* pcrSelect) {
  if (pcrNum == -1) {
    pcrSelect->count = 0;
    return;
  }
  pcrSelect->count = 1;
  pcrSelect->pcrSelections[0].hash = hash;
  pcrSelect->pcrSelections[0].sizeofSelect = 3;
  for (int i = 0; i < 3; i++)
    pcrSelect->pcrSelections[0].pcrSelect[i] = 0;
  if (pcrNum != 0)
    setPcrBit(pcrNum, pcrSelect->pcrSelections[0].pcrSelect);
}

bool Tpm2_ReadPcrs(LocalTpm& tpm, TPML_PCR_SELECTION pcrSelect,
                   uint32_t* updateCounter,
                   TPML_PCR_SELECTION* pcrSelectOut, TPML_DIGEST* values) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  byte input_params[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int in_size = 0;
  byte* in = input_params;

  memset(resp_buf, 0, resp_size);
  memset(input_params, 0, space_left);

  // replace with long marshal_Pcr
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32(&pcrSelect.count, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &in_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16(&pcrSelect.pcrSelections[0].hash, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &in_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, 1)
  *in = pcrSelect.pcrSelections[0].sizeofSelect;
  Update(1, &in, &in_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, 3)
  memcpy(in, pcrSelect.pcrSelections[0].pcrSelect, 3);
  Update(3, &in, &in_size, &space_left);

  int cmd_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_PCR_Read,
                                commandBuf, in_size, input_params);
  if (!tpm.SendCommand(cmd_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  printCommand("ReadPcr", cmd_size, commandBuf);

  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }

  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("ReadPcr", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return GetPcrValue(responseSize - sizeof(TPM_RESPONSE),
                     resp_buf + sizeof(TPM_RESPONSE), updateCounter,
                     pcrSelectOut, values);
}

bool Tpm2_ReadPcr(LocalTpm& tpm, int pcrNum, uint32_t* updateCounter,
                  TPML_PCR_SELECTION* pcrSelectOut, TPML_DIGEST* values) {
  TPML_PCR_SELECTION pcrSelect;
  InitSinglePcrSelection(pcrNum, TPM_ALG_SHA1, &pcrSelect);
  return Tpm2_ReadPcrs(tpm, pcrSelect, updateCounter,
                   pcrSelectOut, values);
}

int SetOwnerHandle(TPM_HANDLE owner, int size, byte* buf) {
  TPM_HANDLE handle = owner;

  ChangeEndian32(&handle, (uint32_t*)buf);
  return sizeof(TPM_HANDLE);
}

byte ToHex(const char in) {
  if (in >= 0 && in <= '9')
    return in - '0';
  if (in >= 'a' && in <= 'f')
    return in - 'a' + 10;
  if (in >= 'A' && in <= 'F')
    return in - 'A' + 10;
  return 0;
}

int SetPasswordData(string& password, int size, byte* buf) {
  int num_auth_bytes =  password.size() / 2;
  int total_size = 0;
  int space_left = size;
  byte* out = buf;

  byte auth[64];
  if (num_auth_bytes > 0 ) {
    const char* str = password.c_str();
    byte c;
    for (int i = 0; i < num_auth_bytes; i++) {
      c = (ToHex(*str) << 4) | ToHex(*(str + 1));
      str += 2;
      auth[i] = c;
    }
  }
  uint16_t size_out = num_auth_bytes;
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&size_out, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);
  if (num_auth_bytes > 0) {
    IF_LESS_THAN_RETURN_MINUS1(space_left, num_auth_bytes)
    memcpy(out, auth, num_auth_bytes);
    Update(num_auth_bytes, &out, &total_size, &space_left);
  }
  return total_size;
}

int CreatePasswordAuthArea(string& password, int size, byte* buf) {
  byte* out = buf;
  int total_size = 0;
  int space_left = size;
  uint16_t len;
  byte* pLen = out;

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t));
  memset(out, 0, 2);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  uint32_t policy = TPM_RS_PW;
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint32_t));
  ChangeEndian32(&policy, (uint32_t*)out);
  Update(sizeof(uint32_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t));
  memset(out, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, 1);
  *out = 1;
  Update(1, &out, &total_size, &space_left);

  int n = SetPasswordData(password, size, out);
  IF_NEG_RETURN_MINUS1(n)
  Update(n, &out, &total_size, &space_left);
  len = 7 + n;
  ChangeEndian16(&len, (uint16_t*)pLen);
  return total_size;
}

int CreateSensitiveArea(int size_in, byte* in, int size_data, byte* data,
                        int size, byte* buf) {
  int total_size = 0;
  int space_left = size;
  byte* out = buf;
  byte* pSize = out;

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t));
  memset(out, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t));
  ChangeEndian16((uint16_t*)&size_in, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);
  if (size_in > 0) {
    IF_LESS_THAN_RETURN_MINUS1(size_in, sizeof(uint16_t));
    memcpy(out, in, size_in);
    Update(size_in, &out, &total_size, &space_left);
  }

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t));
  ChangeEndian16((uint16_t*)&size_data, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);
  if (size_data > 0) {
    IF_LESS_THAN_RETURN_MINUS1(size_data, sizeof(uint16_t));
    memcpy(out, data, size_data);
    Update(size_data, &out, &total_size, &space_left);
  }

  uint16_t size_sensitive = total_size - sizeof(uint16_t);
  ChangeEndian16((uint16_t*)&size_sensitive, (uint16_t*) pSize);
  return total_size;
}

int CreateSensitiveArea(string& authString, int size_data, byte* data,
                        int size, byte* buf) {
  int total_size = 0;
  int space_left = size;
  byte* out = buf;
  byte* pSize = out;

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t));
  memset(out, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  int n = SetPasswordData(authString, size, out);
  IF_NEG_RETURN_MINUS1(n)
  Update(n, &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t));
  ChangeEndian16((uint16_t*)&size_data, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);
  if (size_data > 0) {
    IF_LESS_THAN_RETURN_MINUS1(space_left, size_data);
    memcpy(out, data, size_data);
    Update(size_data, &out, &total_size, &space_left);
  }
  uint16_t size_sensitive = total_size - sizeof(uint16_t);
  ChangeEndian16((uint16_t*)&size_sensitive, (uint16_t*) pSize);
  return total_size;
}

bool Tpm2_PCR_Event(LocalTpm& tpm, int pcr_num,
                    uint16_t size_eventData, byte* eventData) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int input_size = 0;
  int space_left = MAX_SIZE_PARAMS;
  byte input_params[MAX_SIZE_PARAMS];
  byte* in = input_params;
  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int n;

  memset(resp_buf, 0, resp_size);
  memset(input_params, 0, MAX_SIZE_PARAMS);

  if (pcr_num < 0) {
    printf("No PCR to update\n");
    return true;
  }

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&pcr_num, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &input_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &input_size, &space_left);

  string emptyAuth;
  n = CreatePasswordAuthArea(emptyAuth, MAX_SIZE_PARAMS, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &input_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16(&size_eventData, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &input_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, size_eventData)
  memcpy(in, eventData, size_eventData);
  Update(size_eventData, &in, &input_size, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_PCR_Event,
                                commandBuf, input_size, input_params);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  printCommand("PCR_Event", in_size, commandBuf);

  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }

  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("PCR_Event", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return true;
}

int Marshal_AuthSession_Info(TPMI_DH_OBJECT& tpm_obj, TPMI_DH_ENTITY& bind_obj,
                    TPM2B_NONCE& initial_nonce, TPM2B_ENCRYPTED_SECRET& salt,
                    TPM_SE& session_type, TPMT_SYM_DEF& symmetric,
                    TPMI_ALG_HASH& hash_alg, int size, byte* out_buf) {
  int total_size = 0;
  int space_left = size;
  byte* out = out_buf;

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&tpm_obj, (uint32_t*)out);
  Update(sizeof(uint32_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&bind_obj, (uint32_t*)out);
  Update(sizeof(uint32_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&initial_nonce.size, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, initial_nonce.size)
  memcpy(out, initial_nonce.buffer, initial_nonce.size);
  Update(initial_nonce.size, &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&salt.size, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, salt.size)
  memcpy(out, salt.secret, salt.size);
  Update(salt.size, &out, &total_size, &space_left);

  *out = session_type;
  Update(1, &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&symmetric.algorithm, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  if (symmetric.algorithm != TPM_ALG_NULL) {
    IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
    ChangeEndian16((uint16_t*)&symmetric.keyBits.aes, (uint16_t*)out);
    Update(sizeof(uint16_t), &out, &total_size, &space_left);
    IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
    ChangeEndian16((uint16_t*)&symmetric.mode.aes, (uint16_t*)out);
    Update(sizeof(uint16_t), &out, &total_size, &space_left);
  }

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&hash_alg, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);
  return total_size;
}

int Marshal_Public_Key_Info(TPM2B_PUBLIC& in, int size, byte* buf) {
  int total_size = 0;
  int space_left = size;
  byte* out = buf;

  in.size = 10;
  // symmetric is variable size
  in.size += 2;
  if (in.publicArea.parameters.rsaDetail.symmetric.algorithm != TPM_ALG_NULL) {
    in.size += 2;
  }
  in.size += 12;

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&in.size, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  // type
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&in.publicArea.type, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  //alg 
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&in.publicArea.nameAlg, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  // attributes
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&in.publicArea.objectAttributes, (uint32_t*)out);
  Update(sizeof(uint32_t), &out, &total_size, &space_left);

  // auth size
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  memset(out, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  // algorithm
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&in.publicArea.parameters.rsaDetail.symmetric.algorithm,
                 (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);
  if (in.publicArea.parameters.rsaDetail.symmetric.algorithm != TPM_ALG_NULL) {
    IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
    ChangeEndian16((uint16_t*)&in.publicArea.parameters.rsaDetail.symmetric.keyBits.aes,
                   (uint16_t*)out);
    Update(sizeof(uint16_t), &out, &total_size, &space_left);
    IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
    ChangeEndian16((uint16_t*)&in.publicArea.parameters.rsaDetail.symmetric.mode.aes,
                   (uint16_t*)out);
    Update(sizeof(uint16_t), &out, &total_size, &space_left);
  }

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&in.publicArea.parameters.rsaDetail.scheme.scheme,
                 (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  if (in.publicArea.parameters.rsaDetail.scheme.scheme == TPM_ALG_RSASSA) {
    IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
    ChangeEndian16(
      &in.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg,
      (uint16_t*)out);
    Update(sizeof(uint16_t), &out, &total_size, &space_left);
  }

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&in.publicArea.parameters.rsaDetail.keyBits,
                 (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&in.publicArea.parameters.rsaDetail.exponent,
                 (uint32_t*)out);
  Update(sizeof(uint32_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  memset(out, 0, 2);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);
  return total_size;
}

int Marshal_OutsideInfo(TPM2B_DATA& in, int size, byte* buf) {
  int total_size = 0;
  int space_left = size;
  byte* out = buf;

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&in.size, (uint16_t*) out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, in.size)
  memcpy(out, in.buffer, in.size);
  Update(in.size, &out, &total_size, &space_left);
  return total_size;
}

int Marshal_PCR_Long_Selection(TPML_PCR_SELECTION& in, int size, byte* buf) {
  int total_size = 0;
  int space_left = size;
  byte* out = buf;

  if (in.count == 0) {
    memset(out, 0, sizeof(uint32_t));
    return sizeof(uint32_t);
  }
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint32_t))
  ChangeEndian32(&in.count, (uint32_t*)out);
  Update(sizeof(uint32_t), &out, &total_size, &space_left);

  for (int i = 0; i < static_cast<int>(in.count); i++) {

    IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
    ChangeEndian16(&in.pcrSelections[i].hash, (uint16_t*)out);
    Update(sizeof(uint16_t), &out, &total_size, &space_left);

    IF_LESS_THAN_RETURN_MINUS1(space_left, 1)
    *out = in.pcrSelections[i].sizeofSelect;
    Update(1, &out, &total_size, &space_left);

    IF_LESS_THAN_RETURN_MINUS1(space_left, in.pcrSelections[i].sizeofSelect)
    memcpy(out, in.pcrSelections[i].pcrSelect,
           in.pcrSelections[i].sizeofSelect);
    Update(in.pcrSelections[i].sizeofSelect, &out, &total_size, &space_left);
  }
  return total_size;
}

int Marshal_PCR_Short_Selection(TPMS_PCR_SELECTION& in, int size, byte* buf) {
  byte* out = buf;
  int total_size = 0;
  int space_left = size;

  IF_LESS_THAN_RETURN_MINUS1(space_left, 1)
  *out = in.sizeofSelect;
  Update(1, &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, in.sizeofSelect)
  memcpy(out, in.pcrSelect, in.sizeofSelect);
  Update(in.sizeofSelect, &out, &total_size, &space_left);
  return total_size;
}

int Marshal_Signature_Scheme_Info(TPMT_SIG_SCHEME& sig_scheme, int size,
                                  byte* buf) {
  int total_size = 0;
  int space_left = size;
  byte* out = buf;

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&sig_scheme.scheme, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&sig_scheme.details.rsassa.hashAlg, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);
  return total_size;
}

int Marshal_Keyed_Hash_Info(TPM2B_PUBLIC& keyed_hash, int size, byte* buf) {
  int total_size = 0;
  int space_left = size;
  byte* out = buf;
  byte* pSize = out;

  // size to fill in later
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  memset(out, 0, 2);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&keyed_hash.publicArea.type, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&keyed_hash.publicArea.nameAlg, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&keyed_hash.publicArea.objectAttributes,
                 (uint32_t*)out);
  Update(sizeof(uint32_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&keyed_hash.publicArea.authPolicy.size,
                 (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, keyed_hash.publicArea.authPolicy.size)
  memcpy(out, keyed_hash.publicArea.authPolicy.buffer,
         keyed_hash.publicArea.authPolicy.size);
  Update(keyed_hash.publicArea.authPolicy.size, &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16(&keyed_hash.publicArea.parameters.keyedHashDetail.scheme.scheme,
                 (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  // public id
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  memset(out, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  uint16_t size_publicArea = total_size - sizeof(uint16_t);
  ChangeEndian16(&size_publicArea, (uint16_t*)pSize);
  return total_size;
}

void FillPublicRsaTemplate(TPM_ALG_ID enc_alg, TPM_ALG_ID int_alg, 
                           TPMA_OBJECT flags, TPM_ALG_ID sym_alg,
                           TPMI_AES_KEY_BITS sym_key_size,
                           TPMI_ALG_SYM_MODE sym_mode, TPM_ALG_ID sig_scheme,
                           int mod_size, uint32_t exp, TPM2B_PUBLIC& pub_key) {
  pub_key.publicArea.type = enc_alg;
  pub_key.publicArea.nameAlg = int_alg;
  pub_key.publicArea.objectAttributes = flags;
  pub_key.publicArea.parameters.rsaDetail.symmetric.algorithm = sym_alg;
  if (sym_alg != TPM_ALG_NULL) {
    pub_key.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = sym_key_size;
    pub_key.publicArea.parameters.rsaDetail.symmetric.mode.aes = sym_mode;
  }
  pub_key.publicArea.parameters.rsaDetail.scheme.scheme = sig_scheme;
  if (sig_scheme != TPM_ALG_NULL)
    pub_key.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = 0x04;
  pub_key.publicArea.parameters.rsaDetail.keyBits = (uint16_t)mod_size;
  pub_key.publicArea.parameters.rsaDetail.exponent = exp;
}

void FillEmptyData(TPM2B_DATA& data) {
  data.size = 0;
}

void FillSignatureSchemeTemplate(TPM_ALG_ID enc_alg, TPM_ALG_ID int_alg,
                                 TPMT_SIG_SCHEME& scheme) {
  scheme.scheme = enc_alg;
  scheme.details.rsassa.hashAlg= int_alg;
}

void FillKeyedHashTemplate(TPM_ALG_ID enc_alg, TPM_ALG_ID int_alg,
                           TPMA_OBJECT flags, uint16_t size_auth, byte* auth,
                           TPM2B_PUBLIC& keyed_hash) {
  keyed_hash.publicArea.type = enc_alg;
  keyed_hash.publicArea.nameAlg = int_alg;
  keyed_hash.publicArea.objectAttributes = flags;
  keyed_hash.publicArea.authPolicy.size = size_auth;
  memcpy(keyed_hash.publicArea.authPolicy.buffer, auth, size_auth);
  keyed_hash.publicArea.authPolicy.size = size_auth;
  keyed_hash.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_NULL;
}

bool GetPublicOut(int size, byte* in, TPM_HANDLE* handle, TPM2B_PUBLIC* pub_out,
                  TPM2B_CREATION_DATA* creation_data, TPM2B_DIGEST* hash,
                  TPMT_TK_CREATION* creation_ticket, TPM2B_NAME* name) {
  byte* current_in = in;
  ChangeEndian32((uint32_t*)current_in, (uint32_t*)handle);
  current_in += sizeof(TPM_HANDLE);

  // skip size and 2 uint16_t's
  current_in += 3 * sizeof(uint16_t);
  uint16_t new_size;
  ChangeEndian16((uint16_t*)current_in,
                 (uint16_t*)&pub_out->publicArea.type);
  current_in += sizeof(uint16_t);
  ChangeEndian16((uint16_t*)current_in,
                 (uint16_t*)&pub_out->publicArea.nameAlg);
  current_in += sizeof(uint16_t);

  ChangeEndian32((uint32_t*)current_in,
                 (uint32_t*)&pub_out->publicArea.objectAttributes);
  current_in += sizeof(uint32_t);

  ChangeEndian32((uint32_t*)current_in,
                 (uint32_t*)&pub_out->publicArea.parameters.rsaDetail.symmetric.algorithm);
  current_in += sizeof(uint32_t);
  if (pub_out->publicArea.parameters.rsaDetail.symmetric.algorithm != TPM_ALG_NULL) {
  }
  ChangeEndian16((uint16_t*)current_in,
                 (uint16_t*)&pub_out->publicArea.parameters.rsaDetail.scheme.scheme);
  current_in += sizeof(uint16_t);
  ChangeEndian16((uint16_t*)current_in,
                 (uint16_t*)&pub_out->publicArea.parameters.rsaDetail.scheme.details);
  current_in += sizeof(uint16_t);

  ChangeEndian16((uint16_t*)current_in,
    &pub_out->publicArea.parameters.rsaDetail.keyBits);
  current_in += sizeof(uint16_t);
  ChangeEndian32((uint32_t*)current_in,
    &pub_out->publicArea.parameters.rsaDetail.exponent);
  current_in += sizeof(uint32_t);

  // get modulus
  ChangeEndian16((uint16_t*)current_in, &new_size);
  pub_out->publicArea.unique.rsa.size = new_size;
  current_in += sizeof(uint16_t);
  memcpy(pub_out->publicArea.unique.rsa.buffer, current_in, new_size);
  current_in += new_size;

  return true;
}

bool Tpm2_CreatePrimary(LocalTpm& tpm, TPM_HANDLE owner, string& authString,
                        TPML_PCR_SELECTION& pcr_selection, 
                        TPM_ALG_ID enc_alg, TPM_ALG_ID int_alg,
                        TPMA_OBJECT& flags, TPM_ALG_ID sym_alg,
                        TPMI_AES_KEY_BITS sym_key_size,
                        TPMI_ALG_SYM_MODE sym_mode, TPM_ALG_ID sig_scheme,
                        int mod_size, uint32_t exp,
                        TPM_HANDLE* handle, TPM2B_PUBLIC* pub_out) {
  byte commandBuf[2*MAX_SIZE_PARAMS];

  byte params[MAX_SIZE_PARAMS];
  byte* out = params;
  int size_params = 0;
  int space_left = MAX_SIZE_PARAMS;
  int n;

  memset(commandBuf, 0, 2*MAX_SIZE_PARAMS);
  memset(params, 0, MAX_SIZE_PARAMS);

  n = SetOwnerHandle(owner, space_left, out);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &out, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(out, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &out, &size_params, &space_left);

  string emptyAuth;
  n = CreatePasswordAuthArea(emptyAuth, space_left, out);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &out, &size_params, &space_left);

  n = CreateSensitiveArea(authString, 0, NULL, space_left, out);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &out, &size_params, &space_left);

  TPM2B_PUBLIC pub_key;
  FillPublicRsaTemplate(enc_alg, int_alg, flags, sym_alg,
                        sym_key_size, sym_mode, sig_scheme,
                        mod_size, exp, pub_key);
  n = Marshal_Public_Key_Info(pub_key, space_left, out);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &out, &size_params, &space_left);

  TPM2B_DATA data;
  FillEmptyData(data);
  n = Marshal_OutsideInfo(data, space_left, out);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &out, &size_params, &space_left);

  n = Marshal_PCR_Long_Selection(pcr_selection, space_left, out);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &out, &size_params, &space_left);
  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_CreatePrimary,
                                (byte*)commandBuf,
                                size_params,
                                (byte*)params);
  if (!tpm.SendCommand(in_size, (byte*)commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  printCommand("CreatePrimary", in_size, commandBuf);

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, resp_size);
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
 
  uint16_t cap;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("CreatePrimary", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;

  TPM2B_CREATION_DATA creation_data;
  TPM2B_DIGEST hash;
  TPMT_TK_CREATION creation_ticket;
  TPM2B_NAME name;
  return GetPublicOut(responseSize - sizeof(TPM_RESPONSE),
                      &resp_buf[sizeof(TPM_RESPONSE)], handle,
                      pub_out, &creation_data,
                      &hash, &creation_ticket, &name);
}

bool GetLoadOut(int size, byte* in, TPM_HANDLE* new_handle, TPM2B_NAME* name) {
  byte* current_in = in;

  ChangeEndian32((uint32_t*)current_in, (uint32_t*)new_handle);
  current_in += sizeof(uint32_t);
  ChangeEndian16((uint16_t*)current_in, (uint16_t*)&name->size);
  current_in += sizeof(uint16_t);
  memcpy(name->name, current_in, name->size);
  current_in += name->size;
  return true;
}

bool Tpm2_PolicySecret(LocalTpm& tpm, TPM_HANDLE handle,
                       TPM2B_DIGEST* policy_digest,
                       TPM2B_TIMEOUT* timeout,
                       TPMT_TK_AUTH* ticket) {
  byte commandBuf[2*MAX_SIZE_PARAMS];

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  byte params[MAX_SIZE_PARAMS];
  byte* in = params;
  int total_size = 0;
  int space_left = MAX_SIZE_PARAMS;

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&handle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &total_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&policy_digest->size, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &total_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, policy_digest->size)
  memcpy(in, policy_digest->buffer, policy_digest->size);
  Update(policy_digest->size, &in, &total_size, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_PolicySecret,
                                commandBuf, total_size, params);
  printCommand("PolicySecret", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("PolicySecret", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return true;
}

bool Tpm2_PolicyPassword(LocalTpm& tpm, TPM_HANDLE handle) {
  byte commandBuf[2*MAX_SIZE_PARAMS];

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  byte params[MAX_SIZE_PARAMS];
  byte* current_out = params;
  int total_size = 0;

  ChangeEndian32((uint32_t*)&handle, (uint32_t*)current_out);
  current_out += sizeof(uint32_t);
  total_size += sizeof(uint32_t);

  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_PolicyPassword,
                                commandBuf, total_size, params);
  printCommand("PolicyPassword", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("PolicyPassword", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return true;
}

bool Tpm2_PolicyGetDigest(LocalTpm& tpm, TPM_HANDLE handle, TPM2B_DIGEST* digest_out) {
  byte commandBuf[2*MAX_SIZE_PARAMS];

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params[MAX_SIZE_PARAMS];

  memset(resp_buf, 0, resp_size);

  ChangeEndian32(&handle, (uint32_t*)params);
  size_params += sizeof(uint32_t);
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_PolicyGetDigest,
                                commandBuf, size_params, params);
  printCommand("PolicyGetDigest", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("PolicyGetDigest", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  byte* current_in = resp_buf + sizeof(TPM_RESPONSE);
  ChangeEndian16((uint16_t*)current_in, &digest_out->size);
  current_in += sizeof(uint16_t);
  memcpy(digest_out->buffer, current_in, digest_out->size);
  return true;
}

bool Tpm2_StartAuthSession(LocalTpm& tpm, TPM_RH tpm_obj, TPM_RH bind_obj,
                           TPM2B_NONCE& initial_nonce,
                           TPM2B_ENCRYPTED_SECRET& salt,
                           TPM_SE session_type, TPMT_SYM_DEF& symmetric,
                           TPMI_ALG_HASH hash_alg, TPM_HANDLE* session_handle,
                           TPM2B_NONCE* nonce_obj) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params[MAX_SIZE_PARAMS];
  byte* in = params;
  int space_left = MAX_SIZE_PARAMS;

  memset(params, 0, MAX_SIZE_PARAMS);

  int n= Marshal_AuthSession_Info(tpm_obj, bind_obj, initial_nonce,
                                  salt, session_type, symmetric, hash_alg,
                                  MAX_SIZE_PARAMS, params);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_StartAuthSession,
                                commandBuf, size_params, params);
  printCommand("StartAuthSession", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("StartAuthSession", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  byte* current_out = resp_buf + sizeof(TPM_RESPONSE);
  ChangeEndian32((uint32_t*)current_out, (uint32_t*)session_handle);
  current_out += sizeof(uint32_t);
  ChangeEndian16((uint16_t*)current_out, &nonce_obj->size);
  current_out += sizeof(uint16_t);
  memcpy(nonce_obj->buffer, current_out, nonce_obj->size);
  return true;
}

bool Tpm2_PolicyPcr(LocalTpm& tpm, TPM_HANDLE session_handle,
                    TPM2B_DIGEST& expected_digest, TPML_PCR_SELECTION& pcr) {
  byte commandBuf[2*MAX_SIZE_PARAMS];

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  byte params[MAX_SIZE_PARAMS];
  byte* out = params;
  int total_size = 0;
  int space_left = MAX_SIZE_PARAMS;

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t));
  ChangeEndian32((uint32_t*)&session_handle, (uint32_t*)out);
  Update(sizeof(uint32_t), &out, &total_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t));
  ChangeEndian16(&expected_digest.size, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &total_size, &space_left);

  int n = Marshal_PCR_Long_Selection(pcr, MAX_SIZE_PARAMS, out);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &out, &total_size, &space_left);
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_PolicyPCR,
                                commandBuf, total_size, params);
  printCommand("PolicyPcr", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("PolicyPcr", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return true;
}

bool Tpm2_MakeCredential(LocalTpm& tpm,
                         TPM_HANDLE keyHandle,
                         TPM2B_DIGEST& credential,
                         TPM2B_NAME& objectName,
                         TPM2B_ID_OBJECT* credentialBlob,
                         TPM2B_ENCRYPTED_SECRET* secret) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  byte params[MAX_SIZE_PARAMS];
  byte* in = params;
  int total_size = 0;
  int space_left = MAX_SIZE_PARAMS;

  memset(params, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&keyHandle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &total_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&credential.size, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &total_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, credential.size)
  memcpy(in, credential.buffer, credential.size);
  Update(credential.size, &in, &total_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&objectName.size, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &total_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, objectName.size)
  memcpy(in, objectName.name, objectName.size);
  Update(objectName.size, &in, &total_size, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_MakeCredential,
                                commandBuf, total_size, params);
  printCommand("MakeCredential", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("MakeCredential", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;

  byte* out = resp_buf + sizeof(TPM_RESPONSE);

  ChangeEndian16((uint16_t*)out, (uint16_t*)&credentialBlob->size);
  out += sizeof(uint16_t);
  memcpy(credentialBlob->credential, out, credentialBlob->size);
  out += credentialBlob->size;

  ChangeEndian16((uint16_t*)out, (uint16_t*)&secret->size);
  out += sizeof(uint16_t);
  memcpy(secret->secret, out, secret->size);
  out += secret->size;
  return true;
}

bool Tpm2_ActivateCredential(LocalTpm& tpm, TPM_HANDLE activeHandle,
                             TPM_HANDLE keyHandle,
                             string& activeAuth, string& keyAuth,
                             TPM2B_ID_OBJECT& credentialBlob,
                             TPM2B_ENCRYPTED_SECRET& secret,
                             TPM2B_DIGEST* certInfo) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  byte params[MAX_SIZE_PARAMS];
  byte* in = params;
  int total_size = 0;
  int space_left = MAX_SIZE_PARAMS;

  memset(params, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&activeHandle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &total_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&keyHandle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &total_size, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &total_size, &space_left);

  // twin auth areas
  byte activeAuthArea[512];
  byte keyAuthArea[512];
  byte outAuthArea[512];
  int n = CreatePasswordAuthArea(activeAuth, 512, activeAuthArea);
  int m = CreatePasswordAuthArea(keyAuth, 512, keyAuthArea);
  uint16_t k = m + n - 4;
  ChangeEndian16(&k, (uint16_t*)outAuthArea);
  memcpy(&outAuthArea[2], &activeAuthArea[2], n - 2);
  memcpy(&outAuthArea[n], &keyAuthArea[2], m - 2);
  memcpy(in, outAuthArea, k + 2);
  Update(k + 2, &in, &total_size, &space_left);

  ChangeEndian16((uint16_t*)&credentialBlob.size, (uint16_t*) in);
  Update(sizeof(uint16_t), &in, &total_size, &space_left);
  memcpy(in, credentialBlob.credential, credentialBlob.size);
  Update(credentialBlob.size, &in, &total_size, &space_left);

  ChangeEndian16((uint16_t*)&secret.size, (uint16_t*) in);
  Update(sizeof(uint16_t), &in, &total_size, &space_left);
  memcpy(in, secret.secret, secret.size);
  Update(secret.size, &in, &total_size, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_ActivateCredential,
                                commandBuf, total_size, params);
  printCommand("ActivateCredential", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("ActivateCredential", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;

  byte* out = resp_buf + sizeof(TPM_RESPONSE);
  out += sizeof(uint32_t);
  ChangeEndian16((uint16_t*)out, (uint16_t*)&certInfo->size);
  out += sizeof(uint16_t);
  memcpy(certInfo->buffer, out, certInfo->size);
  out += certInfo->size;
  return true;
}

bool Tpm2_Load(LocalTpm& tpm, TPM_HANDLE parent_handle, 
               string& parentAuth,
               int size_public, byte* inPublic,
               int size_private, byte* inPrivate,
               TPM_HANDLE* new_handle, TPM2B_NAME* name) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  memset(commandBuf, 0, 2*MAX_SIZE_PARAMS);

  byte params_buf[MAX_SIZE_PARAMS];
  memset(params_buf, 0, MAX_SIZE_PARAMS);
  byte* in = params_buf;
  int size_params = 0;
  int space_left = MAX_SIZE_PARAMS;
  int n;

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&parent_handle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, 2);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  n = CreatePasswordAuthArea(parentAuth, MAX_SIZE_PARAMS, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, size_private + 2)
  memcpy(in, inPrivate, size_private + 2);
  Update(size_private + 2, &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, size_public + 2)
  memcpy(in, inPublic, size_public + 2);
  Update(size_public + 2, &in, &size_params, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_Load, (byte*)commandBuf,
                                size_params, (byte*)params_buf);
  printCommand("Load", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, (byte*)commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, resp_size);
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
 
  uint16_t cap;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("Load", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return GetLoadOut(responseSize - sizeof(TPM_RESPONSE),
                    &resp_buf[sizeof(TPM_RESPONSE)], new_handle, name);
}

bool Tpm2_Save(LocalTpm& tpm) {
  printf("Unimplmented\n");
  return false;
}

int GetName(uint16_t size_in, byte* in, TPM2B_NAME* name) {
  int total_size = 0;

  ChangeEndian16((uint16_t*) in, (uint16_t*)&name->size);
  in += sizeof(uint16_t);
  memcpy(name->name, in, name->size);
  in += name->size;
  return total_size;
}

int GetRsaParams(uint16_t size_in, byte* input, TPMS_RSA_PARMS& rsaParams,
                 TPM2B_PUBLIC_KEY_RSA* rsa) {
  int total_size = 0;

  ChangeEndian16((uint16_t*) input, (uint16_t*)&rsaParams.symmetric.algorithm);
  input += sizeof(uint16_t);
  total_size += sizeof(uint16_t);
  if (rsaParams.symmetric.algorithm != TPM_ALG_NULL) {
    ChangeEndian16((uint16_t*) input, (uint16_t*)&rsaParams.symmetric.keyBits);
    input += sizeof(uint16_t);
    total_size += sizeof(uint16_t);
    ChangeEndian16((uint16_t*) input, (uint16_t*)&rsaParams.symmetric.mode);
    input += sizeof(uint16_t);
    total_size += sizeof(uint16_t);
    ChangeEndian16((uint16_t*) input,
                   (uint16_t*)&rsaParams.scheme.scheme);
    input += sizeof(uint16_t);
    total_size += sizeof(uint16_t);
    // TODO(jlm): what goes here?  Details?
    input += sizeof(uint16_t);
    total_size += sizeof(uint16_t);
   } else {
     ChangeEndian16((uint16_t*) input,
                    (uint16_t*)&rsaParams.scheme.scheme);
     input += sizeof(uint16_t);
     total_size += sizeof(uint16_t);
     // TODO(jlm): what goes here?  Details?
     input += sizeof(uint32_t);
     total_size += sizeof(uint32_t);
   }
  // Exponent
  ChangeEndian32((uint32_t*) input, (uint32_t*)&rsaParams.exponent);
  input += sizeof(uint32_t);
  total_size += sizeof(uint32_t);
  // modulus size
  ChangeEndian16((uint16_t*) input, (uint16_t*)&rsa->size);
  input += sizeof(uint16_t);
  total_size += sizeof(uint16_t);
  // modulus
  memcpy(rsa->buffer, input, rsa->size);
  input += rsa->size;
  total_size += rsa->size;
  return total_size;
}

bool GetReadPublicOut(uint16_t size_in, byte* input, TPM2B_PUBLIC* outPublic) {
  ChangeEndian16((uint16_t*) input, (uint16_t*)&outPublic->publicArea.type);
  input += sizeof(uint16_t);
  size_in -= sizeof(uint16_t);
  ChangeEndian16((uint16_t*) input, (uint16_t*)&outPublic->publicArea.nameAlg);
  input += sizeof(uint16_t);
  size_in -= sizeof(uint16_t);
  ChangeEndian32((uint32_t*) input,
                 (uint32_t*)&outPublic->publicArea.objectAttributes);
  input += sizeof(uint32_t);
  size_in -= sizeof(uint32_t);
  ChangeEndian16((uint16_t*) input, 
                 (uint16_t*)&outPublic->publicArea.authPolicy.size);
  input += sizeof(uint16_t);
  size_in -= sizeof(uint16_t);
  memcpy(outPublic->publicArea.authPolicy.buffer, input,
         outPublic->publicArea.authPolicy.size);
  input += outPublic->publicArea.authPolicy.size;
  size_in -= outPublic->publicArea.authPolicy.size;

  if (outPublic->publicArea.type!= TPM_ALG_RSA) {
    printf("Can only retrieve RSA Params %04x\n", outPublic->publicArea.nameAlg);
    return false;
  }
  int n = GetRsaParams(size_in, input,
                       outPublic->publicArea.parameters.rsaDetail,
                       &outPublic->publicArea.unique.rsa);
  if (n < 0) {
    printf("Can't get RSA Params\n");
    return false;
  }
  input += n;
  return true;
}

bool Tpm2_ReadPublic(LocalTpm& tpm, TPM_HANDLE handle,
                     uint16_t* pub_blob_size, byte* pub_blob,
                     TPM2B_PUBLIC* outPublic, TPM2B_NAME* name,
                     TPM2B_NAME* qualifiedName) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  memset(commandBuf, 0, MAX_SIZE_PARAMS);

  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  byte* in = params_buf;
  int space_left = MAX_SIZE_PARAMS;
  int n;

  memset(resp_buf, 0, MAX_SIZE_PARAMS);
  memset(params_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&handle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_ReadPublic,
                                commandBuf, size_params, params_buf);
  printCommand("ReadPublic", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("ReadPublic", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  byte* out = resp_buf + sizeof(TPM_RESPONSE);

  ChangeEndian16((uint16_t*)out, (uint16_t*)&outPublic->size);
  *pub_blob_size = outPublic->size + 2;
  memcpy(pub_blob, out, outPublic->size + 2);
  out += sizeof(uint16_t);
  if (!GetReadPublicOut(outPublic->size, out, outPublic)) {
    printf("ReadPublic can't GetPublic\n");
    return false;
  }
  out += outPublic->size;
  n = GetName(0, out, name);
  if (n < 0) {
    printf("ReadPublic can't Get name\n");
    return false;
  }
  out += n;
  n = GetName(0, out, qualifiedName);
  if (n < 0) {
    printf("ReadPublic can't Get qualified name\n");
    return false;
  }
  out += n;
  return true;
}

bool Tpm2_Certify(LocalTpm& tpm, TPM_HANDLE signedKey, TPM_HANDLE signingKey,
                  string& auth_signed_key, string& auth_signing_key, 
                  TPM2B_DATA& qualifyingData,
                  TPM2B_ATTEST* attest, TPMT_SIGNATURE* sig) {
  byte commandBuf[2*MAX_SIZE_PARAMS];

  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, MAX_SIZE_PARAMS);
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;
  int n;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(params_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&signedKey, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&signingKey, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  byte* size_ptr = in;
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  uint16_t first_position= size_params;
  uint32_t password_auth = TPM_RS_PW;

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&password_auth, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, 1)
  *in = 1;
  Update(1, &in, &size_params, &space_left);

  n = SetPasswordData(auth_signed_key, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&password_auth, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, 1)
  *in = 1;
  Update(1, &in, &size_params, &space_left);

  n = SetPasswordData(auth_signed_key, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  uint16_t block_size = size_params - first_position;
  ChangeEndian16((uint16_t*)&block_size, (uint16_t*)size_ptr);

  // parameters: qualifying data, scheme
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&qualifyingData.size, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, qualifyingData.size)
  memcpy(in, qualifyingData.buffer, qualifyingData.size);
  Update(qualifyingData.size, &in, &size_params, &space_left);

  TPMI_ALG_HASH alg = TPM_ALG_NULL;
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&alg, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);
  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_Certify,
                                commandBuf, size_params, params_buf);
  printCommand("Certify", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("Certify", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  byte* out = resp_buf + sizeof(TPM_RESPONSE);
  out += 2*sizeof(uint16_t);  // check this
  ChangeEndian16((uint16_t*)out, &attest->size);
  out += sizeof(uint16_t);
  memcpy(attest->attestationData, out, attest->size);
  out += attest->size;
  ChangeEndian16((uint16_t*)out, &sig->sigAlg);
  out += sizeof(uint16_t);
  if (sig->sigAlg != TPM_ALG_RSASSA) {
    printf("I only understand TPM_ALG_RSASSA signatures for now\n");
    return false;
  }
  ChangeEndian16((uint16_t*)out, &sig->signature.rsassa.hash);
  out += sizeof(uint16_t);
  ChangeEndian16((uint16_t*)out, &sig->signature.rsassa.sig.size);
  out += sizeof(uint16_t);
  memcpy(sig->signature.rsassa.sig.buffer, out,
         sig->signature.rsassa.sig.size);
  out += sizeof(sig->signature.rsassa.sig.size);
  return true;
}

bool GetCreateOut(int size, byte* in, int* size_public, byte* out_public, 
                  int* size_private, byte* out_private, 
                  TPM2B_CREATION_DATA* creation_out, TPM2B_DIGEST* digest_out,
                  TPMT_TK_CREATION* creation_ticket) {
  byte* current_in = in;

  uint32_t unknown;
  ChangeEndian32((uint32_t*)current_in, (uint32_t*)&unknown);
  current_in += sizeof(uint32_t);

  *size_private = 0;
  ChangeEndian16((uint16_t*)current_in, (uint16_t*)size_private);
  memcpy(out_private, current_in, *size_private + 2);
  current_in += *size_private + 2;

  *size_public = 0;
  ChangeEndian16((uint16_t*)current_in, (uint16_t*)size_public);
  memcpy(out_public, current_in, *size_public + 2);
  current_in += *size_public + 2;

  ChangeEndian16((uint16_t*)current_in, &creation_out->size);
  current_in += sizeof(uint16_t);
  ChangeEndian32((uint32_t*)current_in,
                 &creation_out->creationData.pcrSelect.count);
  current_in += sizeof(uint32_t);
  
  for (uint32_t i = 0; i < creation_out->creationData.pcrSelect.count; i++) {
    ChangeEndian16((uint16_t*)current_in,
                  &creation_out->creationData.pcrSelect.pcrSelections[i].hash);
    current_in += sizeof(uint16_t);
    creation_out->creationData.pcrSelect.pcrSelections[i].sizeofSelect =
      *(current_in++);
    memcpy(&creation_out->creationData.pcrSelect.pcrSelections[i].pcrSelect,
           current_in,
           creation_out->creationData.pcrSelect.pcrSelections[i].sizeofSelect);
    current_in +=
      creation_out->creationData.pcrSelect.pcrSelections[i].sizeofSelect;
  }

  ChangeEndian16((uint16_t*)current_in,
                 &creation_out->creationData.pcrDigest.size);
  current_in += sizeof(uint16_t);
  memcpy(creation_out->creationData.pcrDigest.buffer, current_in,
         creation_out->creationData.pcrDigest.size);
  current_in += creation_out->creationData.pcrDigest.size;
  return true;
}

bool Tpm2_CreateKey(LocalTpm& tpm, TPM_HANDLE parent_handle, 
                 string& parentAuth, string& authString,
                 TPML_PCR_SELECTION& pcr_selection,
                 TPM_ALG_ID enc_alg, TPM_ALG_ID int_alg,
                 TPMA_OBJECT& flags, TPM_ALG_ID sym_alg,
                 TPMI_AES_KEY_BITS sym_key_size,
                 TPMI_ALG_SYM_MODE sym_mode, TPM_ALG_ID sig_scheme,
                 int mod_size, uint32_t exp,
                 int* size_public, byte* out_public, 
                 int* size_private, byte* out_private,
                 TPM2B_CREATION_DATA* creation_out,
                 TPM2B_DIGEST* digest_out, TPMT_TK_CREATION* creation_ticket) {
  byte commandBuf[2*MAX_SIZE_PARAMS];

  byte params[MAX_SIZE_PARAMS];
  byte* in = params;
  int size_params = 0;
  int space_left = MAX_SIZE_PARAMS;
  int n;

  memset(commandBuf, 0, 2*MAX_SIZE_PARAMS);
  memset(params, 0, MAX_SIZE_PARAMS);

  // parent handle
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*) &parent_handle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  n = CreatePasswordAuthArea(authString, space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);

  n = CreateSensitiveArea(authString, 0, NULL, space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);

  TPM2B_PUBLIC pub_key;
  FillPublicRsaTemplate(enc_alg, int_alg, flags, sym_alg,
                        sym_key_size, sym_mode, sig_scheme,
                        mod_size, exp, pub_key);

  n = Marshal_Public_Key_Info(pub_key, space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);

  TPM2B_DATA data;
  FillEmptyData(data);
  n = Marshal_OutsideInfo(data, space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);

  n = Marshal_PCR_Long_Selection(pcr_selection, space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);
  
  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_Create,
                                (byte*)commandBuf,
                                size_params,
                                (byte*)params);
  printCommand("Create", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, (byte*)commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, resp_size);
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
 
  uint16_t cap;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("Create", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;

  return GetCreateOut(responseSize - sizeof(TPM_RESPONSE),
                      &resp_buf[sizeof(TPM_RESPONSE)],
                      size_public, out_public,
                      size_private, out_private,
                      creation_out, digest_out, creation_ticket);
}

bool Tpm2_CreateSealed(LocalTpm& tpm, TPM_HANDLE parent_handle, 
                       int size_policy_digest, byte* policy_digest,
                       string& parentAuth,
                       int size_to_seal, byte* to_seal,
                       TPML_PCR_SELECTION& pcr_selection,
                       TPM_ALG_ID int_alg,
                       TPMA_OBJECT& flags, TPM_ALG_ID sym_alg,
                       TPMI_AES_KEY_BITS sym_key_size,
                       TPMI_ALG_SYM_MODE sym_mode, TPM_ALG_ID sig_scheme,
                       int mod_size, uint32_t exp,
                       int* size_public, byte* out_public, 
                       int* size_private, byte* out_private,
                       TPM2B_CREATION_DATA* creation_out,
                       TPM2B_DIGEST* digest_out,
                       TPMT_TK_CREATION* creation_ticket) {
  byte commandBuf[2*MAX_SIZE_PARAMS];

  byte params[MAX_SIZE_PARAMS];
  byte* in = params;
  int size_params = 0;
  int space_left = MAX_SIZE_PARAMS;
  int n;

  memset(commandBuf, 0, 2*MAX_SIZE_PARAMS);
  memset(params, 0, MAX_SIZE_PARAMS);

  // parent handle
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*) &parent_handle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  string emptyAuth;
  n = CreatePasswordAuthArea(parentAuth, space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);
  n = CreateSensitiveArea(parentAuth, size_to_seal, to_seal,
                          space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);

  TPM2B_PUBLIC keyed_hash;
  FillKeyedHashTemplate(TPM_ALG_KEYEDHASH, int_alg, flags, 
                        size_policy_digest, policy_digest, keyed_hash);
  n = Marshal_Keyed_Hash_Info(keyed_hash, space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);

  TPM2B_DATA data;
  FillEmptyData(data);
  n = Marshal_OutsideInfo(data, space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);

  n = Marshal_PCR_Long_Selection(pcr_selection, space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);
  
  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_Create,
                                (byte*)commandBuf,
                                size_params,
                                (byte*)params);
  printCommand("CreateSealed", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, (byte*)commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }

  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, resp_size);
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
 
  uint16_t cap;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("Create", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;

  return GetCreateOut(responseSize - sizeof(TPM_RESPONSE),
                      &resp_buf[sizeof(TPM_RESPONSE)],
                      size_public, out_public, size_private, out_private,
                      creation_out, digest_out, creation_ticket);
}

bool ComputeHmac(int size_buf, byte* command, TPM2B_NONCE& newNonce, 
                 TPM2B_NONCE& oldNonce, uint16_t* size_hmac,
                 byte* hmac) {
  memset(hmac, 0 , *size_hmac);
  *size_hmac = 0;
  return true;
}

bool Tpm2_Unseal(LocalTpm& tpm, TPM_HANDLE item_handle, string& parentAuth,
                 TPM_HANDLE session_handle, TPM2B_NONCE& nonce,
                 byte session_attributes, TPM2B_DIGEST& hmac_digest,
                 int* out_size, byte* unsealed) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  memset(commandBuf, 0, 2*MAX_SIZE_PARAMS);

  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  int space_left = MAX_SIZE_PARAMS;
  byte params_buf[MAX_SIZE_PARAMS];
  byte* in = params_buf;
  int n;

  memset(params_buf, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&item_handle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);
  
  byte* auth_area_size_ptr = in;
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  uint16_t start_of_auth_area = size_params;

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&session_handle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  // null hmac
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, 1)
  *in = session_attributes;
  Update(1, &in, &size_params, &space_left);

  // password
  n = SetPasswordData(parentAuth, space_left, in);
  IF_NEG_RETURN_FALSE(n)
  Update(n, &in, &size_params, &space_left);

  uint16_t auth_area = size_params - start_of_auth_area;
  ChangeEndian16(&auth_area, (uint16_t*)auth_area_size_ptr);
  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_Unseal,
                                commandBuf, size_params, params_buf);
  printCommand("Unseal", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("Unseal", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  *out_size = (int)(responseSize - sizeof(TPM_RESPONSE));
  memcpy(unsealed, resp_buf + sizeof(TPM_RESPONSE), *out_size);
  return true;
}

bool Tpm2_Quote(LocalTpm& tpm, TPM_HANDLE signingHandle, string& parentAuth,
               int quote_size, byte* toQuote,
               TPMT_SIG_SCHEME scheme, TPML_PCR_SELECTION& pcr_selection,
               TPM_ALG_ID sig_alg, TPM_ALG_ID hash_alg, 
               int* attest_size, byte* attest, int* sig_size, byte* sig) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  memset(commandBuf, 0, 2*MAX_SIZE_PARAMS);

  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  int space_left = MAX_SIZE_PARAMS;
  byte params_buf[MAX_SIZE_PARAMS];
  byte* in = params_buf;
  int n;

  memset(resp_buf, 0, MAX_SIZE_PARAMS);
  memset(params_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&signingHandle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  FillSignatureSchemeTemplate(sig_alg, hash_alg, scheme);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  n = CreatePasswordAuthArea(parentAuth, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&quote_size, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, quote_size)
  memcpy(in, toQuote, quote_size);
  Update(quote_size, &in, &size_params, &space_left);

  uint16_t algorithm = TPM_ALG_NULL;
  IF_LESS_THAN_RETURN_FALSE(space_left, quote_size)
  ChangeEndian16((uint16_t*)&algorithm, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  ChangeEndian16((uint16_t*)&algorithm, (uint16_t*)in);
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  n= Marshal_Signature_Scheme_Info(scheme, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  n = Marshal_PCR_Short_Selection(pcr_selection.pcrSelections[0], space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_Quote,
                                commandBuf, size_params, params_buf);
  printCommand("Quote", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("Quote", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;

  byte* out = &resp_buf[sizeof(TPM_RESPONSE)];
  TPMI_ALG_SIG_SCHEME scheme1;
  TPMI_ALG_SIG_SCHEME scheme2;

  out += sizeof(uint32_t);
  ChangeEndian16((uint16_t*)out, (uint16_t*)attest_size);
  out += sizeof(uint16_t);
  memcpy(attest, out, *attest_size);
  out += *attest_size;
  ChangeEndian16((uint16_t*)out, (uint16_t*)&scheme1);
  out += sizeof(uint16_t);
  ChangeEndian16((uint16_t*)out, (uint16_t*)&scheme2);
  out += sizeof(uint16_t);
  ChangeEndian16((uint16_t*)out, (uint16_t*)sig_size);
  out += sizeof(uint16_t);
  memcpy(sig, out, *sig_size);
  out += *sig_size;
  return true;
}

bool Tpm2_LoadContext(LocalTpm& tpm, uint16_t size, byte* saveArea,
                      TPM_HANDLE* handle) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  memset(commandBuf, 0, 2*MAX_SIZE_PARAMS);

  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, MAX_SIZE_PARAMS);
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  memset(params_buf, 0, MAX_SIZE_PARAMS);
  byte* current_out = params_buf;

  memcpy(current_out, saveArea, size);
  size_params += size;
  current_out += size;
  
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_ContextLoad,
                                commandBuf, size_params, params_buf);
  printCommand("ContextLoad", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("ContextLoad", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  ChangeEndian32((uint32_t*)(resp_buf + responseSize - sizeof(uint32_t)),
                 (uint32_t*)handle);
  return true;
}

bool Tpm2_SaveContext(LocalTpm& tpm, TPM_HANDLE handle, uint16_t* size,
                      byte* saveArea) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  memset(commandBuf, 0, 2*MAX_SIZE_PARAMS);

  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, MAX_SIZE_PARAMS);
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  memset(params_buf, 0, MAX_SIZE_PARAMS);
  byte* current_out = params_buf;

  ChangeEndian32((uint32_t*)&handle, (uint32_t*)current_out);
  size_params += sizeof(uint32_t);
  current_out += sizeof(uint32_t);
  
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_ContextSave,
                                commandBuf, size_params, params_buf);
  printCommand("SaveContext", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("SaveContext", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  *size = responseSize - sizeof(TPM_RESPONSE);
  memcpy(saveArea, resp_buf + sizeof(TPM_RESPONSE), *size);
  return true;
}

bool Tpm2_FlushContext(LocalTpm& tpm, TPM_HANDLE handle) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  memset(commandBuf, 0, MAX_SIZE_PARAMS);

  uint32_t big_endian_handle;
  int size_resp= MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  ChangeEndian32((uint32_t*)&handle, &big_endian_handle);
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_FlushContext,
                                commandBuf, sizeof(TPM_HANDLE),
                                (byte*)&big_endian_handle);
  printCommand("FlushContext", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("FlushContext", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return true;
}

TPM_HANDLE GetNvHandle(uint32_t slot) {
  return (TPM_HANDLE)((TPM_HT_NV_INDEX << HR_SHIFT) + slot);
}

bool Tpm2_IncrementNv(LocalTpm& tpm, TPMI_RH_NV_INDEX index, string& authString) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;
  int n;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  n = CreatePasswordAuthArea(authString, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_NV_Increment,
                                commandBuf, size_params, params_buf);
  printCommand("IncrementNv", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("IncrementNv", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;

  return true;
}

bool Tpm2_ReadNv(LocalTpm& tpm, TPMI_RH_NV_INDEX index,
                 string& authString, uint16_t* size, byte* data) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, MAX_SIZE_PARAMS);
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;
  int n;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(params_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  n = CreatePasswordAuthArea(authString, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);
  memset(in, 0, sizeof(uint16_t));

  uint16_t offset = 0;
  ChangeEndian16((uint16_t*)size, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);
  IF_NEG_RETURN_FALSE(n);
  ChangeEndian16((uint16_t*)&offset, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_NV_Read,
                                commandBuf, size_params, params_buf);
  printCommand("ReadNv", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("ReadNv", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  byte* out = resp_buf + sizeof(TPM_RESPONSE) + sizeof(uint32_t);
  ChangeEndian16((uint16_t*)out, (uint16_t*)size);
  out += sizeof(uint16_t);
  memcpy(data, out, *size);
  return true;
}

bool Tpm2_WriteNv(LocalTpm& tpm, TPMI_RH_NV_INDEX index, 
                  string& authString, uint16_t size, byte* data) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;
  int n;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  n = CreatePasswordAuthArea(authString, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&size, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, size)
  memcpy(in, data, size);
  Update(size, &in, &size_params, &space_left);

  uint16_t offset = 0;
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&offset, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_NV_Write,
                                commandBuf, size_params, params_buf);
  printCommand("WriteNv", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("WriteNv", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return true;
}

bool Tpm2_DefineSpace(LocalTpm& tpm, TPM_HANDLE owner, TPMI_RH_NV_INDEX index,
                      string& authString, uint16_t authPolicySize, byte* authPolicy,
                      uint32_t attributes, uint16_t size_data) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  int n = SetOwnerHandle(owner, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);;

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  string emptyAuth;
  n = CreatePasswordAuthArea(emptyAuth, space_left, in);

  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  n = SetPasswordData(authString, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  // TPM2B_NV_PUBLIC
  uint16_t size_nv_area = sizeof(uint32_t) + sizeof(TPMI_RH_NV_INDEX) +
                          sizeof(TPMI_ALG_HASH) + 2*sizeof(uint16_t) +
                          authPolicySize;
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&size_nv_area, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))

  // nvIndex;
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  // TPMI_ALG_HASH alg = TPM_ALG_SHA256;
  TPMI_ALG_HASH alg = TPM_ALG_SHA1;
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&alg, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&attributes, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  // authPolicy size
  ChangeEndian16((uint16_t*)&authPolicySize, (uint16_t*)in);
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  Update(sizeof(uint16_t), &in, &size_params, &space_left);
  if (authPolicySize > 0) {
    IF_LESS_THAN_RETURN_FALSE(space_left, authPolicySize)
    memcpy(in, authPolicy, authPolicySize);
    Update(authPolicySize, &in, &size_params, &space_left);
  }

  // dataSize
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&size_data, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_NV_DefineSpace,
                                commandBuf, size_params, params_buf);
  printCommand("DefineSpace", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("Definespace", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return true;
}

bool Tpm2_UndefineSpace(LocalTpm& tpm, TPM_HANDLE owner, TPMI_RH_NV_INDEX index) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;
  int n;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  n = SetOwnerHandle(owner, space_left, params_buf);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  memset(in, 0, sizeof(uint16_t));
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  string emptyAuth;
  n = CreatePasswordAuthArea(emptyAuth, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_NV_UndefineSpace,
                                commandBuf, size_params, params_buf);
  printCommand("UndefineSpace", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("UndefineSpace", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return true;
}

bool Tpm2_DictionaryAttackLockReset(LocalTpm& tpm) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  memset(commandBuf, 0, 2*MAX_SIZE_PARAMS);

  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, MAX_SIZE_PARAMS);
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  memset(params_buf, 0, MAX_SIZE_PARAMS);
  byte* current_out = params_buf;
  TPM_HANDLE handle = TPM_RH_LOCKOUT;

  ChangeEndian32((uint32_t*)&handle, (uint32_t*)current_out);
  size_params += sizeof(uint32_t);
  current_out += sizeof(uint32_t);
  
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS,
                                TPM_CC_DictionaryAttackLockReset,
                                commandBuf, size_params, params_buf);
  printCommand("DictionaryAttackLockReset", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("DictionaryAttackLockReset", cap, responseSize,
                responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  return true;
}

bool Tpm2_Flushall(LocalTpm& tpm, uint32_t start) {
  int size = MAX_SIZE_PARAMS;
  byte buf[MAX_SIZE_PARAMS];

  if (!Tpm2_GetCapability(tpm, TPM_CAP_HANDLES, start, &size, buf)) {
    printf("Flushall can't get capabilities\n");
    return false;
  }
  uint32_t cap;
  uint32_t count;
  uint32_t handle;
  byte* current_in = buf;

  current_in += 1;
  ChangeEndian32((uint32_t*)current_in, &cap);
  current_in += sizeof(uint32_t);
  if (cap != TPM_CAP_HANDLES) {
    printf("Flushall: didn't get handles\n");
    return false;
  }
  while (current_in < (size+buf)) {
    uint32_t i;
    ChangeEndian32((uint32_t*)current_in, &count);
    current_in += sizeof(uint32_t);
    for (i = 0; i < count; i++) {
      ChangeEndian32((uint32_t*)current_in, &handle);
      current_in += sizeof(uint32_t);
      printf("deleting handle: %08x\n", handle);
      Tpm2_FlushContext(tpm, handle);
    }
  }
  return true;
}

bool Tpm2_Rsa_Encrypt(LocalTpm& tpm, TPM_HANDLE handle, string& authString,
                      TPM2B_PUBLIC_KEY_RSA& inData, TPMT_RSA_DECRYPT& scheme,
                      TPM2B_DATA& label, TPM2B_PUBLIC_KEY_RSA* outData) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;
  int n;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  n = SetPasswordData(authString, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&handle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&inData.size, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);
  IF_LESS_THAN_RETURN_FALSE(space_left, inData.size)
  memcpy(in, inData.buffer, inData.size);
  Update(inData.size, &in, &size_params, &space_left);

  scheme.scheme = TPM_ALG_NULL;
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&scheme.scheme, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&label.size, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, label.size)
  memcpy(in, label.buffer, label.size);
  Update(label.size, &in, &size_params, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_RSA_Encrypt,
                                commandBuf, size_params, params_buf);
  printCommand("TPM_CC_RSA_Encrypt", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("TPM_RSA_Encrypt", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  byte* out = resp_buf +  sizeof(TPM_RESPONSE);
  ChangeEndian16((uint16_t*)out, &outData->size);
  out += sizeof(uint16_t);
  memcpy(outData->buffer, out, outData->size);
  out += outData->size;
  return true;
}

bool Tpm2_EvictControl(LocalTpm& tpm, TPMI_RH_PROVISION owner,
                       TPM_HANDLE handle, string& authString,
                       TPMI_DH_PERSISTENT persistantHandle) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;
  int n;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  n = SetOwnerHandle(owner, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&handle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  uint16_t hack = 0;
  ChangeEndian16((uint16_t*)&hack, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  string emptyAuth;
  n = CreatePasswordAuthArea(emptyAuth, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);

#if 0
  n = SetPasswordData(authString, space_left, in);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);
#endif

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&persistantHandle, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_EvictControl,
                                commandBuf, size_params, params_buf);
  printCommand("EvictControl", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("EvictControl", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
#if 0
  byte* out = resp_buf +  sizeof(TPM_RESPONSE);
  ChangeEndian32((uint32_t*)out, &persistantHandle);
  out += sizeof(uint32_t);
#endif
  return true;
}

#define DEBUG

//    1. Generate Seed
//    2. encrypted_secret= E(protector_key, seed || "IDENTITY")
//    3. symKey ≔ KDFa (ekNameAlg, seed, “STORAGE”, name, NULL , bits)
//    4. encIdentity ≔ AesCFB(symKey, 0, credential)
//    5. HMACkey ≔ KDFa (ekNameAlg, seed, “INTEGRITY”, NULL, NULL, bits)
//    6. outerHMAC ≔ HMAC(HMACkey, encIdentity || Name)
bool MakeCredential(int size_endorsement_blob, byte* endorsement_blob,
                    TPM_ALG_ID hash_alg_id,
                    TPM2B_DIGEST& unmarshaled_credential,
                    TPM2B_DIGEST& marshaled_credential,
                    TPM2B_NAME& unmarshaled_name,
                    TPM2B_NAME& marshaled_name,
                    int* size_encIdentity, byte* encIdentity,
                    TPM2B_ENCRYPTED_SECRET* unmarshaled_encrypted_secret,
                    TPM2B_ENCRYPTED_SECRET* marshaled_encrypted_secret,
                    TPM2B_DIGEST* unmarshaled_integrityHmac,
                    TPM2B_DIGEST* marshaled_integrityHmac) {
  X509* endorsement_cert = nullptr;
  int size_seed = 16;
  byte seed[32];
  int size_secret = 256;
  byte secret_buf[256];
  byte zero_iv[32];
  byte symKey[MAX_SIZE_PARAMS];
  string label;
  string key;
  string contextU;
  string contextV;
  string name;

  memset(zero_iv, 0, 32);
#ifdef DEBUG
  printf("MakeCredential\n");
#endif

  // 1. Generate seed
  RAND_bytes(seed, size_seed);

  // Get endorsement public key, which is protector key
  byte* p = endorsement_blob;
  endorsement_cert = d2i_X509(nullptr, (const byte**)&p, size_endorsement_blob);
  EVP_PKEY* protector_evp_key = X509_get_pubkey(endorsement_cert);
  RSA* protector_key = EVP_PKEY_get1_RSA(protector_evp_key);
  RSA_up_ref(protector_key);

  // 2. Secret= E(protector_key, seed || "IDENTITY")
  //   args: to, from, label, len
  size_secret= 256;
  RSA_padding_add_PKCS1_OAEP(secret_buf, 256, seed, size_seed,
      (byte*)"IDENTITY", strlen("IDENTITY")+1);
#ifdef DEBUG
  int k = 0;
  byte check[512];
  memset(check, 0, 512);
  while(k < 256 && secret_buf[k] == 0) k++;
  int check_len = RSA_padding_check_PKCS1_OAEP(check, 256, &secret_buf[k], 256-k,
                    256, (byte*)"IDENTITY", strlen("IDENTITY")+1);
  printf("Seed         : ");PrintBytes(size_seed, seed);printf("\n");
  printf("Funny padding: ");PrintBytes(256, secret_buf);printf("\n");
  printf("check %03d    : ", check_len);PrintBytes(check_len, check);printf("\n");
#endif
  int n = RSA_public_encrypt(size_secret, secret_buf,
                             unmarshaled_encrypted_secret->secret,
                             protector_key, RSA_NO_PADDING);
  if (n <=0)
    return false;
  unmarshaled_encrypted_secret->size = n;
  ChangeEndian16((uint16_t*)&unmarshaled_encrypted_secret->size,
                 &marshaled_encrypted_secret->size);
  memcpy(marshaled_encrypted_secret->secret, unmarshaled_encrypted_secret->secret,
         unmarshaled_encrypted_secret->size);
 
  // 3. Calculate symKey
  label = "STORAGE";
  key.assign((const char*)seed, size_seed);
  contextV.clear();
  name.assign((const char*)unmarshaled_name.name, unmarshaled_name.size);
  if (!KDFa(hash_alg_id, key, label, name, contextV, 128, 32, symKey)) {
    printf("Can't KDFa symKey\n");
    return false;
  }

  // 4. encIdentity
  if (!AesCFBEncrypt(symKey, unmarshaled_credential.size + sizeof(uint16_t),
                     (byte*)&marshaled_credential, 16, zero_iv,
                     size_encIdentity, encIdentity)) {
    printf("Can't AesCFBEncrypt\n");
    return false;
  }

  int size_hmacKey = SizeHash(hash_alg_id);
  byte hmacKey[128];

// 5. HMACkey ≔ KDFa (ekNameAlg, seed, “INTEGRITY”, NULL, NULL, bits)
  label = "INTEGRITY";
  if (!KDFa(hash_alg_id, key, label, contextV, contextV,
            8 * SizeHash(hash_alg_id), 32, hmacKey)) {
    printf("Can't KDFa hmacKey\n");
    return false;
  }

// 6. Calculate outerMac = HMAC(hmacKey, encIdentity || name);
  HMAC_CTX hctx;
  HMAC_CTX_init(&hctx);
  if (hash_alg_id == TPM_ALG_SHA1) {
    HMAC_Init_ex(&hctx, hmacKey, size_hmacKey, EVP_sha1(), nullptr);
  } else {
    HMAC_Init_ex(&hctx, hmacKey, size_hmacKey, EVP_sha256(), nullptr);
  }
  HMAC_Update(&hctx, (const byte*)encIdentity, (size_t)*size_encIdentity);
  HMAC_Update(&hctx, (const byte*)name.data(), name.size());
  // HMAC_Update(&hctx, (const byte*)&marshaled_name.name, name.size());
  unmarshaled_integrityHmac->size = size_hmacKey;
  HMAC_Final(&hctx, unmarshaled_integrityHmac->buffer, (uint32_t*)&size_hmacKey);
  HMAC_CTX_cleanup(&hctx);

  // integrityHMAC
  ChangeEndian16((uint16_t*)&size_hmacKey, &marshaled_integrityHmac->size);
  memcpy(marshaled_integrityHmac->buffer, unmarshaled_integrityHmac->buffer,
         size_hmacKey);
#ifdef DEBUG
  printf("encIdentity: "); PrintBytes(*size_encIdentity, (byte*)encIdentity); printf("\n");
  printf("name       : "); PrintBytes(name.size(), (byte*)name.data()); printf("\n");
  printf("hmac       : "); PrintBytes(size_hmacKey, (byte*)unmarshaled_integrityHmac->buffer); printf("\n");
  printf("marsh-hmac : "); PrintBytes(size_hmacKey + 2, (byte*)&marshaled_integrityHmac); printf("\n");
#endif
  return true;
}

// encrypted_data_hmac is an input argument for decrypt and
// an output argument for encrypt.
bool EncryptDataWithCredential(bool encrypt_flag, TPM_ALG_ID hash_alg_id,
                 TPM2B_DIGEST unmarshaled_credential,
                 TPM2B_DIGEST marshaled_credential,
                 int size_input_data, byte* input_data,
                 int* size_hmac, byte* encrypted_data_hmac,
                 int* size_output_data, byte* output_data) {
  int size_derived_keys = 128;
  byte derived_keys[128];
  byte decrypt_mac[128];
  string data_encryption_key_seed;
  string label;
  string contextV;
  byte* encrypted_data = output_data;

  *size_hmac = SizeHash(hash_alg_id);
  data_encryption_key_seed.assign((const char*)unmarshaled_credential.buffer,
                       unmarshaled_credential.size);
  label = "PROTECT";
  if (!KDFa(hash_alg_id, data_encryption_key_seed, label, contextV, contextV, 256,
            size_derived_keys, derived_keys)) {
    printf("Can't derive protection keys\n");
    return false;
  }

  memset(output_data, 0, *size_output_data);
  if (!AesCtrCrypt(128, derived_keys, size_input_data, input_data, output_data)) {
    printf("Can't encrypt input\n");
    return false;
  }
  *size_output_data = size_input_data;
  if (!encrypt_flag)
    encrypted_data = input_data;
  else
    encrypted_data = output_data;
  HMAC_CTX hctx;
  HMAC_CTX_init(&hctx);
  if (hash_alg_id == TPM_ALG_SHA1) {
    HMAC_Init_ex(&hctx, &derived_keys[16], 16, EVP_sha1(), nullptr);
    *size_hmac = 20;
  } else {
    HMAC_Init_ex(&hctx, &derived_keys[16], 16, EVP_sha256(), nullptr);
    *size_hmac = 32;
  }
  HMAC_Update(&hctx, encrypted_data, size_input_data);
  if (encrypt_flag) {
    HMAC_Final(&hctx, encrypted_data_hmac, (uint32_t*)size_hmac);
    HMAC_CTX_cleanup(&hctx);
  } else {
    HMAC_Final(&hctx, decrypt_mac, (uint32_t*)size_hmac);
    HMAC_CTX_cleanup(&hctx);
    if (memcmp(decrypt_mac, encrypted_data_hmac, *size_hmac) != 0)
      return false;
  }

  return true;
}

/*
 *  The following code is for an encrypted session. Later we should fix the
 *  original functions so they allow bound sessions initiated with encrypted salts.
 *
 *  This code works for HMAC sessions only with password authorization.
 */

// Name =  nameAlg || Hash(nvPublicArea)
// nvPublicArea
//   TPMI_RH_NV_INDEX nvIndex;
//   TPMI_ALG_HASH    nameAlg;
//   TPMA_NV          attributes;
//   TPM2B_DIGEST     authPolicy;
//   uint16_t         dataSize;
bool CalculateNvName(ProtectedSessionAuthInfo& in, TPM_HANDLE nv_handle,
         uint16_t nv_hash_alg, uint32_t nv_attributes,
         uint16_t data_size, bool wasWritten, byte* out) {
  SHA_CTX sha1;
  SHA256_CTX sha256;
  byte toHash[256];
  uint16_t zero = 0;

  if (in.hash_alg_!= TPM_ALG_SHA1 && in.hash_alg_ != TPM_ALG_SHA256) {
    printf("CalculateNvName: unsupported hash algorithm\n");
    return false;
  }

  ChangeEndian16(&nv_hash_alg, (uint16_t*)out);

  int current_out_size = 0;
  int room_left = 256;
  byte* current = toHash;

  uint32_t new_attributes = nv_attributes;
  if (wasWritten)
    new_attributes |= NV_WRITTEN;

  ChangeEndian32((uint32_t*)&nv_handle, (uint32_t*)current);
  Update(sizeof(uint32_t), &current, &current_out_size, &room_left);
  ChangeEndian16(&nv_hash_alg, (uint16_t*)current);
  Update(sizeof(uint16_t), &current, &current_out_size, &room_left);
  ChangeEndian32(&new_attributes, (uint32_t*)current);
  Update(sizeof(uint32_t), &current, &current_out_size, &room_left);
  ChangeEndian16(&zero, (uint16_t*)current);
  Update(sizeof(uint16_t), &current, &current_out_size, &room_left);
  ChangeEndian16(&data_size, (uint16_t*)current);
  Update(sizeof(uint16_t), &current, &current_out_size, &room_left);

printf("\nCalculateNvName hash buf: ");
PrintBytes(current_out_size, toHash); printf("\n");

  int size_out = 0;
  if (in.hash_alg_ == TPM_ALG_SHA1) {

    SHA1_Init(&sha1);
    SHA1_Update(&sha1, toHash, current_out_size);
    SHA1_Final(out + 2, &sha1);
    size_out = 22;
  } else {
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, toHash, current_out_size);
    SHA256_Final(out + 2, &sha256);
    size_out = 34;
  }

printf("CalculateNvName name: ");
PrintBytes(size_out, out); printf("\n");
  return true;
}

bool CalculateBindName(LocalTpm& tpm, TPM_HANDLE bind_obj,
          ProtectedSessionAuthInfo& authInfo) {
  uint16_t pub_blob_size = 4096;
  byte pub_blob[4096];
  TPM2B_PUBLIC outPublic;
  TPM2B_NAME pub_name;
  TPM2B_NAME qualified_pub_name;

  if (Tpm2_ReadPublic(tpm, bind_obj, &pub_blob_size, pub_blob, &outPublic, &pub_name,
                      &qualified_pub_name)) {
    printf("ReadPublic succeeded\n");
  } else {
    printf("ReadPublic failed\n");
    return false;
  }
  printf("Public blob: ");
  PrintBytes(pub_blob_size, pub_blob);
  printf("\n");
  printf("Name: ");
  PrintBytes(pub_name.size, pub_name.name);
  printf("\n");
  printf("Qualified name: ");
  PrintBytes(qualified_pub_name.size, qualified_pub_name.name);
  printf("\n");
  authInfo.nameProtected_.size = pub_name.size;
  memcpy(authInfo.nameProtected_.name, pub_name.name, pub_name.size);
  return true;
}


// HMac(sessionkey||auth, cpHash, nonceNewer, nonceOlder, sessionAttrs)
// cpHash ≔ Hash(commandCode {|| Name1 {|| Name2 {|| Name3 }}} {|| parameters })
bool CalculateSessionHmac(ProtectedSessionAuthInfo& in, bool dir, uint32_t cmd,
                int numNames, TPM2B_NAME* names,
                int size_parms, byte* parms, int* size_hmac, byte* hmac) {
  SHA_CTX sha1;
  SHA256_CTX sha256;
  byte toHash[256];
  byte cpHash[32];

#if 1
  printf("\nCalculateSessionHmac\n");
#endif

  if (in.hash_alg_!= TPM_ALG_SHA1 && in.hash_alg_ != TPM_ALG_SHA256) {
    printf("CalculateSessionHmac: unsupported hash algorithm\n");
    return false;
  }

  // Need to include auth too?
  byte hmac_key[256];
  int sizeHmacKey = 0;

  memcpy(hmac_key, in.sessionKey_, in.sessionKeySize_);
  sizeHmacKey += in.sessionKeySize_;

  memcpy(&hmac_key[in.sessionKeySize_], in.targetAuthValue_.buffer,
       in.targetAuthValue_.size);
  sizeHmacKey += in.targetAuthValue_.size;

#if 1
  printf("hmac_key: ");
  PrintBytes(sizeHmacKey, hmac_key); printf("\n");
#endif

  int current_out_size = 0;
  int room_left = 256;

  // If dir is true, this is a response buffer and we add 4 bytes of 0
  // for some reason.
  if (dir) {
    uint32_t zero = 0;
    memcpy(&toHash[current_out_size], (byte*)&zero, sizeof(uint32_t));
    current_out_size += sizeof(uint32_t);
  }
  ChangeEndian32((uint32_t*)&cmd, (uint32_t*)&toHash[current_out_size]);
  current_out_size += sizeof(uint32_t);
  room_left -= sizeof(uint32_t);
  for (int i = 0; i < numNames; i++) {
    memcpy(&toHash[current_out_size], names[i].name, names[i].size);
    current_out_size += names[i].size;
    room_left -= names[i].size;
  }
  memcpy(&toHash[current_out_size], parms, size_parms);
  current_out_size += size_parms;
  room_left -= size_parms;

#if 1
  printf("toHash for cpHash: ");
  PrintBytes(current_out_size, toHash); printf("\n");
#endif

  // Note: current_out_size is repurposed.
  if (in.hash_alg_ == TPM_ALG_SHA1) {
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, toHash, current_out_size);
    SHA1_Final(cpHash, &sha1);
    current_out_size = 20;
  } else {
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, toHash, current_out_size);
    SHA256_Final(cpHash, &sha256);
    current_out_size = 32;
  }

#if 1
  printf("cpHash: ");
  PrintBytes(current_out_size, cpHash); printf("\n");
#endif

  memcpy(toHash, cpHash, current_out_size);
  room_left -= current_out_size;
  byte* current = &toHash[current_out_size];

  // nonceNewer, nonceOlder, sessionAttrs
  memcpy(current, in.newNonce_.buffer, in.newNonce_.size);
  Update(in.newNonce_.size, &current, &current_out_size, &room_left);
  memcpy(current, in.oldNonce_.buffer, in.oldNonce_.size);
  Update(in.oldNonce_.size, &current, &current_out_size, &room_left);
  memcpy(current, &in.tpmSessionAttributes_, 1);
  Update(1, &current, &current_out_size, &room_left);

#if 1
  printf("Hmac in: ");
  PrintBytes(current_out_size, toHash); printf("\n");
#endif

  HMAC_CTX hctx;
  HMAC_CTX_init(&hctx);
  if (in.hash_alg_ == TPM_ALG_SHA1) {
    HMAC_Init_ex(&hctx, hmac_key, sizeHmacKey, EVP_sha1(), nullptr);
    *size_hmac = 20;
  } else {
    HMAC_Init_ex(&hctx, hmac_key, sizeHmacKey, EVP_sha256(), nullptr);
    *size_hmac = 32;
  }
  HMAC_Update(&hctx, (const byte*)toHash, (size_t)current_out_size);
  HMAC_Final(&hctx, hmac, (unsigned*)size_hmac);
  HMAC_CTX_cleanup(&hctx);

#if 1
  printf("Hmac out: ");
  PrintBytes(*size_hmac, hmac); printf("\n\n");
#endif

  return true;
}

// sessionKey = KDFa(sessionAlg, bind.authValue||salt, ATH,
//                   in.newNonce_.buffer, in.oldNonce_.buffer, bits)
bool CalculateSessionKey(ProtectedSessionAuthInfo& in, TPM2B_DIGEST& rawSalt) {
  int sizeKey= SizeHash(in.hash_alg_);
  in.sessionKeySize_ = sizeKey;

#if 1
  printf("\nCalculateSessionKey\n");
  printf("Auth value: ");
  PrintBytes(in.targetAuthValue_.size, in.targetAuthValue_.buffer); printf("\n");
#endif

  string label= "ATH";
  string key;
  string contextU;
  string contextV;

  key.append((const char*)rawSalt.buffer, rawSalt.size);
  // For bound sessions we'd have to append the bound key auth.
  contextV.clear();
  contextU.clear();
  contextU.assign((const char*)in.newNonce_.buffer, in.newNonce_.size);
  contextV.assign((const char*)in.oldNonce_.buffer, in.oldNonce_.size);

#if 1
  printf("CalculateSessionKey KDFa:\n");
  printf("    key    : ");
  PrintBytes(key.size(), (byte*)key.data()); printf("\n");
  printf("    label  : ");
  PrintBytes(label.size(), (byte*)label.data()); printf("\n");
  printf("    U      : ");
  PrintBytes(contextU.size(), (byte*)contextU.data()); printf("\n");
  printf("    V      : ");
  PrintBytes(contextV.size(), (byte*)contextV.data()); printf("\n");
#endif

  if (!KDFa(in.hash_alg_, key, label, contextU, contextV,
            sizeKey*NBITSINBYTE, sizeKey, in.sessionKey_)) {
    printf("Can't KDFa symKey\n");
    return false;
  }

#if 1
  printf("CalculateSessionKey, key: ");
  PrintBytes(sizeKey, in.sessionKey_); printf("\n");
#endif
  return true;
}

void RollNonces(ProtectedSessionAuthInfo& in, TPM2B_NONCE& newNonce) {
  memcpy(in.oldNonce_.buffer, in.newNonce_.buffer, in.newNonce_.size);
  in.oldNonce_.size = in.newNonce_.size;
  memcpy(in.newNonce_.buffer, newNonce.buffer, newNonce.size);
  in.newNonce_.size = newNonce.size;
}

int CalculateandSetProtectedAuthSize(ProtectedSessionAuthInfo& authInfo,
        uint32_t cmd, int size_cmd_params, byte* cmd_params,
        byte* out, int space_left) {
  //    TPMI_SH_AUTH_SESSION authHandle the handle for the authorization session
  //    TPM2B_NONCE nonceCaller the caller-provided session nonce; size may be zero
  //    TPMA_SESSION sessionAttributes the flags associated with the session
  //    TPM2B_AUTH hmac the session HMAC digest value
  return sizeof(uint32_t) +sizeof(TPMI_SH_AUTH_SESSION) + 
         sizeof(uint16_t) + authInfo.newNonce_.size + sizeof(byte) +
         sizeof(uint16_t) + SizeHash(authInfo.hash_alg_);
}

int CalculateandSetProtectedAuth(ProtectedSessionAuthInfo& authInfo,
        uint32_t cmd, int numNames, TPM2B_NAME* names,
        int size_cmd_params, byte* cmd_params, byte* out, int space_left) {

  TPM2B_NONCE newNonce;
  newNonce.size = authInfo.oldNonce_.size;
  RAND_bytes(newNonce.buffer, newNonce.size);

#if 1
  printf("CalculateandSetProtectedAuth nonce: ");
  PrintBytes(newNonce.size, newNonce.buffer); printf("\n");
#endif

  RollNonces(authInfo, newNonce);

#if 1
  printf("\nAfter RollNounces in CalculateandSetProtectedAuth\n");
  printf("newNonce: ");
  PrintBytes(authInfo.newNonce_.size, authInfo.newNonce_.buffer); printf("\n");
  printf("oldNonce: ");
  PrintBytes(authInfo.oldNonce_.size, authInfo.oldNonce_.buffer); printf("\n");
#endif

  int sizeHmac = SizeHash(authInfo.hash_alg_);
  byte hmac[128];
  if (!CalculateSessionHmac(authInfo, false, cmd, numNames, names,
          size_cmd_params, cmd_params, &sizeHmac, hmac)) {
    printf("CalculateSessionHmac failed\n");
    return false;
  }

  // Set session auth.
  //    TPMI_SH_AUTH_SESSION authHandle the handle for the authorization session
  //    TPM2B_NONCE nonceCaller the caller-provided session nonce; size may be zero
  //    TPMA_SESSION sessionAttributes the flags associated with the session
  //    TPM2B_AUTH hmac the session HMAC digest value
  int space_used = 0;
  uint32_t sizeAuth = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(byte) +
                      sizeof(uint16_t) + sizeHmac + authInfo.oldNonce_.size;

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian32((uint32_t*)&sizeAuth, (uint32_t*)out);
  Update(sizeof(uint32_t), &out, &space_used, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&authInfo.sessionHandle_, (uint32_t*)out);
  Update(sizeof(uint32_t), &out, &space_used, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&authInfo.newNonce_.size, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &space_used, &space_left);
  IF_LESS_THAN_RETURN_MINUS1(space_left, authInfo.newNonce_.size)
  memcpy(out, authInfo.newNonce_.buffer, authInfo.newNonce_.size);
  Update(authInfo.newNonce_.size, &out, &space_used, &space_left);
  IF_LESS_THAN_RETURN_MINUS1(space_left, 1)
  *out = authInfo.tpmSessionAttributes_;
  Update(1, &out, &space_used, &space_left);

  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&sizeHmac, (uint16_t*)out);
  Update(sizeof(uint16_t), &out, &space_used, &space_left);
  IF_LESS_THAN_RETURN_MINUS1(space_left, sizeHmac)
  memcpy(out, hmac, sizeHmac);
  Update(sizeHmac, &out, &space_used, &space_left);

  return space_used;
}

bool GetandVerifyProtectedAuth(ProtectedSessionAuthInfo& authInfo, uint32_t cmd,
                         int numNames, TPM2B_NAME* names,
                         int size_in, byte* in,
                         int size_params, byte* params) {

#if 1
printf("GetandVerifyProtectedAuth: ");
PrintBytes(size_in, in); printf("\n");
printf("size_params %d: ", size_params);
PrintBytes(size_params, params); printf("\n");
#endif

  // New nonce
  TPM2B_NONCE newNonce;
  byte* current = nullptr;
  if (params != nullptr) 
    current = params + size_params;
  else
    current = in + size_params;
  ChangeEndian16((uint16_t*)current, &newNonce.size);
  current += sizeof(uint16_t);
  memcpy(newNonce.buffer, current, newNonce.size);
  current += newNonce.size;
  byte prop = *current;
  current += 1;

  TPM2B_DIGEST submitted_hmac;
  ChangeEndian16((uint16_t*) current, &submitted_hmac.size);
  current += sizeof(uint16_t);
  memcpy(submitted_hmac.buffer, current, submitted_hmac.size);
  current += submitted_hmac.size;

#if 1
  printf("NewNonce: ");
  PrintBytes(newNonce.size, newNonce.buffer); printf("\n");
  printf("submitted: ");
  PrintBytes(submitted_hmac.size, submitted_hmac.buffer); printf("\n");
#endif

  RollNonces(authInfo, newNonce);

#if 1
  printf("\nAfter RollNounces in GetandVerifyProtectedAuth\n");
  printf("newNonce: ");
  PrintBytes(authInfo.newNonce_.size, authInfo.newNonce_.buffer); printf("\n");
  printf("oldNonce: ");
  PrintBytes(authInfo.oldNonce_.size, authInfo.oldNonce_.buffer); printf("\n");
#endif

  // Make sure the Hmac is right.
  int sizeHmac = 256;
  byte hmac[256];
  if (!CalculateSessionHmac(authInfo, true, cmd, numNames, names,
                size_params, params, &sizeHmac, hmac)) {
    printf("Can't calculate response hmac\n");
    return false;
  }
  if (submitted_hmac.size != sizeHmac ||
      memcmp(submitted_hmac.buffer, hmac, sizeHmac) != 0) {
    printf("Response hmac failure\n");
    return false;
  }
  return true;
}

bool Tpm2_StartProtectedAuthSession(LocalTpm& tpm, TPM_RH tpm_obj, TPM_RH bind_obj,
                           ProtectedSessionAuthInfo& authInfo,
                           TPM2B_ENCRYPTED_SECRET& salt,
                           TPM_SE session_type, TPMT_SYM_DEF& symmetric,
                           TPMI_ALG_HASH hash_alg, TPM_HANDLE* session_handle) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int resp_size = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params[MAX_SIZE_PARAMS];
  byte* in = params;
  int space_left = MAX_SIZE_PARAMS;

  memset(params, 0, MAX_SIZE_PARAMS);

  // Set name of bind object in the nameProtected_ variable of the
  // ProtectedSessionAuthInfo.
  authInfo.protectedHandle_ = bind_obj;

  int n = Marshal_AuthSession_Info(tpm_obj, bind_obj, authInfo.oldNonce_,
                                  salt, session_type, symmetric, hash_alg,
                                  MAX_SIZE_PARAMS, params);
  IF_NEG_RETURN_FALSE(n);
  Update(n, &in, &size_params, &space_left);
  int in_size = Tpm2_SetCommand(TPM_ST_NO_SESSIONS, TPM_CC_StartAuthSession,
                                commandBuf, size_params, params);
  printCommand("StartAuthSession", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&resp_size, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(resp_size, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("StartAuthSession", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  byte* current_out = resp_buf + sizeof(TPM_RESPONSE);
  ChangeEndian32((uint32_t*)current_out, (uint32_t*)session_handle);
  current_out += sizeof(uint32_t);
  ChangeEndian16((uint16_t*)current_out, &authInfo.newNonce_.size);
  current_out += sizeof(uint16_t);
  memcpy(authInfo.newNonce_.buffer, current_out, authInfo.newNonce_.size);
  current_out += authInfo.newNonce_.size;
  return true;
}

bool Tpm2_DefineProtectedSpace(LocalTpm& tpm, TPM_HANDLE owner,
        TPMI_RH_NV_INDEX index, ProtectedSessionAuthInfo& authInfo,
        uint32_t attributes, uint16_t size_data) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&owner, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  // Set auth
  int n = CalculateandSetProtectedAuthSize(authInfo, TPM_CC_NV_DefineSpace,
                 0, nullptr, in, space_left);
  if (n < 0) {
    printf("CalculateandSetProtectedAuthSize failed\n");
    return false;
  }

  byte* auth_set = in;
  space_left -= n;
  size_params += n;
  in += n;

  byte* cmd_params_place = in;
  uint16_t authPolicySize = 0;
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&authPolicySize, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  // TPM2B_NV_PUBLIC
  uint16_t size_nv_area = sizeof(uint32_t) + sizeof(TPMI_RH_NV_INDEX) +
                          sizeof(TPMI_ALG_HASH) + 2*sizeof(uint16_t) +
                          authPolicySize;
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&size_nv_area, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  // nvIndex;
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&authInfo.hash_alg_, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&attributes, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  // authPolicy size
  ChangeEndian16((uint16_t*)&authPolicySize, (uint16_t*)in);
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  // dataSize
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint16_t))
  ChangeEndian16((uint16_t*)&size_data, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  // handle name of owner is itself.
  TPM2B_NAME owner_name;
  owner_name.size = sizeof(uint32_t);
  ChangeEndian32((uint32_t*)&owner, (uint32_t*)owner_name.name);

  int size_append = in - cmd_params_place;

  // Set auth
  n = CalculateandSetProtectedAuth(authInfo, TPM_CC_NV_DefineSpace,
            1, &owner_name, size_append, cmd_params_place,
            auth_set, space_left);
  if (n < 0) {
    printf("CalculateandSetProtectedAuth failed\n");
    return false;
  }

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_NV_DefineSpace,
                                commandBuf, size_params, params_buf);
  printCommand("DefineSpace", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                        &responseSize, &responseCode);
  printResponse("Definespace", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;

  int size_resp_params = 0;
  byte* current_in = resp_buf + sizeof(TPM_RESPONSE);
  ChangeEndian32((uint32_t*)current_in, (uint32_t*)&size_resp_params);
  byte* resp_params = current_in + sizeof(uint32_t);

  TPM2B_NAME no_name;
  no_name.size = sizeof(uint32_t);
  memset(no_name.name, 0, no_name.size);
  if (!GetandVerifyProtectedAuth(authInfo, TPM_CC_NV_DefineSpace, 0,
           &no_name, responseSize - sizeof(TPM_RESPONSE),
           resp_buf + sizeof(TPM_RESPONSE),
           size_resp_params, resp_params)) {
    printf("GetandVerifyProtectedAuth failed\n");
    return false;
  }
  return true;
}

bool Tpm2_IncrementProtectedNv(LocalTpm& tpm, TPMI_RH_NV_INDEX index,
        ProtectedSessionAuthInfo& authInfo) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(resp_buf, 0, MAX_SIZE_PARAMS);

  // handle
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);

  TPM2B_NAME nv_name[2];
  if (!CalculateNvName(authInfo, index,
         authInfo.hash_alg_, authInfo.protectedAttributes_,
         authInfo.protectedSize_, true, nv_name[0].name)) {
  }

  // Fix this
  nv_name[0].size = SizeHash(authInfo.hash_alg_) + sizeof(uint16_t);
  if (!CalculateNvName(authInfo, index,
         authInfo.hash_alg_, authInfo.protectedAttributes_,
         authInfo.protectedSize_, true, nv_name[1].name)) {
  }

  // Fix this
  nv_name[1].size = SizeHash(authInfo.hash_alg_) + sizeof(uint16_t);
  int n = CalculateandSetProtectedAuthSize(authInfo, TPM_CC_NV_Increment,
              0, nullptr, in, space_left);
  if (n < 0) {
    printf("CalculateandSetProtectedAuth failed\n");
    return false;
  }
  byte* auth_set = in;
  space_left -= n;
  size_params += n;
  in += n;

  // Set auth
  n = CalculateandSetProtectedAuth(authInfo, TPM_CC_NV_Increment,
            2, nv_name, 0, nullptr, auth_set, space_left);
  if (n < 0) {
    printf("CalculateandSetProtectedAuth failed\n");
    return false;
  }

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_NV_Increment,
                                commandBuf, size_params, params_buf);
  printCommand("IncrementProtectedNv", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap, &responseSize, &responseCode);
  printResponse("IncrementProtectedNv", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;
  printf("TPM_CC_NV_Increment response size: %d\n", responseSize);

  int size_resp_params = 0;
  byte* resp_params = resp_buf + sizeof(TPM_RESPONSE) + sizeof(uint32_t);

  if (!GetandVerifyProtectedAuth(authInfo, TPM_CC_NV_Increment, 0,
           nv_name, responseSize - sizeof(TPM_RESPONSE),
           resp_buf + sizeof(TPM_RESPONSE),
          size_resp_params, resp_params)) {
    printf("GetandVerifyProtectedAuth failed\n");
    return false;
  }
  return true;
}

bool Tpm2_ReadProtectedNv(LocalTpm& tpm, TPMI_RH_NV_INDEX index,
                 ProtectedSessionAuthInfo& authInfo,
                 uint16_t* size, byte* data) {
  byte commandBuf[2*MAX_SIZE_PARAMS];
  int size_resp = MAX_SIZE_PARAMS;
  byte resp_buf[MAX_SIZE_PARAMS];
  memset(resp_buf, 0, MAX_SIZE_PARAMS);
  int size_params = 0;
  byte params_buf[MAX_SIZE_PARAMS];
  int space_left = MAX_SIZE_PARAMS;
  byte* in = params_buf;

  memset(commandBuf, 0, MAX_SIZE_PARAMS);
  memset(params_buf, 0, MAX_SIZE_PARAMS);

  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);
  IF_LESS_THAN_RETURN_FALSE(space_left, sizeof(uint32_t))
  ChangeEndian32((uint32_t*)&index, (uint32_t*)in);
  Update(sizeof(uint32_t), &in, &size_params, &space_left);
  byte* auth_set = in;

  // Set Hmac auth
  TPM2B_NAME nv_name[2];
  if (!CalculateNvName(authInfo, index,
         authInfo.hash_alg_, authInfo.protectedAttributes_,
         authInfo.protectedSize_, true, nv_name[0].name)) {
  }
  // Fix this
  nv_name[0].size = SizeHash(authInfo.hash_alg_) + sizeof(uint16_t);
  if (!CalculateNvName(authInfo, index,
         authInfo.hash_alg_, authInfo.protectedAttributes_,
         authInfo.protectedSize_, true, nv_name[1].name)) {
  }
  // Fix this
  nv_name[1].size = SizeHash(authInfo.hash_alg_) + sizeof(uint16_t);

  int n = CalculateandSetProtectedAuthSize(authInfo, TPM_CC_NV_Increment,
              0, nullptr, in, space_left);
  if (n < 0) {
    printf("CalculateandSetProtectedAuth failed\n");
    return false;
  }
  space_left -= n;
  size_params += n;
  in += n;
  byte* cmd_params_place = in;

  // parameters
  uint16_t offset = 0;
  IF_NEG_RETURN_FALSE(n);
  ChangeEndian16((uint16_t*)size, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);
  IF_NEG_RETURN_FALSE(n);
  ChangeEndian16((uint16_t*)&offset, (uint16_t*)in);
  Update(sizeof(uint16_t), &in, &size_params, &space_left);

  // Set auth
  n = CalculateandSetProtectedAuth(authInfo, TPM_CC_NV_Read,
          2, nv_name, in - cmd_params_place, cmd_params_place,
          auth_set, space_left);
  if (n < 0) {
    printf("CalculateSessionHmac failed\n");
    return false;
  }

  int in_size = Tpm2_SetCommand(TPM_ST_SESSIONS, TPM_CC_NV_Read,
                                commandBuf, size_params, params_buf);
  printCommand("ReadProtectedNv", in_size, commandBuf);
  if (!tpm.SendCommand(in_size, commandBuf)) {
    printf("SendCommand failed\n");
    return false;
  }
  if (!tpm.GetResponse(&size_resp, resp_buf)) {
    printf("GetResponse failed\n");
    return false;
  }
  uint16_t cap = 0;
  uint32_t responseSize;
  uint32_t responseCode;
  Tpm2_InterpretResponse(size_resp, resp_buf, &cap,
                         &responseSize, &responseCode);
  printResponse("ReadNv", cap, responseSize, responseCode, resp_buf);
  if (responseCode != TPM_RC_SUCCESS)
    return false;

  int size_resp_params = 0;
  byte* current_in = resp_buf + sizeof(TPM_RESPONSE);
  ChangeEndian32((uint32_t*)current_in, (uint32_t*)&size_resp_params);
  byte* resp_params = current_in + sizeof(uint32_t);

  if (!GetandVerifyProtectedAuth(authInfo, TPM_CC_NV_Read, 0,
           nv_name, responseSize - sizeof(TPM_RESPONSE),
           resp_buf + sizeof(TPM_RESPONSE),
          size_resp_params, resp_params)) {
    printf("GetandVerifyProtectedAuth failed\n");
    return false;
  }

  ChangeEndian16((uint16_t*)resp_params, (uint16_t*)size);
  resp_params += sizeof(uint16_t);
  memcpy(data, resp_params, *size);
  return true;
}

