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
// File: tpm2_lib.h

#ifndef _TPM2_LIB_H__
#define _TPM2_LIB_H__

#include <tpm20.h>
#include <tpm2_types.h>

#include <string>
using std::string;

#define NBITSINBYTE 8

// General Utility functions
bool Equal(int size_in1, byte* in1, int size_in2, byte* in2);
void ReverseCpy(int size, byte* in, byte* out);
void PrintBytes(int n, byte* in);
void ChangeEndian16(const uint16_t* in, uint16_t* out);
void ChangeEndian32(const uint32_t* in, uint32_t* out);
void ChangeEndian64(const uint64_t* in, uint64_t* out);
void InitSinglePcrSelection(int pcrNum, TPM_ALG_ID alg,
                            TPML_PCR_SELECTION* pcrSelect);
void setPcrBit(int pcrNum, byte* array);
bool testPcrBit(int pcrNum, byte* array);

bool ReadFileIntoBlock(const string& filename, int* size, byte* block);
bool WriteFileFromBlock(const string& filename, int size, byte* block);

void PrintCapabilities(int size, byte* buf);
bool GetReadPublicOut(uint16_t size_in, byte* input, TPM2B_PUBLIC* outPublic);
bool MakeCredential(int size_endorsement_blob, byte* endorsement_cert_blob,
                    TPM_ALG_ID hash_alg_id,
                    TPM2B_DIGEST& unmarshaled_credential,
                    TPM2B_DIGEST& marshaled_credential,
                    TPM2B_NAME& unmarshaled_name,
                    TPM2B_NAME& marshaled_name,
                    int* size_encIdentity, byte* encIdentity,
                    TPM2B_ENCRYPTED_SECRET* unmarshaled_encrypted_secret,
                    TPM2B_ENCRYPTED_SECRET* marshaled_encrypted_secret,
                    TPM2B_DIGEST* unmarshaled_integrityHmac,
                    TPM2B_DIGEST* marshaled_integrityHmac);
bool EncryptDataWithCredential(bool encrypt_flag, TPM_ALG_ID hash_alg_id,
                               TPM2B_DIGEST unmarshaled_credential,
                               TPM2B_DIGEST marshaled_credential,
                               int size_input_data, byte* input_data,
                               int* size_hmac, byte* encrypted_data_hmac,
                               int* size_output_data, byte* output_data);

// Local Tpm interaction
class LocalTpm {

private:
  int tpm_fd_;

public:
  LocalTpm();
  ~LocalTpm();

  bool OpenTpm(const char* device);
  void CloseTpm();
  bool SendCommand(int size, byte* command);
  bool GetResponse(int* size, byte* response);
};

// Helpers
int Tpm2_SetCommand(TPM_ST tag, uint32_t cmd, byte* buf,
                    int size_param, byte* params);
void Tpm2_IntepretResponse(int out_size, byte* out_buf,
                           int16_t* cap, uint32_t* responseSize,
                           uint32_t* responseCode);
int Tpm2_Set_OwnerAuthHandle(int size, byte* buf);
int Tpm2_Set_OwnerAuthData(int size, byte* buf);

TPM_HANDLE GetNvHandle(uint32_t slot);


bool FillTpmPcrData(LocalTpm& tpm, TPMS_PCR_SELECTION pcrSelection,
                    int* size, byte* buf);
bool ComputePcrDigest(TPM_ALG_ID hash, int size_in, byte* in_buf,
                      int* size_out, byte* out);

// TPM Commands
bool Tpm2_Startup(LocalTpm& tpm);
bool Tpm2_Shutdown(LocalTpm& tpm);
bool Tpm2_GetCapability(LocalTpm& tpm, uint32_t cap, uint32_t start,
                        int* size, byte* buf);
bool Tpm2_GetRandom(LocalTpm& tpm, int numBytes, byte* buf);

bool Tpm2_ReadClock(LocalTpm& tpm, uint64_t* current_time,
                    uint64_t* current_clock);
bool Tpm2_ReadPcrs(LocalTpm& tpm, TPML_PCR_SELECTION pcrSelect,
                   uint32_t* updateCounter,
                   TPML_PCR_SELECTION* pcrSelectOut, TPML_DIGEST* values);
bool Tpm2_ReadPcr(LocalTpm& tpm, int pcrNum, uint32_t* updateCounter,
                  TPML_PCR_SELECTION* pcrSelectOut, TPML_DIGEST* digest);
bool Tpm2_CreatePrimary(LocalTpm& tpm, TPM_HANDLE owner, string& authString,
                        TPML_PCR_SELECTION& pcr_selection,
                        TPM_ALG_ID enc_alg, TPM_ALG_ID int_alg,
                        TPMA_OBJECT& flags, TPM_ALG_ID sym_alg,
                        TPMI_AES_KEY_BITS sym_key_size,
                        TPMI_ALG_SYM_MODE sym_mode, TPM_ALG_ID sig_scheme,
                        int mod_size, uint32_t exp,
                        TPM_HANDLE* handle, TPM2B_PUBLIC* pub_out);
bool Tpm2_Load(LocalTpm& tpm, TPM_HANDLE parent_handle, string& parentAuth,
               int size_public, byte* inPublic,
               int size_private, byte* inPrivate,
               TPM_HANDLE* new_handle, TPM2B_NAME* name);
bool Tpm2_Save(LocalTpm& tpm);
bool Tpm2_PolicyPassword(LocalTpm& tpm, TPM_HANDLE handle);
bool Tpm2_PCR_Event(LocalTpm& tpm, int pcr_num,
                    uint16_t size, byte* eventData);
bool Tpm2_PolicyGetDigest(LocalTpm& tpm, TPM_HANDLE handle,
                          TPM2B_DIGEST* digest_out);
bool Tpm2_StartAuthSession(LocalTpm& tpm, TPM_RH tpm_obj, TPM_RH bind_obj,
                           TPM2B_NONCE& initial_nonce,
                           TPM2B_ENCRYPTED_SECRET& salt,
                           TPM_SE session_type, TPMT_SYM_DEF& symmetric,
                           TPMI_ALG_HASH hash_alg, TPM_HANDLE* session_handle,
                           TPM2B_NONCE* nonce_obj);
bool Tpm2_PolicyPcr(LocalTpm& tpm, TPM_HANDLE session_handle,
                    TPM2B_DIGEST& expected_digest, TPML_PCR_SELECTION& pcr);
bool Tpm2_PolicySecret(LocalTpm& tpm, TPM_HANDLE handle,
                       TPM2B_DIGEST* policy_digest,
                       TPM2B_TIMEOUT* timeout,
                       TPMT_TK_AUTH* ticket);

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
                       TPMT_TK_CREATION* creation_ticket);
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
                    TPM2B_DIGEST* digest_out, TPMT_TK_CREATION* creation_ticket);

bool Tpm2_Unseal(LocalTpm& tpm, TPM_HANDLE item_handle, string& parentAuth,
                 TPM_HANDLE session_handle, TPM2B_NONCE& nonce,
                 byte session_attributes, TPM2B_DIGEST& hmac_digest,
                 int* out_size, byte* sealed);
bool Tpm2_Quote(LocalTpm& tpm, TPM_HANDLE signingHandle, string& parentAuth,
                int quote_size, byte* toQuote,
                TPMT_SIG_SCHEME scheme, TPML_PCR_SELECTION& pcr_selection,
                TPM_ALG_ID sig_alg, TPM_ALG_ID hash_alg, 
                int* attest_size, byte* attest, int* sig_size, byte* sig);
bool Tpm2_LoadContext(LocalTpm& tpm, uint16_t size, byte* saveArea,
                      TPM_HANDLE* handle);
bool Tpm2_SaveContext(LocalTpm& tpm, TPM_HANDLE handle, uint16_t* size,
                      byte* saveArea);
bool Tpm2_FlushContext(LocalTpm& tpm, TPM_HANDLE handle);

bool Tpm2_IncrementNv(LocalTpm& tpm, TPMI_RH_NV_INDEX index, string& authString);
bool Tpm2_ReadNv(LocalTpm& tpm, TPMI_RH_NV_INDEX index, 
                 string& authString, uint16_t* size, byte* data);
bool Tpm2_WriteNv(LocalTpm& tpm, TPMI_RH_NV_INDEX index, string& authString,
                  uint16_t size, byte* data);
bool Tpm2_DefineSpace(LocalTpm& tpm, TPM_HANDLE owner, TPMI_RH_NV_INDEX index,
                      string& authString, uint16_t authPolicySize,
                      byte* authPolicy, uint32_t attributes, uint16_t size_data);
bool Tpm2_UndefineSpace(LocalTpm& tpm, TPM_HANDLE owner, TPMI_RH_NV_INDEX index);
bool Tpm2_Flushall(LocalTpm& tpm, uint32_t start);

bool Tpm2_MakeCredential(LocalTpm& tpm,
                         TPM_HANDLE keyHandle,
                         TPM2B_DIGEST& credential,
                         TPM2B_NAME& objectName,
                         TPM2B_ID_OBJECT* credentialBlob,
                         TPM2B_ENCRYPTED_SECRET* secret);
bool Tpm2_ActivateCredential(LocalTpm& tpm,
                             TPM_HANDLE activeHandle,
                             TPM_HANDLE keyHandle,
                             string& activeAuth, string& keyAuth,
                             TPM2B_ID_OBJECT& credentialBlob,
                             TPM2B_ENCRYPTED_SECRET& secret,
                             TPM2B_DIGEST* certInfo);
bool Tpm2_Certify(LocalTpm& tpm, TPM_HANDLE signedKey, TPM_HANDLE signingKey,
                  string& auth_signed_key, string& auth_signing_key,
                  TPM2B_DATA& qualifyingData,
                  TPM2B_ATTEST* attest, TPMT_SIGNATURE* sig);
bool Tpm2_ReadPublic(LocalTpm& tpm, TPM_HANDLE handle, 
                     uint16_t* pub_blob_size, byte* pub_blob,
                     TPM2B_PUBLIC* outPublic,
                     TPM2B_NAME* name, TPM2B_NAME* qualifiedName);

bool Tpm2_Rsa_Encrypt(LocalTpm& tpm, TPM_HANDLE handle, string& authString,
                      TPM2B_PUBLIC_KEY_RSA& in, TPMT_RSA_DECRYPT& scheme,
                      TPM2B_DATA& label, TPM2B_PUBLIC_KEY_RSA* out);
bool Tpm2_EvictControl(LocalTpm& tpm, TPMI_RH_PROVISION owner, TPM_HANDLE handle,
                       string& authString,
                       TPMI_DH_PERSISTENT persistantHandle);

bool Tpm2_DictionaryAttackLockReset(LocalTpm& tpm);

#define NV_PLATFORMCREATE 0x40000000
#define NV_AUTHWRITE      0x00000004
#define NV_COUNTER        0x00000010
#define NV_EXTEND         0x00000040
#define NV_POLICY_DELETE  0x00000400
#define NV_AUTHREAD       0x00040000
#define NV_WRITTEN        0x20000000

#define CONTINUESESSION 0x01

class ProtectedSessionAuthInfo {
public:
  TPMI_ALG_HASH hash_alg_;
  TPM2B_NONCE oldNonce_;
  TPM2B_NONCE newNonce_;
  TPM_HANDLE sessionHandle_;
  TPM_HANDLE protectedHandle_;
  uint32_t protectedAttributes_;
  uint16_t protectedSize_;
  TPM2B_NAME nameProtected_;
  TPM2B_DIGEST targetAuthValue_;
  byte tpmSessionAttributes_;
  int sessionKeySize_;
  byte sessionKey_[64];
};

bool CalculateNvName(ProtectedSessionAuthInfo& in, TPM_HANDLE nv_handle,
         uint16_t nv_hash_alg, uint32_t nv_attributes,
         uint16_t data_size, bool wasWritten, byte* out);
bool CalculateSessionKey(ProtectedSessionAuthInfo& in, TPM2B_DIGEST& rawSalt);
bool CalculateSessionHmac(ProtectedSessionAuthInfo& in, bool dir, uint32_t cmd,
		int size_parms, byte* parms, int* size_hmac, byte* hmac);
void RollNonces(ProtectedSessionAuthInfo& in, TPM2B_NONCE& newNonce);
bool Tpm2_StartProtectedAuthSession(LocalTpm& tpm, TPM_RH tpm_obj, TPM_RH bind_obj,
                           ProtectedSessionAuthInfo& authInfo,
                           TPM2B_ENCRYPTED_SECRET& salt,
                           TPM_SE session_type, TPMT_SYM_DEF& symmetric,
                           TPMI_ALG_HASH hash_alg, TPM_HANDLE* session_handle);
bool Tpm2_IncrementProtectedNv(LocalTpm& tpm, TPMI_RH_NV_INDEX index,
          ProtectedSessionAuthInfo& authInfo);
bool Tpm2_ReadProtectedNv(LocalTpm& tpm, TPMI_RH_NV_INDEX index,
                 ProtectedSessionAuthInfo& authInfo, uint16_t* size, byte* data);
bool Tpm2_DefineProtectedSpace(LocalTpm& tpm, TPM_HANDLE owner, TPMI_RH_NV_INDEX index,
                      ProtectedSessionAuthInfo& authInfo, uint32_t attributes,
                      uint16_t size_data);
#endif

