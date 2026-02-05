bool seal_test(local_tpm& tpm, int pcr_num) {
  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  TPM_HANDLE parent_handle;
  TPM2B_PUBLIC pub_out;
  TPML_PCR_SELECTION pcrSelect;
  init_single_pcr_selection(pcr_num, TPM_ALG_SHA256, &pcrSelect);

  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Creating a new SRK
  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, pcrSelect, 
                         TPM_ALG_RSA, TPM_ALG_SHA256, primary_flags,
                         TPM_ALG_AES, 256, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001,
                        &parent_handle, &pub_out)) {
    printf("CreatePrimary succeeded\n");
  } else {
    printf("CreatePrimary failed\n");
    return false;
  }
  TPM2B_DIGEST secret;
  secret.size = 32;
  if (!Tpm2_GetRandom(tpm, secret.size, secret.buffer)) {
    printf("Can't get random key\n");
    return false;
  }
  printf("Secret: ");
  print_bytes(secret.size, secret.buffer);
  printf("\n");

  TPM2B_CREATION_DATA creation_out;
  TPMT_TK_CREATION creation_ticket;
  int size_public = MAX_SIZE_PARAMS;
  byte_t out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte_t out_private[MAX_SIZE_PARAMS];

  TPM2B_DIGEST digest_out;
  TPM2B_NONCE initial_nonce;
  TPM2B_ENCRYPTED_SECRET salt;
  TPMT_SYM_DEF symmetric;
  TPM_HANDLE session_handle;
  TPM2B_NONCE nonce_obj;

  initial_nonce.size = 16;
  memset(initial_nonce.buffer, 0, initial_nonce.size);
  salt.size = 0;
  symmetric.algorithm = TPM_ALG_NULL;
 
  // In a real use, we need to create a session when
  // we make the key (like here) AND when we use it.

  // Start auth session
  if (Tpm2_StartAuthSession(tpm, TPM_RH_NULL, TPM_RH_NULL,
                            initial_nonce, salt, TPM_SE_POLICY,
                            symmetric, TPM_ALG_SHA256, &session_handle,
                            &nonce_obj)) {
    printf("Tpm2_StartAuthSession succeeds handle: %08x\n",
           session_handle);
    printf("nonce (%d): ", nonce_obj.size);
    print_bytes(nonce_obj.size, nonce_obj.buffer);
    printf("\n");
  } else {
    printf("Tpm2_StartAuthSession fails\n");
    return false;
  }

  TPM2B_DIGEST policy_digest;
  // get policy digest
  if(Tpm2_PolicyGetDigest(tpm, session_handle, &policy_digest)) {
    printf("PolicyGetDigest before Pcr succeeded: ");
    print_bytes(policy_digest.size, policy_digest.buffer); printf("\n");
  } else {
    Tpm2_FlushContext(tpm, session_handle);
    printf("PolicyGetDigest failed\n");
    return false;
  }

  if (Tpm2_PolicyPassword(tpm, session_handle)) {
    printf("PolicyPassword succeeded\n");
  } else {
    Tpm2_FlushContext(tpm, session_handle);
    printf("PolicyPassword failed\n");
    return false;
  }

  TPM2B_DIGEST expected_digest;
  expected_digest.size = 0;
  if (Tpm2_PolicyPcr(tpm, session_handle,
                     expected_digest, pcrSelect)) {
    printf("PolicyPcr succeeded\n");
  } else {
    printf("PolicyPcr failed\n");
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }

  if(Tpm2_PolicyGetDigest(tpm, session_handle, &policy_digest)) {
    printf("PolicyGetDigest succeeded: ");
    print_bytes(policy_digest.size, policy_digest.buffer); printf("\n");
  } else {
    printf("PolicyGetDigest failed\n");
    return false;
  }

  TPMA_OBJECT create_flags;
  *(uint32_t*)(&create_flags) = 0;
  create_flags.fixedTPM = 1;
  create_flags.fixedParent = 1;

  // Creating new sealed key
  if (Tpm2_CreateSealed(tpm, parent_handle, policy_digest.size,
                        policy_digest.buffer, parentAuth, secret.size,
                        secret.buffer, pcrSelect, TPM_ALG_SHA256, create_flags,
                        TPM_ALG_NULL, (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB,
                        TPM_ALG_RSASSA, 2048, 0x010001,
                        &size_public, out_public, &size_private, out_private,
                        &creation_out, &digest_out, &creation_ticket)) {
    printf("Create with digest succeeded private size: %d, public size: %d\n",
           size_private, size_public);
  } else {
    printf("Create with digest failed\n");
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }

  // Usually, we'd save the new SRK and sealing key
  // when creating and then reload them using a
  // recreated auth session like the one above.

  TPM_HANDLE load_handle;
  TPM2B_NAME name;
  if (Tpm2_Load(tpm, parent_handle, parentAuth, size_public, out_public,
               size_private, out_private, &load_handle, &name)) {
    printf("Load succeeded\n");
  } else {
    printf("Load failed\n");
    Tpm2_FlushContext(tpm, session_handle);
    return false;
  }

  int unsealed_size = MAX_SIZE_PARAMS;
  byte_t unsealed[MAX_SIZE_PARAMS];
  TPM2B_DIGEST hmac;
  hmac.size = 0;
  if (!Tpm2_Unseal(tpm, load_handle, parentAuth, session_handle,
                   nonce_obj, 0x01, hmac,
                   &unsealed_size, unsealed)) {
    printf("Unseal failed\n");
    Tpm2_FlushContext(tpm, session_handle);
    Tpm2_FlushContext(tpm, load_handle);
    return false;
  }
  printf("Unseal succeeded, unsealed (%d): ", unsealed_size); 
  print_bytes(unsealed_size, unsealed);
  printf("\n"); 

  TPM2B_SENSITIVE_DATA* unsealed_return = (TPM2B_SENSITIVE_DATA*)(&unsealed[2]);
  uint16_t ss;
  change_endian16(&unsealed_return->size, &ss);
  printf("Sensitive data size: %d\n", ss);
  TPM2B_DATA* sym = (TPM2B_DATA*) unsealed_return->buffer;
  uint16_t sb;
  change_endian16(&sym->size, &sb);
  printf("Buffer (%d): ", sb);
  print_bytes(sb, sym->buffer);
  printf("\n");

  if  (memcmp(secret.buffer, sym->buffer, sb) == 0) {
    printf("unsealed string matches\n");
  } else {
    printf("unsealed string DOES NOT matches\n");
  }

  Tpm2_FlushContext(tpm, session_handle);
  Tpm2_FlushContext(tpm, load_handle);
  return true;
}
