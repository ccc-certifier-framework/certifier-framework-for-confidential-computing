bool endorsement_test(local_tpm& tpm) {
  string authString("01020304");
  string srkAuth("01020304");
  string emptyAuth;

  TPM_HANDLE ekHandle;
  TPM2B_PUBLIC pub_out;
  TPM2B_NAME pub_name;
  TPM2B_NAME qualified_pub_name;
  uint16_t pub_blob_size = 4096;
  byte_t pub_blob[pub_blob_size];

  TPML_PCR_SELECTION pcrSelect;
  memset((void*)&pcrSelect, 0, sizeof(TPML_PCR_SELECTION));

  // TPM_RH_ENDORSEMENT
  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Create Endorsement key with handle ekHandle
  if (Tpm2_CreatePrimary(tpm, TPM_RH_ENDORSEMENT, emptyAuth, pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA256, primary_flags,
                         TPM_ALG_AES, 256, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001, &ekHandle, &pub_out)) {
    printf("CreatePrimary succeeded primary: %08x\n", ekHandle);
  } else {
    printf("CreatePrimary failed --- primary key\n");
    return false;
  }
  if (Tpm2_ReadPublic(tpm, ekHandle, &pub_blob_size, pub_blob,
                      &pub_out, &pub_name, &qualified_pub_name)) {
    printf("ReadPublic succeeded\n");
  } else {
    printf("ReadPublic failed\n");
    return false;
  }
  printf("Public blob: ");
  print_bytes(pub_blob_size, pub_blob);
  printf("\n");
  printf("\nName: ");
  print_bytes(pub_name.size, pub_name.name);
  printf("\n");
  printf("Qualified name: ");
  print_bytes(qualified_pub_name.size, qualified_pub_name.name);
  printf("\n");
  printf("\n");
  printf("Pubout size: %d\n", pub_out.size);
  printf("Type: %d\n", pub_out.publicArea.type);
  printf("Name: %d\n", pub_out.publicArea.nameAlg);
  printf("Scheme: %d\n", pub_out.publicArea.parameters.rsaDetail.scheme.scheme);
  printf("Bytes (%d):\n", (int)pub_out.publicArea.unique.rsa.size);
  print_bytes((int)pub_out.publicArea.unique.rsa.size,
             (byte_t*)pub_out.publicArea.unique.rsa.buffer);
  printf("\n");
  printf("Exponent: %d\n", pub_out.publicArea.parameters.rsaDetail.exponent);
  printf("\n");

  TPM_HANDLE srkHandle;
  TPM_HANDLE quotingHandle;
  TPM2B_PUBLIC srk_pub_out;
  TPML_PCR_SELECTION srk_pcrSelect;
  init_single_pcr_selection(7, TPM_ALG_SHA256, &srk_pcrSelect);

  TPMA_OBJECT srk_flags;
  *(uint32_t*)(&srk_flags) = 0;
  srk_flags.fixedTPM = 1;
  srk_flags.fixedParent = 1;
  srk_flags.sensitiveDataOrigin = 1;
  srk_flags.userWithAuth = 1;
  srk_flags.decrypt = 1;
  srk_flags.restricted = 1;

  // Storage root key
  init_single_pcr_selection(7, TPM_ALG_SHA256, &pcrSelect);
  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, srk_pcrSelect,
                         TPM_ALG_RSA, TPM_ALG_SHA256, srk_flags,
                         TPM_ALG_AES, 256, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001,
                         &srkHandle, &srk_pub_out)) {
    printf("CreatePrimary second key succeeded\n");
  } else {
    printf("CreatePrimary failed - second key\n");
    return false;
  }

  // TODO: Save this key for reloading when we quote

  TPM2B_CREATION_DATA creation_out;
  TPM2B_DIGEST digest_out;
  TPMT_TK_CREATION creation_ticket;
  int size_public = MAX_SIZE_PARAMS;
  byte_t out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte_t out_private[MAX_SIZE_PARAMS];

  memset((void*)&pub_out, 0, sizeof(TPM2B_PUBLIC));

  TPMA_OBJECT quoting_flags;
  *(uint32_t*)(&quoting_flags) = 0;
  quoting_flags.fixedTPM = 1;
  quoting_flags.fixedParent = 1;
  quoting_flags.sensitiveDataOrigin = 1;
  quoting_flags.userWithAuth = 1;
  quoting_flags.sign = 1;
  quoting_flags.restricted = 1;

  // Create the Quote Key
  if (Tpm2_CreateKey(tpm, srkHandle, srkAuth, authString,
                     srk_pcrSelect,
                     TPM_ALG_RSA, TPM_ALG_SHA256, quoting_flags, TPM_ALG_NULL,
                     (TPMI_AES_KEY_BITS)0, TPM_ALG_ECB, TPM_ALG_RSASSA,
                     2048, 0x010001, &size_public, out_public,
                     &size_private, out_private,
                     &creation_out, &digest_out, &creation_ticket)) {
    printf("CreateKey succeeded private size: %d, public size: %d\n",
           size_private, size_public);
  } else {
    printf("CreateKey failed\n");
    return false;
  }

  // Load Quote key
  if (Tpm2_Load(tpm, srkHandle, srkAuth, size_public, out_public,
               size_private, out_private, &quotingHandle, &pub_name)) {
    printf("Load succeeded, handle: %08x\n", quotingHandle);
  } else {
    Tpm2_FlushContext(tpm, ekHandle);
    Tpm2_FlushContext(tpm, srkHandle);
    printf("Load failed\n");
    return false;
  }

  TPM2B_DIGEST credential;
  TPM2B_ID_OBJECT credentialBlob;
  TPM2B_ENCRYPTED_SECRET secret;
  TPM2B_DIGEST recovered_credential;

  memset((void*)&credential, 0, sizeof(TPM2B_DIGEST));
  memset((void*)&secret, 0, sizeof(TPM2B_ENCRYPTED_SECRET));
  memset((void*)&credentialBlob, 0, sizeof(TPM2B_ID_OBJECT));

  // TODO: Make a real secret here for MakeCredential with
  // size 32 bits.
  credential.size = 20;
  for (int i = 0; i < credential.size; i++)
    credential.buffer[i] = i + 1;

  TPM2B_PUBLIC quoting_pub_out;
  TPM2B_NAME quoting_pub_name;
  TPM2B_NAME quoting_qualified_pub_name;
  uint16_t quoting_pub_blob_size = 1024;
  byte_t quoting_pub_blob[quoting_pub_blob_size];

  memset((void*)&quoting_pub_out, 0, sizeof(TPM2B_PUBLIC));

  if (Tpm2_ReadPublic(tpm, quotingHandle,
                      &quoting_pub_blob_size, quoting_pub_blob,
                      &quoting_pub_out, &quoting_pub_name,
                      &quoting_qualified_pub_name)) {
    printf("ReadPublic succeeded\n");
  } else {
    printf("ReadPublic failed\n");
    return false;
  }
  printf("Active Name (%d): ", quoting_pub_name.size);
  print_bytes(quoting_pub_name.size, quoting_pub_name.name);
  printf("\n");

  if (Tpm2_MakeCredential(tpm, ekHandle, credential, quoting_pub_name,
                          &credentialBlob, &secret)) {
    printf("MakeCredential succeeded\n");
  } else {
    printf("MakeCredential failed\n");
    Tpm2_FlushContext(tpm, quotingHandle);
    Tpm2_FlushContext(tpm, srkHandle);
    Tpm2_FlushContext(tpm, ekHandle);
    return false;
  }
  printf("credBlob size: %d\n", credentialBlob.size);
  printf("secret size: %d\n", secret.size);
  if (Tpm2_ActivateCredential(tpm, quotingHandle, ekHandle,
                              srkAuth, emptyAuth,
                              credentialBlob, secret,
                              &recovered_credential)) {
    printf("ActivateCredential succeeded\n");
    printf("Recovered credential (%d): ", recovered_credential.size);
    print_bytes(recovered_credential.size, recovered_credential.buffer);
    printf("\n");
  } else {
    printf("ActivateCredential failed\n");
    Tpm2_FlushContext(tpm, quotingHandle);
    Tpm2_FlushContext(tpm, srkHandle);
    Tpm2_FlushContext(tpm, ekHandle);
    return false;
  }
  Tpm2_FlushContext(tpm, quotingHandle);
  Tpm2_FlushContext(tpm, srkHandle);
  Tpm2_FlushContext(tpm, ekHandle);
  return true;
}
