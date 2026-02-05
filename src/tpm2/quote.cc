bool quote_test(local_tpm& tpm, int pcr_num) {
  string authString("01020304");
  string parentAuth("01020304");
  string emptyAuth;

  // Usually, we'd just load the SRK created in
  // the endorsement test and the quoting key
  // rather than making new ones.

  TPM_HANDLE parent_handle;
  TPM2B_PUBLIC pub_out;
  TPML_PCR_SELECTION pcr_selection;
  init_single_pcr_selection(pcr_num, TPM_ALG_SHA256, &pcr_selection);

  TPMA_OBJECT primary_flags;
  *(uint32_t*)(&primary_flags) = 0;
  primary_flags.fixedTPM = 1;
  primary_flags.fixedParent = 1;
  primary_flags.sensitiveDataOrigin = 1;
  primary_flags.userWithAuth = 1;
  primary_flags.decrypt = 1;
  primary_flags.restricted = 1;

  // Storage root key
  if (Tpm2_CreatePrimary(tpm, TPM_RH_OWNER, authString, pcr_selection, 
                         TPM_ALG_RSA, TPM_ALG_SHA256, primary_flags,
                         TPM_ALG_AES, 256, TPM_ALG_CFB, TPM_ALG_NULL,
                         2048, 0x010001,
                         &parent_handle, &pub_out)) {
    printf("CreatePrimary succeeded 1 (2048)\n");
  } else {
    printf("CreatePrimary failed\n");
    return false;
  }

  if (pcr_num >= 0) {
    uint16_t size_eventData = 3;
    byte_t eventData[3] = {1, 2, 3};
    if (Tpm2_PCR_Event(tpm, pcr_num, size_eventData, eventData)) {
      printf("Tpm2_PCR_Event succeeded\n");
    } else {
      printf("Tpm2_PCR_Event failed\n");
    }
  }

  TPM2B_CREATION_DATA creation_out;
  TPMT_TK_CREATION creation_ticket;
  int size_public = MAX_SIZE_PARAMS;
  byte_t out_public[MAX_SIZE_PARAMS];
  int size_private = MAX_SIZE_PARAMS;
  byte_t out_private[MAX_SIZE_PARAMS];
  TPM2B_DIGEST digest_out;

  TPMA_OBJECT create_flags;
  *(uint32_t*)(&create_flags) = 0;
  create_flags.fixedTPM = 1;
  create_flags.fixedParent = 1;
  create_flags.sensitiveDataOrigin = 1;
  create_flags.userWithAuth = 1;
  create_flags.sign = 1;
  create_flags.restricted = 1;

  // Quote key
  if (Tpm2_CreateKey(tpm, parent_handle, parentAuth, authString, pcr_selection,
                     TPM_ALG_RSA, TPM_ALG_SHA256, create_flags, TPM_ALG_NULL,
                     (TPMI_AES_KEY_BITS)256, TPM_ALG_ECB, TPM_ALG_RSASSA,
                     2048, 0x010001,
                     &size_public, out_public, &size_private, out_private,
                     &creation_out, &digest_out, &creation_ticket)) {
    printf("CreateKey succeeded, private size: %d, public size: %d\n",
           size_private, size_public);
  } else {
    printf("Create failed\n");
    return false;
  }

  TPM_HANDLE load_handle;
  TPM2B_NAME name;
  if (Tpm2_Load(tpm, parent_handle, parentAuth, size_public, out_public,
               size_private, out_private, &load_handle, &name)) {
    printf("Load succeeded\n");
  } else {
    printf("Load failed\n");
    return false;
  }

  TPM2B_DATA to_quote;
  to_quote.size = 32;
  for  (int i = 0; i < to_quote.size; i++)
    to_quote.buffer[i] = (byte_t)(i + 1);
  TPMT_SIG_SCHEME scheme;

  int quote_size = MAX_SIZE_PARAMS;
  byte_t quoted[MAX_SIZE_PARAMS];
  int sig_size = MAX_SIZE_PARAMS;
  byte_t sig[MAX_SIZE_PARAMS];
  if (!Tpm2_Quote(tpm, load_handle, authString,
                  to_quote.size, to_quote.buffer,
                  scheme, pcr_selection, TPM_ALG_RSA, TPM_ALG_SHA256,
                  &quote_size, quoted, &sig_size, sig)) {
    printf("Quote failed, pcr_num: %d\n", pcr_num);
    Tpm2_FlushContext(tpm, load_handle);
    Tpm2_FlushContext(tpm, parent_handle);
    return false;
  }
  printf("Quote succeeded, quoted (%d): ", quote_size); 
  print_bytes(quote_size, quoted);
  printf("\n"); 
  printf("Sig (%d): ", sig_size); 
  print_bytes(sig_size, sig);
  printf("\n"); 
  Tpm2_FlushContext(tpm, load_handle);
  Tpm2_FlushContext(tpm, parent_handle);
  return true;
}
