#pragma once

// Adjust includes if your paths differ:
#include "trust_manager/trust_manager.h"
#include "secure_authenticated_channel/secure_authenticated_channel.h"

extern "C" {

// ---- TrustManager flags ----
int cf_tm_auth_key_initialized(TrustManager* tm);           // returns 1/0
int cf_tm_primary_admissions_cert_valid(TrustManager* tm);  // returns 1/0

// ---- Channel peer info ----
// Returns length of copied peer_id into out_buf (<= out_buf_len), or -1 on error.
int cf_channel_peer_id(SecureAuthenticatedChannel* ch, char* out_buf, int out_buf_len);

// Returns length of copied peer certificate bytes (DER/PEM) into out_buf, or -1 on error.
int cf_channel_peer_cert(SecureAuthenticatedChannel* ch, unsigned char* out_buf, int out_buf_len);

}
