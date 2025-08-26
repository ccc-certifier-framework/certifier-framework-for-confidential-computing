#pragma once

// TODO: adjust these includes to correct repo paths:
#include "trust_manager/trust_manager.h"
#include "secure_authenticated_channel/secure_authenticated_channel.h"

extern "C" {

// ---- TrustManager flags ----
// Return 1/0, not throwing exceptions across the JNI boundary.
int cf_tm_auth_key_initialized(TrustManager *tm);
int cf_tm_primary_admissions_cert_valid(TrustManager *tm);

// ---- Channel peek fields ----
// Returns length of peer_id into out_buf (<= out_buf_len), or -1 on error.
int cf_channel_peer_id(SecureAuthenticatedChannel *ch,
                       char                       *out_buf,
                       int                         out_buf_len);

// Returns length of peer_cert DER/PEM into out_buf (<= out_buf_len), or -1 on
// error.
int cf_channel_peer_cert(SecureAuthenticatedChannel *ch,
                         unsigned char              *out_buf,
                         int                         out_buf_len);
}
