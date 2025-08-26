#include "cf_shims.h"
#include <string>
#include <vector>

// --- TRUST MANAGER FLAGS ---

int cf_tm_auth_key_initialized(TrustManager *tm) {
  if (!tm)
    return 0;
  // TODO: If there is a public getter like tm->auth_key_initialized() use it.
  // If not, try to infer from print_trust_data() or a status API.
  // Placeholder assumption:
  return tm->auth_key_initialized() ? 1 : 0;
}

int cf_tm_primary_admissions_cert_valid(TrustManager *tm) {
  if (!tm)
    return 0;
  // TODO: Replace with actual public getter if different name exists.
  return tm->primary_admissions_cert_valid() ? 1 : 0;
}

// --- CHANNEL PEER INFO ---

static int copy_str_to_out(const std::string &s, char *out, int out_len) {
  if (!out || out_len <= 0)
    return -1;
  int n = (int)s.size();
  if (n > out_len)
    n = out_len;
  memcpy(out, s.data(), n);
  return n;
}

int cf_channel_peer_id(SecureAuthenticatedChannel *ch,
                       char                       *out_buf,
                       int                         out_buf_len) {
  if (!ch)
    return -1;
  // TODO: If there is a public method like ch->peer_id() that returns
  // std::string, use it.
  std::string id = ch->peer_id();  // <-- adjust if needed
  return copy_str_to_out(id, out_buf, out_buf_len);
}

int cf_channel_peer_cert(SecureAuthenticatedChannel *ch,
                         unsigned char              *out_buf,
                         int                         out_buf_len) {
  if (!ch)
    return -1;
  // TODO: If there is a public method to fetch peer cert bytes, use it.
  // If it returns std::string/bytes, copy into out_buf.
  std::string cert_der = ch->peer_cert_der();  // <-- adjust if needed
  if (!out_buf || out_buf_len <= 0)
    return -1;
  int n = (int)cert_der.size();
  if (n > out_buf_len)
    n = out_buf_len;
  memcpy(out_buf, cert_der.data(), n);
  return n;
}
