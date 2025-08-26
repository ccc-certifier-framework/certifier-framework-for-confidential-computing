#include "cf_shims.h"

#include <string>
#include <vector>
#include <type_traits>
#include <cstring>

// ---------- Detection helpers (C++17) ----------

template <typename T, typename = void>
struct has_auth_key_initialized : std::false_type {};
template <typename T>
struct has_auth_key_initialized<T, std::void_t<decltype(std::declval<T>().auth_key_initialized())>> : std::true_type {};

template <typename T, typename = void>
struct has_is_auth_key_initialized : std::false_type {};
template <typename T>
struct has_is_auth_key_initialized<T, std::void_t<decltype(std::declval<T>().is_auth_key_initialized())>> : std::true_type {};

template <typename T, typename = void>
struct has_primary_admissions_cert_valid : std::false_type {};
template <typename T>
struct has_primary_admissions_cert_valid<T, std::void_t<decltype(std::declval<T>().primary_admissions_cert_valid())>> : std::true_type {};

template <typename T, typename = void>
struct has_peer_id : std::false_type {};
template <typename T>
struct has_peer_id<T, std::void_t<decltype(std::declval<T>().peer_id())>> : std::true_type {};

template <typename T, typename = void>
struct has_peer_id_str : std::false_type {};
template <typename T>
struct has_peer_id_str<T, std::void_t<decltype(std::declval<T>().peer_id_str())>> : std::true_type {};

template <typename T, typename = void>
struct has_peer_cert_der : std::false_type {};
template <typename T>
struct has_peer_cert_der<T, std::void_t<decltype(std::declval<T>().peer_cert_der())>> : std::true_type {};

template <typename T, typename = void>
struct has_peer_cert_pem : std::false_type {};
template <typename T>
struct has_peer_cert_pem<T, std::void_t<decltype(std::declval<T>().peer_cert_pem())>> : std::true_type {};

static int copy_str_to_out(const std::string& s, char* out, int out_len) {
  if (!out || out_len <= 0) return -1;
  int n = static_cast<int>(s.size());
  if (n > out_len) n = out_len;
  std::memcpy(out, s.data(), n);
  return n;
}

static int copy_bytes_to_out(const std::string& s, unsigned char* out, int out_len) {
  if (!out || out_len <= 0) return -1;
  int n = static_cast<int>(s.size());
  if (n > out_len) n = out_len;
  std::memcpy(out, s.data(), n);
  return n;
}

// ---------- TrustManager flags ----------

int cf_tm_auth_key_initialized(TrustManager* tm) {
  if (!tm) return 0;
  if constexpr (has_auth_key_initialized<TrustManager>::value) {
    return tm->auth_key_initialized() ? 1 : 0;
  } else if constexpr (has_is_auth_key_initialized<TrustManager>::value) {
    return tm->is_auth_key_initialized() ? 1 : 0;
  } else {
    // Unknown API; default to false
    return 0;
  }
}

int cf_tm_primary_admissions_cert_valid(TrustManager* tm) {
  if (!tm) return 0;
  if constexpr (has_primary_admissions_cert_valid<TrustManager>::value) {
    return tm->primary_admissions_cert_valid() ? 1 : 0;
  } else {
    // Unknown API; default to false
    return 0;
  }
}

// ---------- Channel peer info ----------

int cf_channel_peer_id(SecureAuthenticatedChannel* ch, char* out_buf, int out_buf_len) {
  if (!ch) return -1;
  if constexpr (has_peer_id<SecureAuthenticatedChannel>::value) {
    auto id = ch->peer_id();           // expect std::string
    return copy_str_to_out(id, out_buf, out_buf_len);
  } else if constexpr (has_peer_id_str<SecureAuthenticatedChannel>::value) {
    auto id = ch->peer_id_str();       // alternative name
    return copy_str_to_out(id, out_buf, out_buf_len);
  } else {
    return -1;
  }
}

int cf_channel_peer_cert(SecureAuthenticatedChannel* ch, unsigned char* out_buf, int out_buf_len) {
  if (!ch) return -1;
  if constexpr (has_peer_cert_der<SecureAuthenticatedChannel>::value) {
    auto cert = ch->peer_cert_der();   // expect DER bytes in std::string
    return copy_bytes_to_out(cert, out_buf, out_buf_len);
  } else if constexpr (has_peer_cert_pem<SecureAuthenticatedChannel>::value) {
    auto cert = ch->peer_cert_pem();   // expect PEM text in std::string
    return copy_bytes_to_out(cert, out_buf, out_buf_len);
  } else {
    return -1;
  }
}
