%module secure_authenticated_channel

%{
#include "secure_authenticated_channel/secure_authenticated_channel.h"
#include "cf_shims.h"
%}

%package(org.certifier)

%include "std_string.i"
%include "std_vector.i"

%include "secure_authenticated_channel/secure_authenticated_channel.h"

// Shim functions (so Java can read peer info)
%inline %{
extern "C" {
  int cf_channel_peer_id(SecureAuthenticatedChannel* ch, char* out_buf, int out_buf_len);
  int cf_channel_peer_cert(SecureAuthenticatedChannel* ch, unsigned char* out_buf, int out_buf_len);
}
%}
