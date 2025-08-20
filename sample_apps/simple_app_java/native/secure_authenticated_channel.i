%module(directors="1") secure_authenticated_channel

%{
#include "secure_authenticated_channel/secure_authenticated_channel.h"
#include "cf_shims.h"
%}

%package(org.certifier);

%feature("director") SecureAuthenticatedChannel;

%include "std_string.i"
%include "std_vector.i"

namespace std {
    %template(ByteVector) vector<unsigned char>;
    %template(StringVector) vector<string>;
}

%include "secure_authenticated_channel/secure_authenticated_channel.h"

// --- Shim helpers for peer_id / peer_cert ---
%inline %{
extern "C" {
  int cf_channel_peer_id(SecureAuthenticatedChannel* ch, char* out_buf, int out_buf_len);
  int cf_channel_peer_cert(SecureAuthenticatedChannel* ch, unsigned char* out_buf, int out_buf_len);
}
%}
