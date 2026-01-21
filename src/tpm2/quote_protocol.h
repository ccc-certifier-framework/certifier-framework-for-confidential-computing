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
// File: quote_protocol.h

// standard buffer size

#ifndef __QUOTE_PROTOCOL__
#define __QUOTE_PROTOCOL__
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <tpm20.h>
#include <tpm2_lib.h>
#include <errno.h>

#include <openssl/sha.h>

#include <tpm2.pb.h>

#include <string>
using std::string;

void print_quote_certifyinfo(TPMS_ATTEST& in);
bool MarshalCertifyInfo(TPMS_ATTEST& in, int* size, byte* out);
bool UnmarshalCertifyInfo(int size, byte* in, TPMS_ATTEST* out);
bool ProtoToCertifyInfo(quote_certification_information& message, TPMS_ATTEST* out);
bool CertifyInfoToProto(TPMS_ATTEST& in, quote_certification_information& message);
bool ComputeQuotedValue(TPM_ALG_ID alg, int credInfo_size, byte* credInfo,
                        int* size_quoted, byte* quoted);
#endif

