/*
 *
 * Copyright 2019 Asylo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "asylo/examples/secure_grpc/grpc_client_enclave.h"

#include <iostream>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/time/time.h"
#include "asylo/enclave.pb.h"
#include "asylo/examples/grpc_server/translator_server.grpc.pb.h"
#include "asylo/examples/secure_grpc/grpc_client_enclave.pb.h"
#include "asylo/grpc/auth/enclave_channel_credentials.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "asylo/util/statusor.h"
#include "include/grpc/impl/codegen/gpr_types.h"
#include "include/grpc/support/time.h"
#include "include/grpcpp/grpcpp.h"

typedef unsigned char byte;

typedef struct AsyloCertifierFunctions {
  bool (*Attest)(int claims_size, byte* claims, int* size_out, byte* out);
  bool (*Verify)(int user_data_size, byte* user_data, int assertion_size, byte *assertion, int* size_out, byte* out);
  bool (*Seal)(int in_size, byte* in, int* size_out, byte* out);
  bool (*Unseal)(int in_size, byte* in, int* size_out, byte* out);
} AsyloCertifierFunctions;

extern bool certifier_init(char* usr_data_dir, size_t usr_data_dir_size);
extern bool cold_init();
extern bool certify_me();
extern bool setup_client_ssl();
extern bool asylo_setup_certifier_functions(AsyloCertifierFunctions asyloFuncs);

namespace examples {
namespace secure_grpc {
namespace {

using grpc_server::Translator;

const absl::Duration kChannelDeadline = absl::Seconds(5);

// Makes a GetTranslation RPC with |request| to the server backed by *|stub|.
asylo::StatusOr<grpc_server::GetTranslationResponse> GetTranslation(
    const grpc_server::GetTranslationRequest &request, Translator::Stub *stub) {
  grpc_server::GetTranslationResponse response;

  ::grpc::ClientContext context;
  ASYLO_RETURN_IF_ERROR(
      asylo::Status(stub->GetTranslation(&context, request, &response)));
  return response;
}

}  // namespace

asylo::Status GrpcClientEnclave::Initialize(
    const asylo::EnclaveConfig &enclave_config) {
  std::string data_dir = "./client_data";

  LOG(INFO) << "Client initializing";

  AsyloCertifierFunctions asyloFuncs;
  asyloFuncs.Attest = NULL;
  asyloFuncs.Verify = NULL;
  asyloFuncs.Seal = NULL;
  asyloFuncs.Unseal = NULL;

  bool cert_result = false;
  /* Setup functions */
  cert_result = asylo_setup_certifier_functions(asyloFuncs);
  LOG_IF(QFATAL, !cert_result)
      << "asylo_setup_certifier_functions failed: result = " << cert_result;

  cert_result = certifier_init((char*)data_dir.c_str(), data_dir.size());
  LOG_IF(QFATAL, !cert_result)
      << "certifier_init failed: result = " << cert_result;

  cert_result = cold_init();
  LOG_IF(QFATAL, !cert_result)
      << "cold_init failed: result = " << cert_result;

  cert_result = certify_me();
  LOG_IF(QFATAL, !cert_result)
      << "certify_me failed: result = " << cert_result;

  LOG(INFO) << "Client done initializing";

  return absl::OkStatus();
}

asylo::Status GrpcClientEnclave::Run(const asylo::EnclaveInput &input,
                                     asylo::EnclaveOutput *output) {
  bool cert_result = false;
  LOG(INFO) << "Client requesting ssl check";

  cert_result = setup_client_ssl();
  LOG_IF(QFATAL, !cert_result)
      << "setup_ssl failed: result = " << cert_result;

  LOG(INFO) << "Client done ssl check";

  if (!input.HasExtension(client_enclave_input)) {
    return absl::InvalidArgumentError("Input missing client_input extension");
  }
  const GrpcClientEnclaveInput &client_input =
      input.GetExtension(client_enclave_input);

  const std::string &address = client_input.server_address();
  if (address.empty()) {
    return absl::InvalidArgumentError(
        "Input must provide a non-empty server address");
  }
  if (client_input.translation_request().input_word().empty()) {
    return absl::InvalidArgumentError(
        "Input must provide a non-empty RPC input");
  }

  // The ::grpc::ChannelCredentials object configures the channel authentication
  // mechanisms used by the client and server. This particular configuration
  // enforces that both the client and server authenticate using SGX local
  // attestation.
  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
      EnclaveChannelCredentials(
          asylo::BidirectionalSgxLocalCredentialsOptions());

  // Connect a gRPC channel to the server specified in the EnclaveInput.
  std::shared_ptr<::grpc::Channel> channel =
      ::grpc::CreateChannel(address, channel_credentials);

  gpr_timespec absolute_deadline = gpr_time_add(
      gpr_now(GPR_CLOCK_REALTIME),
      gpr_time_from_micros(absl::ToInt64Microseconds(kChannelDeadline),
                           GPR_TIMESPAN));
  if (!channel->WaitForConnected(absolute_deadline)) {
    return absl::InternalError("Failed to connect to server");
  }

  GrpcClientEnclaveOutput *client_output =
      output->MutableExtension(client_enclave_output);

  std::unique_ptr<Translator::Stub> stub = Translator::NewStub(channel);
  ASYLO_ASSIGN_OR_RETURN(
      *client_output->mutable_translation_response(),
      GetTranslation(client_input.translation_request(), stub.get()));

  return absl::OkStatus();
}

}  // namespace secure_grpc
}  // namespace examples

namespace asylo {

// Registers an instance of GrpcClientEnclave as the TrustedApplication. See
// trusted_application.h for more information.
TrustedApplication *BuildTrustedApplication() {
  return new examples::secure_grpc::GrpcClientEnclave();
}

}  // namespace asylo
