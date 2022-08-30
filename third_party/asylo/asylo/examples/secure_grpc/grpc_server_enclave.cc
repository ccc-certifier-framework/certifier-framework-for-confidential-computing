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

#include <chrono>
#include <memory>

#include "absl/base/thread_annotations.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "absl/synchronization/notification.h"
#include "absl/time/time.h"
#include "asylo/examples/grpc_server/grpc_server_config.pb.h"
#include "asylo/examples/secure_grpc/grpc_server_config.pb.h"
#include "asylo/examples/secure_grpc/translator_server_impl.h"
#include "asylo/grpc/auth/enclave_server_credentials.h"
#include "asylo/grpc/auth/sgx_local_credentials_options.h"
#include "asylo/identity/identity_acl.pb.h"
#include "asylo/identity/identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity.pb.h"
#include "asylo/identity/platform/sgx/sgx_identity_util.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_generator.h"
#include "asylo/identity/attestation/sgx/sgx_local_assertion_verifier.h"
#include "asylo/identity/enclave_assertion_authority_config.pb.h"
#include "asylo/identity/platform/sgx/internal/sgx_identity_util_internal.h"
#include "asylo/trusted_application.h"
#include "asylo/util/status.h"
#include "asylo/util/status_macros.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server.h"
#include "include/grpcpp/server_builder.h"
#include "asylo/enclave.pb.h"
#include "asylo/identity/sealing/sgx/sgx_local_secret_sealer.h"
#include "asylo/util/cleansing_types.h"
#include <gtest/gtest.h>

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
extern bool setup_server_ssl();
extern bool asylo_setup_certifier_functions(AsyloCertifierFunctions asyloFuncs);
extern bool asylo_local_certify();
extern bool asylo_seal();

namespace examples {
namespace secure_grpc {

typedef unsigned char byte;
asylo::EnclaveConfig kEnclaveConfig;
constexpr char kCertifierString[] = "CertifierString";
constexpr char kCeritifierAad[] = "Test Aad for certifier";
constexpr char kCeritifierSecret[] = "Test secret for certifier";
constexpr size_t kCeritifierSecretSize = sizeof(kCeritifierSecret) - 1;

absl::Status PrepareSealedSecretHeader(const asylo::SgxLocalSecretSealer &sealer,
                                       asylo::SealedSecretHeader *header) {
  absl::Status status;
  status = sealer.SetDefaultHeader(header);
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return status;
  }
  header->set_secret_name(kCertifierString);
  header->set_secret_version(kCertifierString);
  header->set_secret_purpose(kCertifierString);
  header->set_secret_handling_policy(kCertifierString);

  return absl::OkStatus();
}

void print_bytes(int n, byte* buf) {
  for(int i = 0; i < n; i++)
    printf("%02x", buf[i]);
  printf("\n");
}

absl::Status SetupSealUnseal() {
  asylo::Status status;
  asylo::CleansingVector<uint8_t> input_secret(kCeritifierSecret,
                                               kCeritifierSecret +
                                               kCeritifierSecretSize);
  std::string input_aad(kCeritifierAad);

  LOG(INFO) << "Preparing Sealer size: " << sizeof(input_secret);
  std::unique_ptr<asylo::SgxLocalSecretSealer> sealer =
      asylo::SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  asylo::SealedSecretHeader header;
  status = PrepareSealedSecretHeader(*sealer, &header);
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return status;
  }

  asylo::SealedSecret sealed_secret;
  status = sealer->Seal(header, input_aad, input_secret, &sealed_secret);
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return status;
  }
  LOG(INFO) << "Successfully sealed size: " <<
               sizeof(sealed_secret.SerializeAsString());

  std::unique_ptr<asylo::SgxLocalSecretSealer> sealer2 =
      asylo::SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  asylo::CleansingVector<uint8_t> output_secret;

  status = sealer2->Unseal(sealed_secret, &output_secret);
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return status;
  }
  LOG(INFO) << "Successfully unsealed size: " << sizeof(output_secret);

  EXPECT_EQ(input_secret, output_secret);

  LOG(INFO) << "Successfully verified sealed and unsealed secret\n";

  return absl::OkStatus();
}

absl::Status SetupAssertionRequest() {
  constexpr char kUserData[] = "User data";

  asylo::Status status;
  asylo::SgxLocalAssertionVerifier verifier;

  // Get config from global
  const asylo::EnclaveConfig enclave_config = kEnclaveConfig;

  const asylo::EnclaveAssertionAuthorityConfig *config_out;

  // Initialize assertion authorities with provided configs.
  for (auto it = enclave_config.enclave_assertion_authority_configs().begin();
       it != enclave_config.enclave_assertion_authority_configs().end(); ++it) {
    const asylo::EnclaveAssertionAuthorityConfig &config = *it;
    config_out = &config;

    LOG(INFO) << "Assertion found\n";
  }

  status = verifier.Initialize(config_out->config());
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return status;
  }

  asylo::AssertionRequest request;
  verifier.CreateAssertionRequest(&request);
  LOG(INFO) << "Created assertion request\n";

  asylo::SgxLocalAssertionGenerator generator;
  status = generator.Initialize(config_out->config());

  asylo::Assertion assertion;
  status = generator.Generate(kUserData, request, &assertion);
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return status;
  }
  LOG(INFO) << "Generated assertion\n";

  asylo::EnclaveIdentity identity;
  status = verifier.Verify(kUserData, assertion, &identity);
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return status;
  }
  LOG(INFO) << "Verified assertion\n";

  return absl::OkStatus();
}

bool Attest(int claims_size, byte* claims, int* size_out, byte* out) {
  LOG(INFO) << "Input to Attest size: " << claims_size;
  print_bytes(claims_size, claims);

  std::string str_claims(&claims[0], &claims[0] + claims_size);

  asylo::Status status;
  asylo::SgxLocalAssertionVerifier verifier;

  // Get config from global
  const asylo::EnclaveConfig enclave_config = kEnclaveConfig;

  const asylo::EnclaveAssertionAuthorityConfig *config_out;

  // Initialize assertion authorities with provided configs.
  for (auto it = enclave_config.enclave_assertion_authority_configs().begin();
       it != enclave_config.enclave_assertion_authority_configs().end(); ++it) {
    const asylo::EnclaveAssertionAuthorityConfig &config = *it;
    config_out = &config;

    LOG(INFO) << "Assertion found\n";
  }

  status = verifier.Initialize(config_out->config());
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return false;
  }

  asylo::AssertionRequest request;
  verifier.CreateAssertionRequest(&request);
  LOG(INFO) << "Created assertion request\n";

  asylo::SgxLocalAssertionGenerator generator;
  status = generator.Initialize(config_out->config());

  asylo::Assertion assertion;
  status = generator.Generate(str_claims, request, &assertion);
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return false;
  }
  LOG(INFO) << "Generated assertion\n";

  auto size = assertion.ByteSize();
  assertion.SerializeToArray(out, size);
  print_bytes(size, out);
  *size_out = size;

  return true;
}

bool Verify(int user_data_size, byte* user_data, int assertion_size, byte *assertion, int* size_out, byte* out) {
  asylo::Status status;

  LOG(INFO) << "Input to Verify user_data_size: " << user_data_size;
  print_bytes(user_data_size, user_data);
  LOG(INFO) << "Input to Verify assertion_size: " << assertion_size;
  print_bytes(assertion_size, assertion);

  std::string str_user_data(&user_data[0], &user_data[0] + user_data_size);
  asylo::Assertion asylo_assertion;
  std::string str_assertion(&assertion[0], &assertion[0] + assertion_size);
  asylo_assertion.ParseFromString(str_assertion);

  // Get config from global
  const asylo::EnclaveConfig enclave_config = kEnclaveConfig;

  const asylo::EnclaveAssertionAuthorityConfig *config_out;

  // Initialize assertion authorities with provided configs.
  for (auto it = enclave_config.enclave_assertion_authority_configs().begin();
       it != enclave_config.enclave_assertion_authority_configs().end(); ++it) {
    const asylo::EnclaveAssertionAuthorityConfig &config = *it;
    config_out = &config;

    LOG(INFO) << "Assertion found\n";
  }

  asylo::SgxLocalAssertionVerifier verifier;
  status = verifier.Initialize(config_out->config());
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return false;
  }

  asylo::AssertionRequest request;
  verifier.CreateAssertionRequest(&request);
  LOG(INFO) << "Created assertion request\n";

  asylo::EnclaveIdentity identity;
  status = verifier.Verify(str_user_data, asylo_assertion, &identity);
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return false;
  }
  LOG(INFO) << "Verified assertion\n";

  asylo::SgxIdentity sgx_identity;

  asylo::sgx::ParseSgxIdentity(identity, &sgx_identity);

  asylo::sgx::CodeIdentity code_identity = sgx_identity.code_identity();

  std::string hash = code_identity.signer_assigned_identity().mrsigner().hash();

  for (int i = 0; i < hash.size(); i++) {
    out[i] = hash[i];
  }
  *size_out = hash.size();
  print_bytes(*size_out, out);

  return true;
}


bool Seal(int in_size, byte* in, int* size_out, byte* out) {
  asylo::Status status;
  LOG(INFO) << "Seal: Input size: " << in_size;
  asylo::CleansingVector<uint8_t> input_secret(in, in + in_size);
  LOG(INFO) << "Seal: vec size:" << input_secret.size();
  std::string input_aad(kCeritifierAad);

  print_bytes(in_size, in);
  LOG(INFO) << "Preparing Sealer";
  std::unique_ptr<asylo::SgxLocalSecretSealer> sealer =
      asylo::SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  asylo::SealedSecretHeader header;
  status = PrepareSealedSecretHeader(*sealer, &header);
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return false;
  }

  asylo::SealedSecret sealed_secret;
  status = sealer->Seal(header, input_aad, input_secret, &sealed_secret);
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return false;
  }

  std::string serialized_secret = sealed_secret.SerializeAsString();

  for (int i = 0; i < serialized_secret.size(); i++) {
    out[i] = serialized_secret[i];
  }
  LOG(INFO) << "Print secret";
  print_bytes(serialized_secret.size(), out);

  *size_out = serialized_secret.size();
  LOG(INFO) << "Seal: Successfully sealed size: " << *size_out;

  return true;
}

bool Unseal(int in_size, byte* in, int* size_out, byte* out) {
  asylo::Status status;
  LOG(INFO) << "Preparing Unsealer size: " << in_size;
  std::unique_ptr<asylo::SgxLocalSecretSealer> sealer2 =
      asylo::SgxLocalSecretSealer::CreateMrsignerSecretSealer();
  asylo::CleansingVector<uint8_t> output_secret;

  LOG(INFO) << "Input to Unseal:";
  print_bytes(in_size, in);

  std::string str(&in[0], &in[0] + in_size);
  asylo::SealedSecret sealed_secret;
  sealed_secret.ParseFromString(str);
  LOG(INFO) << "Print bytes before unseal:";
  print_bytes(in_size, (byte*)str.c_str());

  LOG(INFO) << "Invoking Unseal in size: " << in_size << " Parse size: " <<
    sizeof(sealed_secret);
  status = sealer2->Unseal(sealed_secret, &output_secret);
  LOG(INFO) << "Done Unsealing...";
  if (status != absl::OkStatus()) {
    LOG(ERROR) << "Error: " << status;
    return false;
  }

  std::string output_string(output_secret.begin(), output_secret.end());

  *size_out = sizeof(output_string);
  for (int i = 0; i < output_string.size(); i++) {
    out[i] = output_string[i];
  }

  LOG(INFO) << "Successfully unsealed size: " << *size_out << "buffer: ";
  print_bytes(*size_out, out);

  return true;
}

// An enclave that runs a TranslatorServerImpl. We override the methods of
// TrustedApplication as follows:
//
// * Initialize starts the gRPC server.
// * Run retrieves the server port.
// * Finalize shuts down the server.
class GrpcServerEnclave final : public asylo::TrustedApplication {
 public:
  asylo::Status Initialize(const asylo::EnclaveConfig &enclave_config)
      ABSL_LOCKS_EXCLUDED(server_mutex_) override;

  asylo::Status Run(const asylo::EnclaveInput &enclave_input,
                    asylo::EnclaveOutput *enclave_output) override;

  asylo::Status Finalize(const asylo::EnclaveFinal &enclave_final)
      ABSL_LOCKS_EXCLUDED(server_mutex_) override;

 private:
  // Guards the |server_| member.
  absl::Mutex server_mutex_;

  // A gRPC server hosting |service_|.
  std::unique_ptr<::grpc::Server> server_ ABSL_GUARDED_BY(server_mutex_);

  // The translation service.
  std::unique_ptr<TranslatorServerImpl> service_;

  // The server's selected port.
  int selected_port_;
};

asylo::Status GrpcServerEnclave::Initialize(
    const asylo::EnclaveConfig &enclave_config)
    ABSL_LOCKS_EXCLUDED(server_mutex_) {
  // Fail if there is no server_address available.
  if (!enclave_config.HasExtension(grpc_server::server_address)) {
    return absl::InvalidArgumentError(
        "Expected a server_address extension on config.");
  }

  if (!enclave_config.HasExtension(grpc_server::port)) {
    return absl::InvalidArgumentError("Expected a port extension on config.");
  }

  if (!enclave_config.HasExtension(identity_expectation)) {
    return absl::InvalidArgumentError(
        "Expected an identity_expectation extension on config.");
  }

  // Lock |server_mutex_| so that we can start setting up the server.
  absl::MutexLock lock(&server_mutex_);

  // Store in global enclave config
  kEnclaveConfig = enclave_config;

  // Check that the server is not already running.
  if (server_) {
    return absl::AlreadyExistsError("Server is already started");
  }

  // Create a ServerBuilder object to set up the server.
  ::grpc::ServerBuilder builder;

  // Use SGX local credentials to ensure that only local SGX enclaves can
  // connect to the server.
  std::shared_ptr<::grpc::ServerCredentials> server_credentials =
      asylo::EnclaveServerCredentials(
          asylo::BidirectionalSgxLocalCredentialsOptions());

  // Add a listening port to the server.
  builder.AddListeningPort(
      absl::StrCat(enclave_config.GetExtension(grpc_server::server_address),
                   ":", enclave_config.GetExtension(grpc_server::port)),
      server_credentials, &selected_port_);

  bool cert_result = false;
  std::string data_dir = "./server_data";

  AsyloCertifierFunctions asyloFuncs;
  asyloFuncs.Attest = &Attest;
  asyloFuncs.Verify = &Verify;
  asyloFuncs.Seal = &Seal;
  asyloFuncs.Unseal = &Unseal;

  absl::Status status;

  /* Asylo Local Test */
  status = SetupSealUnseal();
  LOG_IF(QFATAL, status != absl::OkStatus())
      << "SealUnseal failed: result = " << status;

  status = SetupAssertionRequest();
  LOG_IF(QFATAL, status != absl::OkStatus())
      << "AssertionRequest failed: result = " << status;

  /* Setup functions */
  cert_result = asylo_setup_certifier_functions(asyloFuncs);
  LOG_IF(QFATAL, !cert_result)
      << "asylo_setup_certifier_functions failed: result = " << cert_result;

  /* Certifier local attest and seal tests */
  cert_result = asylo_local_certify();
  LOG_IF(QFATAL, !cert_result)
      << "asylo_local_certify failed: result = " << cert_result;

  cert_result = asylo_seal();
  LOG_IF(QFATAL, !cert_result)
      << "asylo_seal failed: result = " << cert_result;

  /* Continue with certifier service based usage */
  cert_result = certifier_init((char*)data_dir.c_str(), data_dir.size());
  LOG_IF(QFATAL, !cert_result)
      << "certifier_init failed: result = " << cert_result;

  cert_result = cold_init();
  LOG_IF(QFATAL, !cert_result)
      << "cold_init failed: result = " << cert_result;

  cert_result = certify_me();
  LOG_IF(QFATAL, !cert_result)
      << "certify_me failed: result = " << cert_result;

  cert_result = setup_server_ssl();
  LOG_IF(QFATAL, !cert_result)
      << "setup_ssl failed: result = " << cert_result;

  // Extract the SgxIdentityExpectation from the enclave's configuration. This
  // is used as the basis of the server's ACL.
  asylo::SgxIdentityExpectation sgx_expectation =
      enclave_config.GetExtension(identity_expectation);

  // Construct an ACL based from the SgxIdentityExpectation.
  asylo::IdentityAclPredicate acl;
  ASYLO_ASSIGN_OR_RETURN(
      *acl.mutable_expectation(),
      asylo::SerializeSgxIdentityExpectation(sgx_expectation));

  // Build the service with the configured ACL.
  service_ = absl::make_unique<TranslatorServerImpl>(std::move(acl));

  // Add the translator service to the server.
  builder.RegisterService(service_.get());

  // Start the server.
  server_ = builder.BuildAndStart();
  if (!server_) {
    return absl::InternalError("Failed to start server");
  }

  return absl::OkStatus();
}

asylo::Status GrpcServerEnclave::Run(const asylo::EnclaveInput &enclave_input,
                                     asylo::EnclaveOutput *enclave_output) {
  enclave_output->SetExtension(server_port, selected_port_);

  return absl::OkStatus();
}

asylo::Status GrpcServerEnclave::Finalize(
    const asylo::EnclaveFinal &enclave_final)
    ABSL_LOCKS_EXCLUDED(server_mutex_) {
  // Lock |server_mutex_| so that we can start shutting down the server.
  absl::MutexLock lock(&server_mutex_);

  // If the server exists, then shut it down. Also delete the Server object to
  // indicate that it is no longer valid.
  if (server_) {
    LOG(INFO) << "Server shutting down";

    // Give all outstanding RPC calls 500 milliseconds to complete.
    server_->Shutdown(std::chrono::system_clock::now() +
                      std::chrono::milliseconds(500));
    server_.reset(nullptr);
  }

  return absl::OkStatus();
}

}  // namespace secure_grpc
}  // namespace examples

namespace asylo {

// Registers an instance of GrpcServerEnclave as the TrustedApplication. See
// trusted_application.h for more information.
TrustedApplication *BuildTrustedApplication() {
  return new examples::secure_grpc::GrpcServerEnclave;
}

}  // namespace asylo
