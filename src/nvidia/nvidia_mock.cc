//  Copyright (c) 2023, VMware Inc, and the Certifier Authors.  All rights
//  reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "nvidia_mock.h"
#include "certifier_utilities.h"

std::vector<uint8_t> NvidiaGPUMock::get_attestation_cert_chain() {
  int                  chain_size = 10000;
  std::vector<uint8_t> cert_chain(chain_size, 0);
  std::string          cert_path = base_dir + "/gpuAkCertChain.txt";
  bool                 ret = certifier::utilities::read_file(cert_path,
                                             &chain_size,
                                             cert_chain.data());
  if (!ret) {
    // return empty vector
    cert_chain.clear();
    return cert_chain;
  }
  cert_chain.resize(chain_size);
  return cert_chain;
}

std::vector<uint8_t> NvidiaGPUMock::get_attestation_report(
    const std::vector<uint8_t> &nonce) {
  int hex_report_size = 10000;
  // the attestation report as a hex string
  std::vector<uint8_t> hex_report(hex_report_size, 0);
  std::string          report_path = base_dir + "/attestationReport.txt";
  bool                 ret = certifier::utilities::read_file(report_path,
                                             &hex_report_size,
                                             hex_report.data());
  if (!ret) {
    // return empty vector
    hex_report.clear();
    return hex_report;
  }
  int report_size = hex_report_size / 2;
  // the attestation report as a binary string
  std::vector<uint8_t> report(report_size, 0);
  for (int i = 0; i < report_size; i++) {
    std::string hex_byte =
        std::string(hex_report.begin() + 2 * i, hex_report.begin() + 2 * i + 2);
    report[i] = std::stoi(hex_byte, nullptr, 16);
  }
  return report;
}
