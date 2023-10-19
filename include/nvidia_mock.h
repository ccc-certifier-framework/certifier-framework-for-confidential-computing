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
#pragma once

#include <nvidia.h>

class NvidiaGPUMock : public NvidiaGPU {
 public:
  NvidiaGPUMock(const std::string &dir) : base_dir(dir) {}

  GPUArch get_architecture() override { return GPUArch::Hopper; }

  std::string get_uuid() override {
    return "GPU-11111111-2222-3333-4444-555555555555";
  }

  std::string get_vbios_version() override { return "96.00.5e.00.01"; }

  std::vector<uint8_t> get_attestation_cert_chain() override;

  std::vector<uint8_t> get_attestation_report(
      const std::vector<uint8_t> &nonce) override;

 private:
  std::string base_dir;
};

class NvidiaPlatformMock : public NvidiaPlatform {
 public:
  NvidiaPlatformMock(const std::string &dir) : base_dir(dir) {}

  std::string get_driver_version() override { return "545.00"; }

  bool is_cc_enabled() override { return true; }

  int get_num_gpus() override { return 1; }

  NvidiaGPU *get_gpu(int index) override { return new NvidiaGPUMock(base_dir); }

 private:
  std::string base_dir;
};
