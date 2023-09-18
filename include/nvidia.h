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

#include <string>
#include <vector>
#include <memory>

enum GPUArch {
  Unknown = -1,
  Kepler = 0,
  Maxwell = 1,
  Pascal = 2,
  Volta = 3,
  Turing = 4,
  Ampere = 5,
  Hopper = 6
};

class NvidiaGPU {
 public:
  virtual GPUArch     get_architecture() = 0;
  virtual std::string get_uuid() = 0;
  virtual std::string get_vbios_version() = 0;
  // Returns the attestation certificate chain for this GPU in PEM format
  virtual std::vector<uint8_t> get_attestation_cert_chain() = 0;
  // Returns the attestation report for this GPU with the given nonce
  virtual std::vector<uint8_t> get_attestation_report(
      const std::vector<uint8_t> &nonce) = 0;

  virtual ~NvidiaGPU() = default;
};

class NvidiaPlatform {
 public:
  virtual std::string get_driver_version() = 0;
  virtual bool        is_cc_enabled() = 0;
  virtual int         get_num_gpus() = 0;
  virtual NvidiaGPU * get_gpu(int index) = 0;

  virtual ~NvidiaPlatform() = default;
};
