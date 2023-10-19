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

typedef struct nvmlDevice_st *nvmlDevice_t;

class NvidiaGPUImpl : public NvidiaGPU {
 public:
  GPUArch     get_architecture() override;
  std::string get_uuid() override;
  std::string get_vbios_version() override;

  // Returns the attestation certificate chain for this GPU in PEM format
  virtual std::vector<uint8_t> get_attestation_cert_chain() override;
  // Returns the attestation report for this GPU with the given nonce
  virtual std::vector<uint8_t> get_attestation_report(
      const std::vector<uint8_t> &nonce) override;

 private:
  NvidiaGPUImpl(void *libHandle, nvmlDevice_t device)
     : libHandle(libHandle), device(device) {}
  void *       libHandle;
  nvmlDevice_t device;
  friend class NvidiaPlatformImpl;
};

class NvidiaPlatformImpl : public NvidiaPlatform {
 public:
  static std::unique_ptr<NvidiaPlatform> create(const char *libPath);

  std::string get_driver_version() override;
  bool        is_cc_enabled() override;
  int         get_num_gpus() override;

  NvidiaGPU *get_gpu(int index) override;

 private:
  NvidiaPlatformImpl() {}
  bool                       loadNvmlLibrary(const char *libPath);
  void *                     libHandle;
  std::string                driver_version;
  std::vector<NvidiaGPUImpl> gpus;
};
