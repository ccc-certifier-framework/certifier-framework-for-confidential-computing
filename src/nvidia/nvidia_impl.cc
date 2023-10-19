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

#include "nvidia_impl.h"
#include <cstring>
#include <dlfcn.h>

typedef unsigned int nvmlDeviceArchitecture_t;

/**
 * GPU Certificate Details
 */
#define NVML_GPU_CERT_CHAIN_SIZE             0x1000
#define NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE 0x1400

typedef struct nvmlConfComputeGpuCertificate_st {
  unsigned int  certChainSize;
  unsigned int  attestationCertChainSize;
  unsigned char certChain[NVML_GPU_CERT_CHAIN_SIZE];
  unsigned char attestationCertChain[NVML_GPU_ATTESTATION_CERT_CHAIN_SIZE];
} nvmlConfComputeGpuCertificate_t;

/**
 * GPU Attestation Report
 */
#define NVML_CC_GPU_CEC_NONCE_SIZE                 0x20
#define NVML_CC_GPU_ATTESTATION_REPORT_SIZE        0x2000
#define NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE    0x1000
#define NVML_CC_CEC_ATTESTATION_REPORT_NOT_PRESENT 0
#define NVML_CC_CEC_ATTESTATION_REPORT_PRESENT     1

typedef struct nvmlConfComputeGpuAttestationReport_st {
  unsigned int  isCecAttestationReportPresent;
  unsigned int  attestationReportSize;
  unsigned int  cecAttestationReportSize;
  unsigned char nonce[NVML_CC_GPU_CEC_NONCE_SIZE];
  unsigned char attestationReport[NVML_CC_GPU_ATTESTATION_REPORT_SIZE];
  unsigned char cecAttestationReport[NVML_CC_GPU_CEC_ATTESTATION_REPORT_SIZE];
} nvmlConfComputeGpuAttestationReport_t;

typedef int (*fInit)(void);
typedef int (*fSystemGetDriverVersion)(char *version, unsigned int length);
typedef int (*fDeviceGetCount)(unsigned int *deviceCount);
typedef int (*fDeviceGetHandleByIndex)(unsigned int  index,
                                       nvmlDevice_t *device);
typedef int (*fDeviceGetVbiosVersion)(nvmlDevice_t device,
                                      char *       version,
                                      unsigned int length);
typedef int (*fDeviceGetUUID)(nvmlDevice_t device,
                              char *       uuid,
                              unsigned int length);
typedef int (*fDeviceGetArchitecture)(nvmlDevice_t              device,
                                      nvmlDeviceArchitecture_t *arch);
typedef int (*fDeviceGetConfComputeGpuCertificate)(
    nvmlDevice_t                     device,
    nvmlConfComputeGpuCertificate_t *cert);
typedef int (*fDeviceGetConfComputeGpuAttestationReport)(
    nvmlDevice_t                           device,
    nvmlConfComputeGpuAttestationReport_t *report);

GPUArch NvidiaGPUImpl::get_architecture() {
  fDeviceGetArchitecture deviceGetArchitecture =
      (fDeviceGetArchitecture)dlsym(libHandle, "nvmlDeviceGetArchitecture");
  if (!deviceGetArchitecture) {
    return GPUArch::Unknown;
  }
  nvmlDeviceArchitecture_t arch;
  deviceGetArchitecture(device, &arch);
  switch (arch) {
    case 2:
      return GPUArch::Kepler;
    case 3:
      return GPUArch::Maxwell;
    case 4:
      return GPUArch::Pascal;
    case 5:
      return GPUArch::Volta;
    case 6:
      return GPUArch::Turing;
    case 7:
      return GPUArch::Ampere;
    case 9:
      return GPUArch::Hopper;
    default:
      return GPUArch::Unknown;
  }
}

std::string NvidiaGPUImpl::get_uuid() {
  fDeviceGetUUID deviceGetUUID =
      (fDeviceGetUUID)dlsym(libHandle, "nvmlDeviceGetUUID");
  if (!deviceGetUUID) {
    return "";
  }
  char uuid[256] = {0};
  deviceGetUUID(device, uuid, 256);
  return std::string(uuid);
}

std::string NvidiaGPUImpl::get_vbios_version() {
  fDeviceGetVbiosVersion deviceGetVbiosVersion =
      (fDeviceGetVbiosVersion)dlsym(libHandle, "nvmlDeviceGetVbiosVersion");
  if (!deviceGetVbiosVersion) {
    return "";
  }
  char version[256] = {0};
  deviceGetVbiosVersion(device, version, 256);
  return std::string(version);
}

std::vector<uint8_t> NvidiaGPUImpl::get_attestation_cert_chain() {
  fDeviceGetConfComputeGpuCertificate deviceGetConfComputeGpuCertificate =
      (fDeviceGetConfComputeGpuCertificate)dlsym(
          libHandle,
          "nvmlDeviceGetConfComputeGpuCertificate");
  if (!deviceGetConfComputeGpuCertificate) {
    return {};
  }
  nvmlConfComputeGpuCertificate_t cert;
  std::memset(&cert, 0, sizeof(cert));
  deviceGetConfComputeGpuCertificate(device, &cert);
  std::vector<uint8_t> result;
  result.insert(result.end(),
                cert.attestationCertChain,
                cert.attestationCertChain + cert.attestationCertChainSize);
  return result;
}

std::vector<uint8_t> NvidiaGPUImpl::get_attestation_report(
    const std::vector<uint8_t> &nonce) {
  fDeviceGetConfComputeGpuAttestationReport
      deviceGetConfComputeGpuAttestationReport =
          (fDeviceGetConfComputeGpuAttestationReport)dlsym(
              libHandle,
              "nvmlDeviceGetConfComputeGpuAttestationReport");
  if (!deviceGetConfComputeGpuAttestationReport) {
    return {};
  }
  nvmlConfComputeGpuAttestationReport_t report;
  std::memset(&report, 0, sizeof(report));
  if (nonce.size() != NVML_CC_GPU_CEC_NONCE_SIZE) {
    return {};
  }
  std::memcpy(report.nonce, nonce.data(), nonce.size());
  deviceGetConfComputeGpuAttestationReport(device, &report);
  std::vector<uint8_t> result;
  result.insert(result.end(),
                report.attestationReport,
                report.attestationReport + report.attestationReportSize);
  return result;
}

std::unique_ptr<NvidiaPlatform> NvidiaPlatformImpl::create(
    const char *libPath) {
  auto result = std::unique_ptr<NvidiaPlatformImpl>(new NvidiaPlatformImpl());
  if (!result->loadNvmlLibrary(libPath)) {
    return nullptr;
  }
  return result;
}

std::string NvidiaPlatformImpl::get_driver_version() {
  return driver_version;
}

bool NvidiaPlatformImpl::is_cc_enabled() {
  // TBD
  return true;
}

int NvidiaPlatformImpl::get_num_gpus() {
  return gpus.size();
}

NvidiaGPU *NvidiaPlatformImpl::get_gpu(int index) {
  if (index < (int)gpus.size()) {
    return &gpus[index];
  }
  return nullptr;
}

bool NvidiaPlatformImpl::loadNvmlLibrary(const char *libPath) {
  libHandle = dlopen(libPath, RTLD_NOW | RTLD_GLOBAL);
  if (!libHandle) {
    return false;
  }
  fInit init = (fInit)dlsym(libHandle, "nvmlInit");
  if (!init) {
    return false;
  }
  // init the nvml library
  if (init() != 0) {
    return false;
  }
  // get the driver version
  fSystemGetDriverVersion systemGetDriverVersion =
      (fSystemGetDriverVersion)dlsym(libHandle, "nvmlSystemGetDriverVersion");
  if (!systemGetDriverVersion) {
    return false;
  }
  char version[256] = {0};
  if (systemGetDriverVersion(version, 256) != 0) {
    return false;
  }
  driver_version = std::string(version);
  // get the number of devices
  fDeviceGetCount deviceGetCount =
      (fDeviceGetCount)dlsym(libHandle, "nvmlDeviceGetCount");
  if (!deviceGetCount) {
    return false;
  }
  unsigned int deviceCount = 0;
  deviceGetCount(&deviceCount);
  // get the device handles
  fDeviceGetHandleByIndex deviceGetHandleByIndex =
      (fDeviceGetHandleByIndex)dlsym(libHandle, "nvmlDeviceGetHandleByIndex");
  if (!deviceGetHandleByIndex) {
    return false;
  }
  for (int i = 0; i < (int)deviceCount; i++) {
    nvmlDevice_t device;
    if (deviceGetHandleByIndex(i, &device) != 0) {
      return false;
    }
    NvidiaGPUImpl gpu(libHandle, device);
    gpus.push_back(gpu);
  }
  return true;
}
