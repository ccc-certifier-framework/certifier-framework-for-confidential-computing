#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <string>
#include "nvidia_impl.h"

DEFINE_string(nvml_lib_path,
              "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.535.113.01",
              "nvml lib path");

bool test_load() {
  auto platform = NvidiaPlatformImpl::create(FLAGS_nvml_lib_path.c_str());
  return platform != nullptr;
}

int test_get_num_gpus() {
  auto platform = NvidiaPlatformImpl::create(FLAGS_nvml_lib_path.c_str());
  if (platform == nullptr) {
    return -1;
  }
  return platform->get_num_gpus();
}

std::string test_get_driver_version() {
  auto platform = NvidiaPlatformImpl::create(FLAGS_nvml_lib_path.c_str());
  if (platform == nullptr) {
    return "";
  }
  return platform->get_driver_version();
}

std::string test_get_vbios_version() {
  auto platform = NvidiaPlatformImpl::create(FLAGS_nvml_lib_path.c_str());
  if (platform == nullptr) {
    return "";
  }
  auto gpu = platform->get_gpu(0);
  if (gpu == nullptr) {
    return "";
  }
  return gpu->get_vbios_version();
}

GPUArch test_get_gpu_arch() {
  auto platform = NvidiaPlatformImpl::create(FLAGS_nvml_lib_path.c_str());
  if (platform == nullptr) {
    return GPUArch::Unknown;
  }
  auto gpu = platform->get_gpu(0);
  if (gpu == nullptr) {
    return GPUArch::Unknown;
  }
  return gpu->get_architecture();
}

std::string test_get_gpu_uuid() {
  auto platform = NvidiaPlatformImpl::create(FLAGS_nvml_lib_path.c_str());
  if (platform == nullptr) {
    return "";
  }
  auto gpu = platform->get_gpu(0);
  if (gpu == nullptr) {
    return "";
  }
  return gpu->get_uuid();
}

TEST(nvml, PlatformTests) {
  EXPECT_TRUE(test_load());
  EXPECT_EQ(test_get_num_gpus(), 1);
  EXPECT_EQ(test_get_driver_version(), "535.113.01");
}

TEST(nvml, GPUTests) {
  EXPECT_EQ(test_get_vbios_version(), "90.17.8D.00.FB");
  EXPECT_EQ(test_get_gpu_arch(), GPUArch::Turing);
  EXPECT_EQ(test_get_gpu_uuid(), "GPU-e0735ed5-ade6-97d0-a903-79fcf4ce31a3");
}

int main(int argc, char *argv[]) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  ::testing::InitGoogleTest();
  int result = RUN_ALL_TESTS();
  return result;
}