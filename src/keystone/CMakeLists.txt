cmake_minimum_required(VERSION 3.10)
project(certifier-keystone)

set(KEYSTONE_SDK_DIR "/keystone/sdk/build64")
set(KEYSTONE_EYRIE_RUNTIME "/keystone/runtime")
set(KEYSTONE_EAPP_BIN "keystone_app.exe")

include(${KEYSTONE_SDK_DIR}/cmake/macros.cmake)

find_program(MAKESELF makeself)
use_riscv_toolchain(64)

get_filename_component(eapp_bin ${KEYSTONE_EAPP_BIN} NAME)
set(host_bin runner)
set(host_src host/host.cpp)
set(package_name "certifier.ke")
set(package_script "./runner keystone_app.exe eyrie-rt")

if(RISCV32)
  set(eyrie_plugins "freemem io_syscall linux_syscall env_setup rv32")
else()
  set(eyrie_plugins "freemem io_syscall linux_syscall env_setup")
endif()

# host

add_executable(${host_bin} ${host_src})
include_directories(${KEYSTONE_SDK_DIR}/include)
target_link_libraries(${host_bin} ${KEYSTONE_SDK_DIR}/lib/libkeystone-host.a ${KEYSTONE_SDK_DIR}/lib/libkeystone-edge.a)

# add target for Eyrie runtime (see keystone.cmake)

set(eyrie_files_to_copy .options_log eyrie-rt)
add_eyrie_runtime(${eapp_bin}-eyrie
  ${eyrie_plugins}
  ${eyrie_files_to_copy})

# add target for packaging (see keystone.cmake)

add_keystone_package(${eapp_bin}-package
  ${package_name}
  ${package_script}
  ${eyrie_files_to_copy} ${eapp_bin} ${host_bin})

add_dependencies(${eapp_bin}-package ${eapp_bin}-eyrie)
