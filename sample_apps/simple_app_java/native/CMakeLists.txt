cmake_minimum_required(VERSION 3.16)
project(certifier_jni)

# Options: adjust to your paths
set(JAVA_HOME $ENV{JAVA_HOME})
find_package(Java REQUIRED)
find_package(JNI REQUIRED)

include_directories(${JNI_INCLUDE_DIRS})
include_directories(${JAVA_INCLUDE_PATH})
# TODO adjust to your certifier include roots:
include_directories(${CMAKE_SOURCE_DIR}/../third_party/include)
include_directories(${CMAKE_SOURCE_DIR}/../)  # repo root if needed

# SWIG generated sources (you'll generate these .cxx files before building)
# e.g., swig -c++ -java trust_manager.i
set(SWIG_OUT
  trust_manager_wrap.cxx
  secure_authenticated_channel_wrap.cxx
  store_wrap.cxx
)

add_library(certifier_jni SHARED
  cf_shims.cc
  ${SWIG_OUT}
)

# TODO: link against your certifier libs (names invented here):
# target_link_libraries(certifier_jni PRIVATE certifier trust_manager secure_authenticated_channel store ssl crypto)

set_target_properties(certifier_jni PROPERTIES OUTPUT_NAME "certifier_jni")
