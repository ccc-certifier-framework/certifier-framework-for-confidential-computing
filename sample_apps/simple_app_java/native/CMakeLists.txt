cmake_minimum_required(VERSION 3.16)
project(certifier_jni LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Read env vars written by native/detect_paths.sh
set(CERTIFIER_INC1 $ENV{CERTIFIER_INC1})
set(CERTIFIER_INC2 $ENV{CERTIFIER_INC2})
set(CERTIFIER_INC3 $ENV{CERTIFIER_INC3})
set(JNI_INC1       $ENV{JNI_INC1})
set(JNI_INC2       $ENV{JNI_INC2})
set(CERTIFIER_LIBDIR $ENV{CERTIFIER_LIBDIR})

message(STATUS "CERTIFIER_INC1=${CERTIFIER_INC1}")
message(STATUS "CERTIFIER_INC2=${CERTIFIER_INC2}")
message(STATUS "CERTIFIER_INC3=${CERTIFIER_INC3}")
message(STATUS "JNI_INC1=${JNI_INC1}")
message(STATUS "JNI_INC2=${JNI_INC2}")
message(STATUS "CERTIFIER_LIBDIR=${CERTIFIER_LIBDIR}")

# Includes
include_directories(${JNI_INC1} ${JNI_INC2})
if (EXISTS "${CERTIFIER_INC1}") include_directories(${CERTIFIER_INC1}) endif()
if (EXISTS "${CERTIFIER_INC2}") include_directories(${CERTIFIER_INC2}) endif()
if (EXISTS "${CERTIFIER_INC3}") include_directories(${CERTIFIER_INC3}) endif()

# SWIG-generated sources (must exist already)
set(SWIG_WRAP_SOURCES)
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/trust_manager_wrap.cxx")
  list(APPEND SWIG_WRAP_SOURCES trust_manager_wrap.cxx)
endif()
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/secure_authenticated_channel_wrap.cxx")
  list(APPEND SWIG_WRAP_SOURCES secure_authenticated_channel_wrap.cxx)
endif()
if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/store_wrap.cxx")
  list(APPEND SWIG_WRAP_SOURCES store_wrap.cxx)
endif()

add_library(certifier_jni SHARED
  cf_shims.cc
  ${SWIG_WRAP_SOURCES}
)

# Where to find native libs
if (EXISTS "${CERTIFIER_LIBDIR}")
  link_directories(${CERTIFIER_LIBDIR})
endif()

# ---- Link libraries ----
# Adjust the certifier lib names below to match what's in ${CERTIFIER_LIBDIR}.
# Run:  ls -1 ${CERTIFIER_LIBDIR}/lib*
target_link_libraries(certifier_jni PRIVATE
  trust_manager
  secure_authenticated_channel
  certifier_core
)

# System/3rd-party libs
if(APPLE)
  target_link_libraries(certifier_jni PRIVATE ssl crypto protobuf)
elseif(UNIX)
  target_link_libraries(certifier_jni PRIVATE ssl crypto protobuf pthread dl)
elseif(WIN32)
  target_link_libraries(certifier_jni PRIVATE ws2_32 bcrypt)
endif()

set_target_properties(certifier_jni PROPERTIES OUTPUT_NAME "certifier_jni")
