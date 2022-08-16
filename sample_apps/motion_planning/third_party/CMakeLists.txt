# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

# If the CC environment variable has been specified or if the CMAKE_C_COMPILER
# cmake variable has been passed to cmake, use the C compiler that has been
# specified. Otherwise, prefer clang. Same for C++ compiler.
# This must be done before the `project` command.
if (UNIX)
  if (NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
    find_program(CMAKE_C_COMPILER clang-10 clang)
  endif ()
  if (NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(CMAKE_CXX_COMPILER clang++-10 clang++)
  endif ()
endif ()

project("Attestation Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

add_subdirectory(assimp)
add_subdirectory(libccd)
add_subdirectory(fcl)

find_package(Threads)
find_package(Eigen3 3.3 REQUIRED NO_MODULE)

# link_directories(${FCL_LIBRARY_DIRS} ${ASSIMP_LIBRARY_DIRS})
# include_directories(include ../nigh/src ${FCL_INCLUDE_DIRS} ${ASSIMP_INCLUDE_DIRS})
include_directories(include ../nigh/src)

# Create a library common to each of our two enclaves.
add_library(mpl STATIC 
            ${CMAKE_SOURCE_DIR}/mplambda/src/mpl/demo/lambda_common.cpp
           ${CMAKE_SOURCE_DIR}/mplambda/src/mpl/comm.cpp
           ${CMAKE_SOURCE_DIR}/mplambda/src/mpl/write_queue.cpp
           ${CMAKE_SOURCE_DIR}/mplambda/src/mpl/demo/app_options.cpp
           )

SET(LINK_SEARCH_START_STATIC TRUE)
target_link_libraries(
  mpl PUBLIC openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB}
    ${CMAKE_BINARY_DIR} Threads::Threads
    zlibstatic libassimp   fcl ccd 
    openenclave::oehostfs openenclave::oehostsock openenclave::oehostresolver
    ${CMAKE_SOURCE_DIR}/openlibm/libopenlibm.a openenclave::oelibc openenclave::oelibcxx )

target_include_directories(mpl PUBLIC ${CMAKE_SOURCE_DIR}
                                         ${CMAKE_BINARY_DIR}
                                         ${CMAKE_SOURCE_DIR}/mplambda/include
                                         ${CMAKE_SOURCE_DIR}/fcl/include
                                         ${CMAKE_SOURCE_DIR}/libccd/
                                         ${CMAKE_SOURCE_DIR}/assimp/include/
                                         ${CMAKE_SOURCE_DIR}/nigh/src/
                                        )
