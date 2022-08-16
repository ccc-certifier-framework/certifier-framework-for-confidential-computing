# Install script for directory: /home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xlibassimp5.2.0-devx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/build/assimp/lib/libassimp.a")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xassimp-devx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/assimp" TYPE FILE FILES
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/anim.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/aabb.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/ai_assert.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/camera.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/color4.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/color4.inl"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/build/assimp/code/../include/assimp/config.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/ColladaMetaData.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/commonMetaData.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/defs.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/cfileio.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/light.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/material.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/material.inl"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/matrix3x3.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/matrix3x3.inl"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/matrix4x4.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/matrix4x4.inl"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/mesh.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/ObjMaterial.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/pbrmaterial.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/GltfMaterial.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/postprocess.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/quaternion.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/quaternion.inl"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/scene.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/metadata.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/texture.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/types.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/vector2.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/vector2.inl"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/vector3.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/vector3.inl"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/version.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/cimport.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/importerdesc.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Importer.hpp"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/DefaultLogger.hpp"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/ProgressHandler.hpp"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/IOStream.hpp"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/IOSystem.hpp"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Logger.hpp"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/LogStream.hpp"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/NullLogger.hpp"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/cexport.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Exporter.hpp"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/DefaultIOStream.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/DefaultIOSystem.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/ZipArchiveIOSystem.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/SceneCombiner.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/fast_atof.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/qnan.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/BaseImporter.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Hash.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/MemoryIOWrapper.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/ParsingUtils.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/StreamReader.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/StreamWriter.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/StringComparison.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/StringUtils.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/SGSpatialSort.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/GenericProperty.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/SpatialSort.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/SkeletonMeshBuilder.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/SmallVector.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/SmoothingGroups.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/SmoothingGroups.inl"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/StandardShapes.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/RemoveComments.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Subdivision.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Vertex.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/LineSplitter.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/TinyFormatter.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Profiler.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/LogAux.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Bitmap.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/XMLTools.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/IOStreamBuffer.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/CreateAnimMesh.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/XmlParser.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/BlobIOSystem.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/MathFunctions.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Exceptional.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/ByteSwapper.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Base64.hpp"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xassimp-devx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/assimp/Compiler" TYPE FILE FILES
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Compiler/pushpack1.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Compiler/poppack1.h"
    "/home/azureuser/certifier-framework-for-confidential-computing/sample_apps/motion_planning/third_party/assimp/code/../include/assimp/Compiler/pstdint.h"
    )
endif()

