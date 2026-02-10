# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

cmake_minimum_required(VERSION 3.10)

project(mvfst)

# Set for FetchContent to skip find_package(mvfst)
set(mvfst_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}"
  CACHE INTERNAL "mvfst source directory")

if (NOT DEFINED PACKAGE_VERSION)
  set(PACKAGE_VERSION "0")
endif()

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
  message(STATUS "setting C++ standard to C++${CMAKE_CXX_STANDARD}")
endif()

set(CMAKE_MODULE_PATH
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
  # for in-fbsource builds
  "${CMAKE_CURRENT_SOURCE_DIR}/opensource/fbcode_builder/CMake"
  # For shipit-transformed builds
  "${CMAKE_CURRENT_SOURCE_DIR}/build/fbcode_builder/CMake"
  ${CMAKE_MODULE_PATH})

if (NOT DEFINED CMAKE_INSTALL_LIBDIR)
  set(CMAKE_INSTALL_LIBDIR "lib")
endif()
set(CMAKE_INSTALL_MODULE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/mvfst CACHE STRING
    "The subdirectory where CMake module files should be installed")
set(INCLUDE_INSTALL_DIR include CACHE STRING
    "The subdirectory where header files should be installed")

include(FBBuildOptions)
fb_activate_static_library_option()

# QUIC_FBCODE_ROOT is where the top level quic/ directory resides, so
# an #include <quic/path/to/file> will resolve to
# $QUIC_FBCODE_ROOT/quic/path/to/file on disk
set(QUIC_FBCODE_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

# Dependencies
# Boost headers only (iterator_facade.hpp in QuicPacketScheduler.h)
find_package(Boost 1.69 REQUIRED)
find_package(fmt REQUIRED)
# If folly/fizz are being built from source (FetchContent), skip find_package
if (NOT DEFINED folly_SOURCE_DIR)
  find_package(folly REQUIRED)
endif()
if (NOT DEFINED fizz_SOURCE_DIR)
  find_package(Fizz REQUIRED)
endif()
find_package(Glog REQUIRED)
add_compile_definitions(GLOG_USE_GLOG_EXPORT)
find_package(Threads)
find_package(OpenSSL REQUIRED)

SET(GFLAG_DEPENDENCIES "")
SET(QUIC_EXTRA_LINK_LIBRARIES "")
SET(QUIC_EXTRA_INCLUDE_DIRECTORIES "")

find_package(gflags CONFIG QUIET)
if (gflags_FOUND)
  message(STATUS "Found gflags from package config")
  if (TARGET gflags-shared)
    list(APPEND GFLAG_DEPENDENCIES gflags-shared)
  elseif (TARGET gflags)
    list(APPEND GFLAG_DEPENDENCIES gflags)
  else()
    message(FATAL_ERROR "Unable to determine the target name for the GFlags package.")
  endif()
  list(APPEND CMAKE_REQUIRED_LIBRARIES ${GFLAGS_LIBRARIES})
  list(APPEND CMAKE_REQUIRED_INCLUDES ${GFLAGS_INCLUDE_DIR})
else()
  find_package(Gflags REQUIRED MODULE)
  list(APPEND QUIC_EXTRA_LINK_LIBRARIES ${LIBGFLAGS_LIBRARY})
  list(APPEND QUIC_EXTRA_INCLUDE_DIRECTORIES ${LIBGFLAGS_INCLUDE_DIR})
  list(APPEND CMAKE_REQUIRED_LIBRARIES ${LIBGFLAGS_LIBRARY})
  list(APPEND CMAKE_REQUIRED_INCLUDES ${LIBGFLAGS_INCLUDE_DIR})
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
list(APPEND
  _QUIC_BASE_COMPILE_OPTIONS
  -Wall
  -Wextra
)
endif()

list(APPEND
  _QUIC_COMMON_COMPILE_OPTIONS
  ${_QUIC_BASE_COMPILE_OPTIONS}
)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND
    _QUIC_COMMON_COMPILE_OPTIONS
    -Woverloaded-virtual
    -Wnon-virtual-dtor
    -Wtype-limits
    -Wunused-value
  )
else()
  # MSVC: Enable conforming preprocessor for __VA_OPT__ support and extended
  # alignment storage for std::aligned_storage with Align > alignof(max_align_t)
  list(APPEND
    _QUIC_COMMON_COMPILE_OPTIONS
    /Zc:preprocessor
  )
  add_compile_definitions(_ENABLE_EXTENDED_ALIGNED_STORAGE)
endif()

SET(LIBFIZZ_LIBRARY ${FIZZ_LIBRARIES})
SET(LIBFIZZ_INCLUDE_DIR ${FIZZ_INCLUDE_DIR})

# =============================================================================
# Granular CMake targets
# =============================================================================

# Include mvfst functions for granular library targets
include(MvfstFunctions)

if(BUILD_TESTS)
  enable_testing()
  include(QuicTest)
endif()

add_subdirectory(quic)

# Create the monolithic mvfst library for backward compatibility
mvfst_create_monolithic_library()

# Resolve deferred dependencies between mvfst targets
mvfst_resolve_deferred_dependencies()

# =============================================================================
# Backwards compatibility aliases
# =============================================================================
# Manually maintained in cmake/MvfstCompatAliases.cmake
include(MvfstCompatAliases)

# =============================================================================
# Header installation
# =============================================================================

# Collect all headers (.h and .hpp), excluding test/facebook/build directories
file(GLOB_RECURSE MVFST_HEADERS
  "${CMAKE_CURRENT_SOURCE_DIR}/quic/*.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/quic/*.hpp"
)
list(FILTER MVFST_HEADERS EXCLUDE REGEX "/test/")
list(FILTER MVFST_HEADERS EXCLUDE REGEX "/facebook/")
list(FILTER MVFST_HEADERS EXCLUDE REGEX "/build/")

# Install headers preserving directory structure
mvfst_install_headers(quic ${CMAKE_CURRENT_SOURCE_DIR}/quic ${MVFST_HEADERS})

# =============================================================================
# Install and export configuration
# =============================================================================

install(
  TARGETS mvfst
  EXPORT mvfst-exports
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  EXPORT mvfst-exports
  FILE mvfst-targets.cmake
  NAMESPACE mvfst::
  DESTINATION ${CMAKE_INSTALL_MODULE_DIR}
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  cmake/mvfst-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/mvfst-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_MODULE_DIR}
)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/mvfst-config.cmake
  DESTINATION ${CMAKE_INSTALL_MODULE_DIR}
)
