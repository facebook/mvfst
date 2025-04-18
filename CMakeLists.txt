# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

cmake_minimum_required(VERSION 3.10)

project(mvfst)

if (NOT DEFINED PACKAGE_VERSION)
  set(PACKAGE_VERSION "0")
endif()

if(NOT CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 17)
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

include(FBBuildOptions)
fb_activate_static_library_option()

# QUIC_FBCODE_ROOT is where the top level quic/ directory resides, so
# an #include <quic/path/to/file> will resolve to
# $QUIC_FBCODE_ROOT/quic/path/to/file on disk
set(QUIC_FBCODE_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

# Dependencies
find_package(Boost 1.62
  REQUIRED COMPONENTS
  iostreams
  system
  thread
  filesystem
  regex
  context
  date_time
  program_options
)
find_package(fmt REQUIRED)
find_package(folly REQUIRED)
find_package(Fizz REQUIRED)
find_package(Glog REQUIRED)
find_package(Threads)

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
endif()

SET(LIBFIZZ_LIBRARY ${FIZZ_LIBRARIES})
SET(LIBFIZZ_INCLUDE_DIR ${FIZZ_INCLUDE_DIR})
if(BUILD_TESTS)
  enable_testing()
  include(QuicTest)
endif()

add_subdirectory(quic)

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
