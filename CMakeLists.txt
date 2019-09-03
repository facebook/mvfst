# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

cmake_minimum_required(VERSION 3.10)

project(
  mvfst
)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

# QUIC_FBCODE_ROOT is where the top level quic/ directory resides, so
# an #include <quic/path/to/file> will resolve to
# $QUIC_FBCODE_ROOT/quic/path/to/file on disk
set(QUIC_FBCODE_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

option(BUILD_SHARED_LIBS
  "If enabled, build mvfst as a shared library.  \
  This is generally discouraged, since mvfst does not commit to having \
  a stable ABI."
  OFF
)
# Mark BUILD_SHARED_LIBS as an "advanced" option, since enabling it
# is generally discouraged.
mark_as_advanced(BUILD_SHARED_LIBS)

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

list(APPEND
  _QUIC_BASE_COMPILE_OPTIONS
  -std=c++14
  -Wall
  -Wextra
)

list(APPEND
  _QUIC_COMMON_COMPILE_OPTIONS
  ${_QUIC_BASE_COMPILE_OPTIONS}
  # more strict options
  -Werror=sign-compare
  -Werror=unused-variable
  -Woverloaded-virtual
  -Wnon-virtual-dtor
)

# Not all compilers support -Werror=bool-compare
# (e.g., Apple LLVM version 10.0.1 (clang-1001.0.46.4) on MacOS Mojave 10.14.x)
include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-Werror=bool-compare COMPILER_HAS_ERROR_BOOL_COMPARE)
if (COMPILER_HAS_ERROR_BOOL_COMPARE)
  list(APPEND
    _QUIC_COMMON_COMPILE_OPTIONS
    -Werror=bool-compare
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
  DESTINATION lib/cmake/mvfst/
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  cmake/mvfst-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/mvfst-config.cmake
  INSTALL_DESTINATION lib/cmake/mvfst/
)
install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/mvfst-config.cmake
  DESTINATION lib/cmake/mvfst/
)
