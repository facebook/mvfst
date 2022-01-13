# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# Probe Raiser
add_library(
  mvfst_d6d_probe_raiser INTERFACE
)

target_include_directories(
  mvfst_d6d_probe_raiser INTERFACE
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

# State Functions
add_library(
  mvfst_d6d_state_functions STATIC
  QuicD6DStateFunctions.cpp
)

target_include_directories(
  mvfst_d6d_state_functions PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_d6d_state_functions
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_d6d_state_functions
  mvfst_state_machine
)

target_link_libraries(
  mvfst_d6d_state_functions PUBLIC
  Folly::folly
  mvfst_state_machine
)

# Types
add_library(
  mvfst_d6d_types STATIC
  Types.cpp
)

target_include_directories(
  mvfst_d6d_types PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_d6d_types
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_d6d_types
  mvfst_codec_types
)

target_link_libraries(
  mvfst_d6d_types PUBLIC
  Folly::folly
  mvfst_codec_types
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)

list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/d6d/${header_dir})
endforeach()

install(
  TARGETS mvfst_d6d_probe_raiser
  EXPORT mvfst-exports
)

install(
  TARGETS mvfst_d6d_state_functions
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_d6d_types
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
