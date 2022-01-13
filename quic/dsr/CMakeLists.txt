# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_dsr_sender INTERFACE
)

target_include_directories(
  mvfst_dsr_sender INTERFACE
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

add_library(
  mvfst_dsr_types
  Types.cpp
)

target_include_directories(
  mvfst_dsr_types PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

add_dependencies(
  mvfst_dsr_types
  mvfst_codec_types
)

target_link_libraries(
  mvfst_dsr_types PUBLIC
  Folly::folly
  mvfst_codec_types
)

target_compile_options(
  mvfst_dsr_types
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_library(
  mvfst_dsr_frontend
  frontend/Scheduler.cpp
  frontend/WriteCodec.cpp
  frontend/WriteFunctions.cpp)

target_include_directories(
  mvfst_dsr_frontend PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

add_dependencies(
  mvfst_dsr_frontend
  mvfst_dsr_types
  mvfst_flowcontrol
)

target_link_libraries(
  mvfst_dsr_frontend PUBLIC
  Folly::folly
  mvfst_codec_types
  mvfst_dsr_types
)

target_compile_options(
  mvfst_dsr_frontend
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_library(
  mvfst_dsr_backend
  backend/DSRPacketizer.cpp)

target_include_directories(
  mvfst_dsr_backend PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

add_dependencies(
  mvfst_dsr_backend
  mvfst_dsr_types
  mvfst_transport
)

target_link_libraries(
  mvfst_dsr_backend PUBLIC
  Folly::folly
  mvfst_codec_types
  mvfst_dsr_types
  mvfst_transport
)

target_compile_options(
  mvfst_dsr_frontend
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/dsr/${header_dir})
endforeach()

install(
  TARGETS mvfst_dsr_sender
  EXPORT mvfst-exports
)

install(
  TARGETS mvfst_dsr_types
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_dsr_frontend
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
