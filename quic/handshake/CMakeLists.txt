# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_handshake STATIC
  HandshakeLayer.cpp
  QuicFizzFactory.cpp
  TransportParameters.cpp
)

target_include_directories(
  mvfst_handshake PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<BUILD_INTERFACE:${LIBFIZZ_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_handshake
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_handshake
  mvfst_constants
  mvfst_exception
  mvfst_codec_types
  mvfst_codec_packet_number_cipher
)

target_link_libraries(
  mvfst_handshake PUBLIC
  Folly::folly
  ${LIBFIZZ_LIBRARY}
  mvfst_constants
  mvfst_exception
  mvfst_codec_types
  mvfst_codec_packet_number_cipher
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/handshake/${header_dir})
endforeach()

install(
  TARGETS mvfst_handshake
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
