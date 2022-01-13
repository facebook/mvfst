# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_codec_types STATIC
  DefaultConnectionIdAlgo.cpp
  PacketNumber.cpp
  QuicConnectionId.cpp
  QuicInteger.cpp
  Types.cpp
)

target_include_directories(
  mvfst_codec_types PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_codec_types
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_codec_types
  mvfst_constants
  mvfst_exception
)

target_link_libraries(
  mvfst_codec_types PUBLIC
  Folly::folly
  mvfst_bufutil
  mvfst_constants
  mvfst_exception
  PRIVATE
  ${Boost_LIBRARIES}
)

add_library(
  mvfst_codec_decode STATIC
  Decode.cpp
)

target_include_directories(
  mvfst_codec_decode PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_codec_decode
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_codec_decode
  mvfst_codec_types
  mvfst_exception
)

target_link_libraries(
  mvfst_codec_decode PUBLIC
  Folly::folly
  mvfst_codec_types
  mvfst_exception
)

add_library(
  mvfst_codec_packet_number_cipher STATIC
  PacketNumberCipher.cpp
)

target_include_directories(
  mvfst_codec_packet_number_cipher PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_codec_packet_number_cipher
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_codec_packet_number_cipher
  mvfst_codec_types
  mvfst_codec_decode
)

target_link_libraries(
  mvfst_codec_packet_number_cipher PUBLIC
  Folly::folly
  mvfst_codec_types
  mvfst_codec_decode
)

add_library(
  mvfst_codec_pktbuilder STATIC
  QuicPacketBuilder.cpp
)

target_include_directories(
  mvfst_codec_pktbuilder PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_codec_pktbuilder
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_codec_pktbuilder
  mvfst_codec_types
  mvfst_handshake
)

target_link_libraries(
  mvfst_codec_pktbuilder PUBLIC
  Folly::folly
  mvfst_codec_types
  mvfst_handshake
)

add_library(
  mvfst_codec_pktrebuilder STATIC
  QuicPacketRebuilder.cpp
)

target_include_directories(
  mvfst_codec_pktrebuilder PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_codec_pktrebuilder
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_codec_pktrebuilder
  mvfst_codec
  mvfst_codec_pktbuilder
  mvfst_flowcontrol
  mvfst_state_machine
  mvfst_state_simple_frame_functions
  mvfst_state_stream_functions
)

target_link_libraries(
  mvfst_codec_pktrebuilder PUBLIC
  Folly::folly
  mvfst_codec
  mvfst_codec_pktbuilder
  mvfst_flowcontrol
  mvfst_state_machine
  mvfst_state_simple_frame_functions
  mvfst_state_stream_functions
)

add_library(
  mvfst_codec STATIC
  QuicHeaderCodec.cpp
  QuicReadCodec.cpp
  QuicWriteCodec.cpp
)

target_include_directories(
  mvfst_codec PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_codec
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_codec
  mvfst_bufutil
  mvfst_constants
  mvfst_codec_decode
  mvfst_codec_types
  mvfst_codec_pktbuilder
  mvfst_exception
  mvfst_handshake
)

target_link_libraries(
  mvfst_codec PUBLIC
  Folly::folly
  mvfst_constants
  mvfst_codec_decode
  mvfst_codec_types
  mvfst_exception
  mvfst_handshake
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/codec/${header_dir})
endforeach()

install(
  TARGETS mvfst_codec_types
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_codec_decode
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_codec_pktbuilder
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_codec_pktrebuilder
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_codec_packet_number_cipher
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_codec
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
