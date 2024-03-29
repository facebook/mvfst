# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_fizz_handshake
  FizzBridge.cpp
  FizzCryptoFactory.cpp
  FizzPacketNumberCipher.cpp
  FizzRetryIntegrityTagGenerator.cpp
  QuicFizzFactory.cpp
)

set_property(TARGET mvfst_fizz_handshake PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_fizz_handshake PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<BUILD_INTERFACE:${LIBFIZZ_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_fizz_handshake
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_fizz_handshake
  ${LIBFIZZ_LIBRARY}
  mvfst_handshake
  mvfst_codec_packet_number_cipher
)

target_link_libraries(
  mvfst_fizz_handshake PUBLIC
  ${LIBFIZZ_LIBRARY}
  mvfst_handshake
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
  install(FILES ${header} DESTINATION include/quic/fizz/handshake/${header_dir})
endforeach()

install(
  TARGETS mvfst_fizz_handshake
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(test)
