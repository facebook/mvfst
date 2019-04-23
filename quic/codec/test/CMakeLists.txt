# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

add_library(mvfst_mock_codec STATIC
  Mocks.h
)

target_include_directories(
  mvfst_mock_codec PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

add_dependencies(
  mvfst_mock_codec
  mvfst_codec_pktbuilder
  mvfst_test_utils
)

target_link_libraries(
  mvfst_mock_codec PUBLIC
  Folly::folly
  mvfst_codec_pktbuilder
  mvfst_test_utils
)

quic_add_test(TARGET QuicHeaderCodecTest
  SOURCES
  QuicHeaderCodecTest.cpp
  DEPENDS
  Folly::folly
  mvfst_exception
  mvfst_codec
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicReadCodecTest
  SOURCES
  QuicReadCodecTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec
  mvfst_exception
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicWriteCodecTest
  SOURCES
  QuicWriteCodecTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec
  mvfst_codec_decode
  mvfst_codec_types
  mvfst_exception
  mvfst_mock_codec
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicTypesTest
  SOURCES
  TypesTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec_decode
  mvfst_codec_types
  mvfst_exception
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET PacketNumberTest
  SOURCES
  PacketNumberTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec_types
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET PacketNumberCipherTest
  SOURCES
  PacketNumberCipherTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec_packet_number_cipher
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET DecodeTest
  SOURCES
  DecodeTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec
  mvfst_codec_decode
  mvfst_codec_types
  mvfst_exception
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicConnectionIdTest
  SOURCES
  QuicConnectionIdTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec_types
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicPacketBuilderTest
  SOURCES
  QuicPacketBuilderTest.cpp
  QuicPacketRebuilderTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec
  mvfst_codec_pktbuilder
  mvfst_codec_pktrebuilder
  mvfst_codec_types
  mvfst_handshake
  mvfst_mock_codec
  mvfst_server
  mvfst_state_functions
  mvfst_state_machine
  mvfst_state_stream_functions
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)


quic_add_test(TARGET QuicIntegerTest
  SOURCES
  QuicIntegerTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec_types
  mvfst_exception
  ${LIBGTEST_LIBRARY}
)
