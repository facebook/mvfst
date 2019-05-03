# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

add_library(quic_mock_handshake STATIC
  Mocks.h
)

target_include_directories(
  quic_mock_handshake PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

target_link_libraries(
  quic_mock_handshake PUBLIC
  Folly::folly
  ${LIBGMOCK_LIBRARIES}
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET TransportParametersTest
  SOURCES
  TransportParametersTest.cpp
  DEPENDS
  Folly::folly
  mvfst_handshake
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET HandshakeLayerTest
  SOURCES
  HandshakeLayerTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec_types
  mvfst_handshake
  quic_mock_handshake
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)
