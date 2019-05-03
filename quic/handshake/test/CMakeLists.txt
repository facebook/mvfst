# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

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
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)
