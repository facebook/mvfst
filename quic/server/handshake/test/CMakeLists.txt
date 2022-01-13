# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET ServerHandshakeTest
  SOURCES
  AppTokenTest.cpp
  DefaultAppTokenValidatorTest.cpp
  RetryTokenGeneratorTest.cpp
  ServerHandshakeTest.cpp
  ServerTransportParametersTest.cpp
  StatelessResetGeneratorTest.cpp
  DEPENDS
  Folly::folly
  ${LIBFIZZ_LIBRARY}
  mvfst_client
  mvfst_codec_types
  mvfst_constants
  mvfst_handshake
  mvfst_server
  mvfst_state_machine
  mvfst_test_utils
)
