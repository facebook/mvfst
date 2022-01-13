# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET QuicServerTest
  SOURCES
  QuicServerTest.cpp
  QuicSocketTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec
  mvfst_codec_types
  mvfst_server
  mvfst_test_utils
  mvfst_transport
)

quic_add_test(TARGET QuicServerTransportTest
  SOURCES
  QuicServerTransportTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec_pktbuilder
  mvfst_codec_types
  mvfst_server
  mvfst_state_stream_functions
  mvfst_test_utils
  mvfst_transport
)

quic_add_test(TARGET ServerStateMachineTest
  SOURCES
  ServerStateMachineTest.cpp
  DEPENDS
  Folly::folly
  mvfst_server
  mvfst_test_utils
)

quic_add_test(TARGET SlidingWindowRateLimiterTest
  SOURCES
  SlidingWindowRateLimiterTest.cpp
  DEPENDS
  Folly::folly
  mvfst_server
)
