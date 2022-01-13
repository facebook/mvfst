# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET StreamStateMachineTest
  SOURCES
  StreamStateMachineTest.cpp
  StreamStateFunctionsTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec_types
  mvfst_server
  mvfst_state_stream
  mvfst_state_stream_functions
  mvfst_test_utils
  mvfst_transport
)
