# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET ClientStateMachineTest
  SOURCES
  ClientStateMachineTest.cpp
  QuicClientTransportTest.cpp
  QuicClientTransportLiteTest.cpp
  QuicConnectorTest.cpp
  DEPENDS
  Folly::folly
  mvfst_client_client
  mvfst_client_connector
  mvfst_test_utils
)
