# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET DatagramFlowManagerTest
  SOURCES
  DatagramFlowManagerTest.cpp
  DEPENDS
  Folly::folly
  mvfst_datagram_datagram_flow_manager
  mvfst_priority_http_priority_queue
)
