# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# Always install this header, even when not building tests.
# It can be used by dependent projects to build their own tests

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET PriorityQueueTest
  SOURCES
  PriorityQueueTest.cpp
  RoundRobinTests.cpp
  HTTPPriorityQueueTest.cpp
  DEPENDS
  Folly::folly
  mvfst_priority_round_robin
  mvfst_priority_http_priority_queue
)
