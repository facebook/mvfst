# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET SocketObserverInterfaceTest
  SOURCES
  SocketObserverInterfaceTest.cpp
  DEPENDS
  Folly::folly
  mvfst_observer_socket_observer_container
  mvfst_constants
  mvfst_exception
  mvfst_state_ack_handler
  mvfst_state_quic_state_machine
  mvfst_test_utils
)
