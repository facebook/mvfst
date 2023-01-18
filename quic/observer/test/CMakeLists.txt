# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# Always install this header, even when not building tests.
# It can be used by dependent projects to build their own tests
install(FILES MockQuicSocket.h Mocks.h DESTINATION include/quic/api/test)

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET SocketObserverInterfaceTest
  SOURCES
  SocketObserverInterfaceTest.cpp
  DEPENDS
  Folly::folly
  mvfst_observer
  mvfst_constants
  mvfst_exception
  mvfst_state_ack_handler
  mvfst_state_machine
)
