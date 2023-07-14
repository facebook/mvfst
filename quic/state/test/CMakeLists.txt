# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET StateMachineTest
  SOURCES
  StateDataTest.cpp
  DEPENDS
  Folly::folly
  mvfst_state_machine
  mvfst_test_utils
)

quic_add_test(TARGET QuicStreamFunctionsTest
  SOURCES
  QuicStreamFunctionsTest.cpp
  DEPENDS
  mvfst_client
  mvfst_server
  mvfst_state_stream_functions
  mvfst_test_utils
)

quic_add_test(TARGET QuicStreamManagerTest
  SOURCES
  QuicPriorityQueueTest.cpp
  QuicStreamManagerTest.cpp
  DEPENDS
  mvfst_client
  mvfst_server
  mvfst_state_stream_functions
  mvfst_test_utils
)

quic_add_test(TARGET AckHandlersTest
  SOURCES
  AckEventTestUtil.cpp
  AckHandlersTest.cpp
  DEPENDS
  mvfst_server
  mvfst_state_machine
  mvfst_state_ack_handler
  mvfst_test_utils
)

quic_add_test(TARGET OutstandingPacketTest
  SOURCES
  OutstandingPacketTest.cpp
  DEPENDS
  mvfst_test_utils
)

quic_add_test(TARGET QuicStateFunctionsTest
  SOURCES
  QuicStateFunctionsTest.cpp
  DEPENDS
  mvfst_server
  mvfst_test_utils
  mvfst_state_functions
)

quic_add_test(TARGET QuicPacingFunctionsTest
  SOURCES
  QuicPacingFunctionsTest.cpp
  DEPENDS
  mvfst_state_pacing_functions
)

quic_add_test(TARGET QuicTransportSettingsFunctionsTest
  SOURCES
  TransportSettingsFunctionsTest.cpp
  DEPENDS
  mvfst_test_utils
  mvfst_transport_settings_functions
)
