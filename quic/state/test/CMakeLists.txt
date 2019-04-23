# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

add_library(mvfst_mock_state STATIC
  Mocks.h
)

target_include_directories(
  mvfst_mock_state PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

add_dependencies(
  mvfst_mock_state
  mvfst_constants
)

target_link_libraries(
  mvfst_mock_state PUBLIC
  mvfst_constants
)

quic_add_test(TARGET StateMachineTest
  SOURCES
  StateMachineTest.cpp
  StateDataTest.cpp
  DEPENDS
  Folly::folly
  mvfst_state_machine
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicStreamFunctionsTest
  SOURCES
  QuicStreamFunctionsTest.cpp
  DEPENDS
  mvfst_client
  mvfst_server
  mvfst_state_stream_functions
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET AckHandlersTest
  SOURCES
  AckHandlersTest.cpp
  DEPENDS
  mvfst_mock_socket
  mvfst_server
  mvfst_state_machine
  mvfst_state_ack_handler
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicStateFunctionsTest
  SOURCES
  QuicStateFunctionsTest.cpp
  DEPENDS
  mvfst_mock_state
  mvfst_server
  mvfst_test_utils
  mvfst_state_functions
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicPacingFunctionsTest
  SOURCES
  QuicPacingFunctionsTest.cpp
  DEPENDS
  mvfst_state_pacing_functions
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QPRFunctionsTest
  SOURCES
  QPRFunctionsTest.cpp
  DEPENDS
  mvfst_server
  mvfst_state_qpr_functions
  ${LIBGTEST_LIBRARY}
)
