# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

add_library(mvfst_mock_socket STATIC
  MockQuicSocket.h
  MockQuicStats.h
  Mocks.h
)

target_include_directories(
  mvfst_mock_socket PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

add_dependencies(
  mvfst_mock_socket
  mvfst_exception
  mvfst_transport
  mvfst_codec_types
  mvfst_server
  mvfst_state_machine
  mvfst_state_stats_callback
)

target_link_libraries(
  mvfst_mock_socket PUBLIC
  Folly::folly
  mvfst_exception
  mvfst_transport
  mvfst_codec_types
  mvfst_server
  mvfst_state_machine
  mvfst_state_stats_callback
  ${LIBGMOCK_LIBRARIES}
)

quic_add_test(TARGET QuicTransportTest
  SOURCES
  QuicTransportTest.cpp
  DEPENDS
  Folly::folly
  mvfst_transport
  mvfst_mock_socket
  mvfst_mock_state
  mvfst_server
  mvfst_state_stream_functions
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicTransportBaseTest
  SOURCES
  QuicTransportBaseTest.cpp
  DEPENDS
  Folly::folly
  mvfst_transport
  mvfst_mock_socket
  mvfst_mock_state
  mvfst_codec_types
  mvfst_test_utils
  mvfst_state_stream_functions
  mvfst_server
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicTransportFunctionsTest
  SOURCES
  QuicTransportFunctionsTest.cpp
  DEPENDS
  Folly::folly
  mvfst_transport
  mvfst_mock_socket
  mvfst_mock_state
  mvfst_test_utils
  mvfst_server
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET QuicPacketSchedulerTest
  SOURCES
  QuicPacketSchedulerTest.cpp
  DEPENDS
  Folly::folly
  mvfst_client
  mvfst_codec_pktbuilder
  mvfst_transport
  mvfst_mock_socket
  mvfst_test_utils
  mvfst_server
  ${LIBGTEST_LIBRARY}
)

quic_add_test(TARGET IoBufQuicBatchTest
  SOURCES
  IoBufQuicBatchTest.cpp
  DEPENDS
  Folly::folly
  mvfst_transport
  mvfst_state_machine
)

quic_add_test(TARGET QuicBatchWriterTest
  SOURCES
  QuicBatchWriterTest.cpp
  DEPENDS
  Folly::folly
  mvfst_transport
)
