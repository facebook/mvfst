# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# Always install this header, even when not building tests.
# It can be used by dependent projects to build their own tests
install(FILES MockQuicSocket.h Mocks.h DESTINATION include/quic/api/test)

# Header-only mocks library for downstream test projects
mvfst_add_library(mvfst_api_test_mocks
  EXPORTED_DEPS
    mvfst_api_loop_detector_callback
    mvfst_api_quic_callbacks
    mvfst_api_transport
    mvfst_codec_types
    mvfst_common_events_folly_eventbase
    mvfst_common_events_quic_timer
    mvfst_common_network_data
    mvfst_exception
    mvfst_server_server
    mvfst_state_quic_state_machine
    Folly::folly_io_async_async_base
    ${LIBGMOCK_LIBRARY}
)

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET QuicTransportTest
  SOURCES
  QuicTransportTest.cpp
  DEPENDS
  Folly::folly
  mvfst_common_buf_util
  mvfst_common_events_eventbase
  mvfst_congestion_control_static_cwnd_congestion_controller
  mvfst_api_transport
  mvfst_server_server
  mvfst_state_stream_functions
  mvfst_test_utils
)

quic_add_test(TARGET QuicTransportBaseTest
  SOURCES
  QuicTransportBaseTest.cpp
  DEPENDS
  Folly::folly
  mvfst_api_transport
  mvfst_codec_types
  mvfst_folly_utils
  mvfst_test_utils
  mvfst_state_stream_functions
  mvfst_server_server
)

quic_add_test(TARGET QuicTransportFunctionsTest
  SOURCES
  QuicTransportFunctionsTest.cpp
  DEPENDS
  Folly::folly
  mvfst_api_transport
  mvfst_test_utils
  mvfst_server_server
  mvfst_logging_file_qlogger
)

quic_add_test(TARGET QuicPacketSchedulerTest
  SOURCES
  QuicPacketSchedulerTest.cpp
  DEPENDS
  Folly::folly
  mvfst_fizz_client_handshake
  mvfst_server_server
  mvfst_codec_pktbuilder
  mvfst_api_transport
  mvfst_test_utils
)

quic_add_test(TARGET IoBufQuicBatchTest
  SOURCES
  IoBufQuicBatchTest.cpp
  DEPENDS
  Folly::folly
  mvfst_fizz_client_handshake
  mvfst_test_utils
  mvfst_api_transport
  mvfst_state_quic_state_machine
)

quic_add_test(TARGET QuicBatchWriterTest
  SOURCES
  QuicBatchWriterTest.cpp
  DEPENDS
  Folly::folly
  mvfst_common_buf_accessor
  mvfst_server_server
  mvfst_api_transport
  mvfst_test_utils
)

quic_add_test(TARGET QuicStreamAsyncTransportTest
  SOURCES
  QuicStreamAsyncTransportTest.cpp
  DEPENDS
  Folly::folly
  mvfst_api_stream_async_transport
  mvfst_common_buf_accessor
  mvfst_client_client
  mvfst_server_server
  mvfst_test_utils
  mvfst_api_transport
)
