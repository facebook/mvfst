# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# Always install this header, even when not building tests.
# It can be used by dependent projects to build their own tests
install(FILES MockQuicSocket.h DESTINATION include/quic/api/test)

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET QuicTransportTest
  SOURCES
  QuicTransportTest.cpp
  DEPENDS
  Folly::folly
  mvfst_transport
  mvfst_server
  mvfst_state_stream_functions
  mvfst_test_utils
)

quic_add_test(TARGET QuicTransportBaseTest
  SOURCES
  QuicTransportBaseTest.cpp
  DEPENDS
  Folly::folly
  mvfst_transport
  mvfst_codec_types
  mvfst_test_utils
  mvfst_state_stream_functions
  mvfst_server
)

quic_add_test(TARGET QuicTransportFunctionsTest
  SOURCES
  QuicTransportFunctionsTest.cpp
  DEPENDS
  Folly::folly
  mvfst_transport
  mvfst_test_utils
  mvfst_server
)

quic_add_test(TARGET QuicPacketSchedulerTest
  SOURCES
  QuicPacketSchedulerTest.cpp
  DEPENDS
  Folly::folly
  mvfst_client
  mvfst_codec_pktbuilder
  mvfst_transport
  mvfst_test_utils
  mvfst_server
)

quic_add_test(TARGET IoBufQuicBatchTest
  SOURCES
  IoBufQuicBatchTest.cpp
  DEPENDS
  Folly::folly
  mvfst_client
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
