# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

add_library(
  mvfst_test_utils STATIC
  TestUtils.cpp
  AeadTestUtil.cpp
  CryptoTestUtil.cpp
)

target_include_directories(
  mvfst_test_utils PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${LIBFIZZ_INCLUDE_DIR}>
  ${LIBGMOCK_INCLUDE_DIR}
  ${LIBGTEST_INCLUDE_DIR}
)

target_compile_options(
  mvfst_test_utils
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_test_utils
  mvfst_client
  mvfst_codec_pktbuilder
  mvfst_codec_types
  mvfst_handshake
  mvfst_server
  mvfst_state_machine
  mvfst_transport
)

target_link_libraries(
  mvfst_test_utils PUBLIC
  Folly::folly
  ${LIBFIZZ_LIBRARY}
  ${LIBGMOCK_LIBRARIES}
  ${LIBGTEST_LIBRARIES}
  mvfst_client
  mvfst_codec_pktbuilder
  mvfst_codec_types
  mvfst_handshake
  mvfst_server
  mvfst_state_machine
  mvfst_transport
  PRIVATE
  ${BOOST_LIBRARIES}
)

quic_add_test(TARGET QuicCommonUtilTest SOURCES
  FunctionLooperTest.cpp
  QuicCodecUtilsTest.cpp
  TimeUtilTest.cpp
  IntervalSetTest.cpp
  DEPENDS
  Folly::folly
  ${LIBFIZZ_LIBRARY}
  mvfst_client
  mvfst_codec_pktbuilder
  mvfst_codec_types
  mvfst_handshake
  mvfst_looper
  mvfst_transport
  mvfst_server
  mvfst_state_machine
  mvfst_test_utils
  ${BOOST_LIBRARIES}
)
