# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

add_library(mvfst_cubic_test_utils STATIC
  TestingCubic.h
)

target_include_directories(
  mvfst_cubic_test_utils PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

add_dependencies(
  mvfst_cubic_test_utils
  mvfst_cc_algo
)

target_link_libraries(
  mvfst_cubic_test_utils PUBLIC
  Folly::folly
  mvfst_cc_algo
)

quic_add_test(TARGET CongestionControllerTests
  SOURCES
  CongestionControlFunctionsTest.cpp
  CubicHystartTest.cpp
  CubicRecoveryTest.cpp
  CubicStateTest.cpp
  CubicSteadyTest.cpp
  CubicTest.cpp
  NewRenoTest.cpp
  CopaTest.cpp
  DEPENDS
  Folly::folly
  mvfst_cc_algo
  mvfst_cubic_test_utils
  mvfst_test_utils
  ${LIBGTEST_LIBRARY}
)
