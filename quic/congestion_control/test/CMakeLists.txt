# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

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
  mvfst_test_utils
)
