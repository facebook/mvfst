# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET CongestionControllerTests
  SOURCES
  BandwidthTest.cpp
  BbrBandwidthSamplerTest.cpp
  BbrRttSamplerTest.cpp
  BbrTest.cpp
  Bbr2Test.cpp
  CongestionControlFunctionsTest.cpp
  CopaTest.cpp
  CubicHystartTest.cpp
  CubicRecoveryTest.cpp
  CubicStateTest.cpp
  CubicSteadyTest.cpp
  CubicTest.cpp
  NewRenoTest.cpp
  PacerTest.cpp
  SimulatedTBFTest.cpp
  ThrottlingSignalProviderTest.cpp
  DEPENDS
  Folly::folly
  mvfst_cc_algo
  mvfst_test_utils
)
