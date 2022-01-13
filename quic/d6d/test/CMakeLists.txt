# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET QuicD6DProbeSizeRaiserTest
  SOURCES
  ProbeSizeRaiserTest.cpp
  DEPENDS
  Folly::folly
  mvfst_d6d_probe_raiser
)

quic_add_test(TARGET QuicD6DStateFunctionTest
  SOURCES
  QuicD6DStateFunctionsTest.cpp
  DEPENDS
  Folly::folly
  mvfst_d6d_probe_raiser
  mvfst_d6d_state_functions
  mvfst_test_utils
)
