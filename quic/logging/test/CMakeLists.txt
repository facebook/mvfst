# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET MacroTest
  SOURCES
  QuicLoggingMacroTest.cpp
  DEPENDS
  Folly::folly
  ${LIBGTEST_LIBRARY}
  mvfst_state_functions
)
