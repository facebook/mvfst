# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET ClientHandshakeTest
  SOURCES
  FizzClientHandshakeTest.cpp
  FizzClientExtensionsTest.cpp
  DEPENDS
  mvfst_fizz_client
  mvfst_codec_types
  mvfst_constants
  mvfst_server
  mvfst_test_utils
)
