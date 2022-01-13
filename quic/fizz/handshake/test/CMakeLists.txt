# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET FizzTransportParametersTest
  SOURCES
  FizzTransportParametersTest.cpp
  DEPENDS
  Folly::folly
  mvfst_handshake
  mvfst_test_utils
)

quic_add_test(TARGET FizzCryptoFactoryTest
  SOURCES
  FizzCryptoFactoryTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec_types
  mvfst_fizz_handshake
  mvfst_test_utils
)

quic_add_test(TARGET FizzPacketNumberCipherTest
  SOURCES
  FizzPacketNumberCipherTest.cpp
  DEPENDS
  Folly::folly
  mvfst_fizz_handshake
  mvfst_codec_packet_number_cipher
)
