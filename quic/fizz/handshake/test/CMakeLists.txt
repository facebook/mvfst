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

quic_add_test(TARGET ContiguousAeadTest
  SOURCES
  ContiguousAeadTest.cpp
  DEPENDS
  Folly::folly
  fizz::fizz
  mvfst_fizz_handshake
  mvfst_fizz_handshake_contiguous_aead
  mvfst_fizz_handshake_fizz_bridge
)

if(MVFST_USE_HABERDASHERY)
  quic_add_test(TARGET HaberdasheryAeadTest
    SOURCES
    HaberdasheryAeadTest.cpp
    DEPENDS
    Folly::folly
    fizz::fizz
    mvfst_fizz_handshake
    mvfst_fizz_handshake_fizz_bridge
    mvfst_fizz_handshake_haberdashery_aead
  )
endif()

quic_add_test(TARGET FizzCryptoFactoryTest
  SOURCES
  FizzCryptoFactoryTest.cpp
  DEPENDS
  Folly::folly
  mvfst_codec_types
  mvfst_folly_utils
  mvfst_fizz_handshake
  mvfst_common_string_utils
  mvfst_test_utils
)

quic_add_test(TARGET FizzPacketNumberCipherTest
  SOURCES
  FizzPacketNumberCipherTest.cpp
  DEPENDS
  Folly::folly
  fizz::fizz
  mvfst_fizz_handshake
  mvfst_codec_packet_number_cipher
  mvfst_common_string_utils
)
