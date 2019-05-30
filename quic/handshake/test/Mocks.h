/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/crypto/aead/test/Mocks.h>
#include <gmock/gmock.h>
#include <quic/codec/PacketNumberCipher.h>

namespace quic {
namespace test {

class MockPacketNumberCipher : public PacketNumberCipher {
 public:
  virtual ~MockPacketNumberCipher() = default;

  MOCK_METHOD1(setKey, void(folly::ByteRange key));
  MOCK_CONST_METHOD1(mask, HeaderProtectionMask(folly::ByteRange));
  MOCK_CONST_METHOD0(keyLength, size_t());
};

using MockAead = fizz::test::MockAead;
} // namespace test
} // namespace quic
