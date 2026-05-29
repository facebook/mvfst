/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/common/BufUtil.h>
#include <quic/common/Expected.h>
#include <quic/common/MvfstLogging.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/state/StateData.h>

#include <memory>

namespace quic::test {

TrafficKey getQuicTestKey();

template <class T>
std::unique_ptr<T> createNoOpAeadImpl(uint64_t cipherOverhead = 0) {
  // Fake that the handshake has already occurred
  auto aead = std::make_unique<testing::NiceMock<T>>();
  ON_CALL(*aead, _inplaceEncrypt(testing::_, testing::_, testing::_))
      .WillByDefault(testing::Invoke([&](auto& buf, auto, auto) {
        if (buf) {
          return std::move(buf);
        } else {
          return BufHelpers::create(0);
        }
      }));
  // Fake that the handshake has already occurred and fix the keys.
  ON_CALL(*aead, _decrypt(testing::_, testing::_, testing::_))
      .WillByDefault(
          testing::Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
  ON_CALL(*aead, _tryDecrypt(testing::_, testing::_, testing::_))
      .WillByDefault(
          testing::Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
  ON_CALL(*aead, getCipherOverhead())
      .WillByDefault(testing::Return(cipherOverhead));
  ON_CALL(*aead, getKey()).WillByDefault(testing::Invoke([]() {
    return getQuicTestKey();
  }));
  return aead;
}

std::unique_ptr<MockAead> createNoOpAead(uint64_t cipherOverhead = 0);

quic::Expected<std::unique_ptr<MockPacketNumberCipher>, QuicError>
createNoOpHeaderCipher();

// For backward compatibility with existing code
inline std::unique_ptr<MockPacketNumberCipher> createNoOpHeaderCipherNoThrow() {
  auto result = createNoOpHeaderCipher();
  CHECK(!result.hasError()) << "Failed to create header cipher";
  return std::move(result.value());
}

void initializePathManagerState(QuicConnectionStateBase& conn);

std::unique_ptr<QuicConnectionStateBase> createTestQuicConnectionState();

} // namespace quic::test
