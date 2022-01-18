/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/handshake/FizzBridge.h>

namespace quic {

EncryptionLevel getEncryptionLevelFromFizz(
    const fizz::EncryptionLevel encryptionLevel) {
  switch (encryptionLevel) {
    case fizz::EncryptionLevel::Plaintext:
      return EncryptionLevel::Initial;
    case fizz::EncryptionLevel::Handshake:
      return EncryptionLevel::Handshake;
    case fizz::EncryptionLevel::EarlyData:
      return EncryptionLevel::EarlyData;
    case fizz::EncryptionLevel::AppTraffic:
      return EncryptionLevel::AppData;
  }

  folly::assume_unreachable();
}

folly::Optional<TrafficKey> FizzAead::getKey() const {
  if (!fizzAead) {
    return folly::none;
  }
  auto fizzKey = fizzAead->getKey();
  if (!fizzKey) {
    return folly::none;
  }
  TrafficKey quicKey;
  quicKey.key = std::move(fizzKey->key);
  quicKey.iv = std::move(fizzKey->iv);
  return quicKey;
}

} // namespace quic
