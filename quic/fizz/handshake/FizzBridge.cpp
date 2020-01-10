/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
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

} // namespace quic
