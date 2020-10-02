/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/server/AeadTokenCipher.h>
#include <quic/codec/Types.h>
#include "folly/io/IOBuf.h"

namespace quic {

using RetryTokenSecret = std::array<uint8_t, kRetryTokenSecretLength>;

/**
 * A RetryToken generator.
 *
 */
class RetryTokenGenerator {
 public:
  explicit RetryTokenGenerator(RetryTokenSecret secret);

  folly::Optional<Buf> encryptToken(
      const ConnectionId& connId,
      const folly::IPAddress& clientIp,
      uint16_t clientPort);

  folly::Optional<RetryToken> decryptToken(Buf encryptedToken);

 private:
  fizz::server::Aead128GCMTokenCipher cipher_;
};
} // namespace quic
