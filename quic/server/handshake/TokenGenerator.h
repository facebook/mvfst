/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/server/AeadTokenCipher.h>
#include <folly/io/IOBuf.h>
#include <quic/codec/Types.h>

namespace quic {

using TokenSecret = std::array<uint8_t, kRetryTokenSecretLength>;

/**
 * A RetryToken and NewToken generator.
 */
class TokenGenerator {
 public:
  explicit TokenGenerator(TokenSecret secret);

  Optional<BufPtr> encryptToken(const QuicAddrValidationToken& token);

  uint64_t decryptToken(BufPtr encryptedToken, BufPtr aeadAssocData);

  /**
   * Decrypts a retry token from a client Initial with the given destination
   * connection id. Accepts tokens with or without a server-chosen Retry source
   * connection id.
   */
  Optional<RetryToken> decryptRetryToken(
      BufPtr encryptedToken,
      const ConnectionId& dstConnId,
      const folly::IPAddress& clientIp);

 private:
  fizz::server::Aead128GCMTokenCipher cipher_;
};
} // namespace quic
