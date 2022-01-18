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

  folly::Optional<Buf> encryptToken(const QuicAddrValidationToken& token);

  uint64_t decryptToken(Buf encryptedToken, Buf aeadAssocData);

 private:
  fizz::server::Aead128GCMTokenCipher cipher_;
};
} // namespace quic
