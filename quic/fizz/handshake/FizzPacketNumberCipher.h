/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/PacketNumberCipher.h>

#include <folly/ssl/OpenSSLPtrTypes.h>

namespace quic {

class Aes128PacketNumberCipher : public PacketNumberCipher {
 public:
  ~Aes128PacketNumberCipher() override = default;

  [[nodiscard]] folly::Expected<folly::Unit, QuicError> setKey(
      ByteRange key) override;

  [[nodiscard]] const BufPtr& getKey() const override;

  [[nodiscard]] folly::Expected<HeaderProtectionMask, QuicError> mask(
      ByteRange sample) const override;

  [[nodiscard]] size_t keyLength() const override;

 private:
  folly::ssl::EvpCipherCtxUniquePtr encryptCtx_;

  BufPtr pnKey_;
};

class Aes256PacketNumberCipher : public PacketNumberCipher {
 public:
  ~Aes256PacketNumberCipher() override = default;

  [[nodiscard]] folly::Expected<folly::Unit, QuicError> setKey(
      ByteRange key) override;

  [[nodiscard]] const BufPtr& getKey() const override;

  [[nodiscard]] folly::Expected<HeaderProtectionMask, QuicError> mask(
      ByteRange sample) const override;

  [[nodiscard]] size_t keyLength() const override;

 private:
  folly::ssl::EvpCipherCtxUniquePtr encryptCtx_;

  BufPtr pnKey_;
};

} // namespace quic
