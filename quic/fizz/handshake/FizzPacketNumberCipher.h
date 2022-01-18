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

  void setKey(folly::ByteRange key) override;

  const Buf& getKey() const override;

  HeaderProtectionMask mask(folly::ByteRange sample) const override;

  size_t keyLength() const override;

 private:
  folly::ssl::EvpCipherCtxUniquePtr encryptCtx_;

  Buf pnKey_;
};

class Aes256PacketNumberCipher : public PacketNumberCipher {
 public:
  ~Aes256PacketNumberCipher() override = default;

  void setKey(folly::ByteRange key) override;

  const Buf& getKey() const override;

  HeaderProtectionMask mask(folly::ByteRange sample) const override;

  size_t keyLength() const override;

 private:
  folly::ssl::EvpCipherCtxUniquePtr encryptCtx_;

  Buf pnKey_;
};

} // namespace quic
