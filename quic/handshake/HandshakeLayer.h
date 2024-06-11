/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/codec/Types.h>
#include <quic/handshake/Aead.h>

namespace quic {

constexpr folly::StringPiece kQuicKeyLabel = "quic key";
constexpr folly::StringPiece kQuicIVLabel = "quic iv";
constexpr folly::StringPiece kQuicPNLabel = "quic hp";
constexpr folly::StringPiece kQuicKULabel = "quic ku";

class Handshake {
 public:
  virtual ~Handshake() = default;

  virtual const Optional<std::string>& getApplicationProtocol() const = 0;

  /**
   * An API to get oneRttReadCiphers on key rotation. Each call will return a
   * one rtt read cipher using the current traffic secret and advance the
   * traffic secret.
   */
  virtual std::unique_ptr<Aead> getNextOneRttReadCipher() = 0;

  /**
   * An API to get oneRttWriteCiphers on key rotation. Each call will return a
   * one rtt write cipher using the current traffic secret and advance the
   * traffic secret.
   */
  virtual std::unique_ptr<Aead> getNextOneRttWriteCipher() = 0;

  /*
   * Export the underlying TLS key material.
   * label is the label argument for the TLS exporter.
   * context is the context value argument for the TLS exporter.
   * keyLength is the length of the exported key.
   */
  virtual Optional<std::vector<uint8_t>> getExportedKeyingMaterial(
      const std::string& label,
      const Optional<folly::ByteRange>& context,
      uint16_t keyLength) = 0;

  virtual void handshakeConfirmed() {
    LOG(FATAL) << "Not implemented";
  }
};

constexpr folly::StringPiece kQuicDraft23Salt =
    "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02";
constexpr folly::StringPiece kQuicDraft29Salt =
    "\xaf\xbf\xec\x28\x99\x93\xd2\x4c\x9e\x97\x86\xf1\x9c\x61\x11\xe0\x43\x90\xa8\x99";
constexpr folly::StringPiece kQuicV1Salt =
    "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a";

constexpr folly::StringPiece kClientInitialLabel = "client in";
constexpr folly::StringPiece kServerInitialLabel = "server in";

/**
 * Converts the protection type of QUIC to an encryption level.
 */
EncryptionLevel protectionTypeToEncryptionLevel(ProtectionType type);

folly::StringPiece getQuicVersionSalt(QuicVersion version);

} // namespace quic
