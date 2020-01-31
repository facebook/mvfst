/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/codec/Types.h>

namespace quic {

constexpr folly::StringPiece kQuicKeyLabel = "quic key";
constexpr folly::StringPiece kQuicIVLabel = "quic iv";
constexpr folly::StringPiece kQuicPNLabel = "quic hp";

class Handshake {
 public:
  virtual ~Handshake() = default;

  virtual const folly::Optional<std::string>& getApplicationProtocol()
      const = 0;
};

constexpr folly::StringPiece kQuicDraft17Salt =
    "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0";
constexpr folly::StringPiece kQuicDraft22Salt =
    "\x7f\xbc\xdb\x0e\x7c\x66\xbb\xe9\x19\x3a\x96\xcd\x21\x51\x9e\xbd\x7a\x02\x64\x4a";
constexpr folly::StringPiece kQuicDraft23Salt =
    "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02";

constexpr folly::StringPiece kClientInitialLabel = "client in";
constexpr folly::StringPiece kServerInitialLabel = "server in";

/**
 * Converts the protection type of QUIC to an encryption level.
 */
EncryptionLevel protectionTypeToEncryptionLevel(ProtectionType type);

} // namespace quic
