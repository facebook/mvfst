/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/protocol/Exporter.h>
#include <fizz/protocol/Factory.h>
#include <fizz/protocol/Types.h>
#include <fizz/record/Types.h>
#include <folly/Expected.h>

#include <quic/QuicConstants.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/codec/Types.h>
#include <quic/handshake/Aead.h>
#include <quic/handshake/QuicFizzFactory.h>

namespace fizz {
class Factory;
}

namespace quic {

constexpr folly::StringPiece kQuicKeyLabel = "quic key";
constexpr folly::StringPiece kQuicIVLabel = "quic iv";
constexpr folly::StringPiece kQuicPNLabel = "quic hp";

class Handshake : public folly::DelayedDestruction {
 public:
  virtual const folly::Optional<std::string>& getApplicationProtocol()
      const = 0;

 protected:
  virtual ~Handshake() = default;
};

constexpr folly::StringPiece kQuicDraft17Salt =
    "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0";

constexpr folly::StringPiece kClientInitialLabel = "client in";
constexpr folly::StringPiece kServerInitialLabel = "server in";

std::unique_ptr<Aead> makeInitialAead(
    fizz::Factory* factory,
    folly::StringPiece label,
    const ConnectionId& clientDestinationConnId);

std::unique_ptr<Aead> getClientInitialCipher(
    fizz::Factory* factory,
    const ConnectionId& clientDestinationConnId);

std::unique_ptr<Aead> getServerInitialCipher(
    fizz::Factory* factory,
    const ConnectionId& clientDestinationConnId);

Buf makeInitialTrafficSecret(
    fizz::Factory* factory,
    folly::StringPiece label,
    const ConnectionId& clientDestinationConnId);

/**
 * Makes the header cipher for writing client initial packets.
 */
std::unique_ptr<PacketNumberCipher> makeClientInitialHeaderCipher(
    QuicFizzFactory* factory,
    const ConnectionId& initialDestinationConnectionId);

/**
 * Makes the header cipher for writing server initial packets.
 */
std::unique_ptr<PacketNumberCipher> makeServerInitialHeaderCipher(
    QuicFizzFactory* factory,
    const ConnectionId& initialDestinationConnectionId);

Buf makeServerInitialTrafficSecret(
    fizz::Factory* factory,
    const ConnectionId& clientDestinationConnId);

Buf makeClientInitialTrafficSecret(
    fizz::Factory* factory,
    const ConnectionId& clientDestinationConnId);

std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
    QuicFizzFactory* factory,
    folly::ByteRange baseSecret,
    fizz::CipherSuite cipher);

/**
 * Converts the protection type of QUIC to the encryption type of fizz.
 */
fizz::EncryptionLevel protectionTypeToEncryptionLevel(ProtectionType type);
} // namespace quic
