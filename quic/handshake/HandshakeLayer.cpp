/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/handshake/HandshakeLayer.h>

#include <fizz/crypto/KeyDerivation.h>
#include <fizz/crypto/Sha256.h>
#include <fizz/protocol/Factory.h>
#include <quic/handshake/FizzBridge.h>
#include <quic/handshake/QuicFizzFactory.h>

namespace quic {

Buf makeInitialTrafficSecret(
    fizz::Factory* factory,
    folly::StringPiece label,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) {
  auto deriver =
      factory->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto connIdRange = folly::range(clientDestinationConnId);
  auto salt =
      version == QuicVersion::MVFST_OLD ? kQuicDraft17Salt : kQuicDraft22Salt;
  auto initialSecret = deriver->hkdfExtract(salt, connIdRange);
  auto trafficSecret = deriver->expandLabel(
      folly::range(initialSecret),
      label,
      folly::IOBuf::create(0),
      fizz::Sha256::HashLen);
  return trafficSecret;
}

Buf makeServerInitialTrafficSecret(
    fizz::Factory* factory,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) {
  return makeInitialTrafficSecret(
      factory, kServerInitialLabel, clientDestinationConnId, version);
}

Buf makeClientInitialTrafficSecret(
    fizz::Factory* factory,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) {
  return makeInitialTrafficSecret(
      factory, kClientInitialLabel, clientDestinationConnId, version);
}

std::unique_ptr<Aead> makeInitialAead(
    fizz::Factory* factory,
    folly::StringPiece label,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) {
  auto trafficSecret = makeInitialTrafficSecret(
      factory, label, clientDestinationConnId, version);
  auto deriver =
      factory->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto aead = factory->makeAead(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto key = deriver->expandLabel(
      trafficSecret->coalesce(),
      kQuicKeyLabel,
      folly::IOBuf::create(0),
      aead->keyLength());
  auto iv = deriver->expandLabel(
      trafficSecret->coalesce(),
      kQuicIVLabel,
      folly::IOBuf::create(0),
      aead->ivLength());

  fizz::TrafficKey trafficKey = {std::move(key), std::move(iv)};
  aead->setKey(std::move(trafficKey));
  return FizzAead::wrap(std::move(aead));
}

std::unique_ptr<Aead> getClientInitialCipher(
    fizz::Factory* factory,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) {
  return makeInitialAead(
      factory, kClientInitialLabel, clientDestinationConnId, version);
}

std::unique_ptr<Aead> getServerInitialCipher(
    fizz::Factory* factory,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) {
  return makeInitialAead(
      factory, kServerInitialLabel, clientDestinationConnId, version);
}

std::unique_ptr<PacketNumberCipher> makeClientInitialHeaderCipher(
    QuicFizzFactory* factory,
    const ConnectionId& initialDestinationConnectionId,
    QuicVersion version) {
  auto clientInitialTrafficSecret = makeClientInitialTrafficSecret(
      factory, initialDestinationConnectionId, version);
  return makePacketNumberCipher(
      factory,
      clientInitialTrafficSecret->coalesce(),
      fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
}

std::unique_ptr<PacketNumberCipher> makeServerInitialHeaderCipher(
    QuicFizzFactory* factory,
    const ConnectionId& initialDestinationConnectionId,
    QuicVersion version) {
  auto serverInitialTrafficSecret = makeServerInitialTrafficSecret(
      factory, initialDestinationConnectionId, version);
  return makePacketNumberCipher(
      factory,
      serverInitialTrafficSecret->coalesce(),
      fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
}

std::unique_ptr<PacketNumberCipher> makePacketNumberCipher(
    QuicFizzFactory* factory,
    folly::ByteRange baseSecret,
    fizz::CipherSuite cipher) {
  auto pnCipher = factory->makePacketNumberCipher(cipher);
  auto deriver = factory->makeKeyDeriver(cipher);
  auto pnKey = deriver->expandLabel(
      baseSecret, kQuicPNLabel, folly::IOBuf::create(0), pnCipher->keyLength());
  pnCipher->setKey(pnKey->coalesce());
  return pnCipher;
}

EncryptionLevel protectionTypeToEncryptionLevel(ProtectionType type) {
  switch (type) {
    case ProtectionType::Initial:
      return EncryptionLevel::Initial;
    case ProtectionType::Handshake:
      return EncryptionLevel::Handshake;
    case ProtectionType::ZeroRtt:
      return EncryptionLevel::EarlyData;
    case ProtectionType::KeyPhaseZero:
    case ProtectionType::KeyPhaseOne:
      return EncryptionLevel::AppData;
  }
  folly::assume_unreachable();
}
} // namespace quic
