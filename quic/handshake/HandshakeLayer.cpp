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
#include <quic/handshake/FizzCryptoFactory.h>
#include <quic/handshake/QuicFizzFactory.h>

namespace quic {

std::unique_ptr<PacketNumberCipher> makeClientInitialHeaderCipher(
    QuicFizzFactory* factory,
    const ConnectionId& initialDestinationConnectionId,
    QuicVersion version) {
  auto clientInitialTrafficSecret =
      FizzCryptoFactory(factory).makeClientInitialTrafficSecret(
          initialDestinationConnectionId, version);
  return makePacketNumberCipher(
      factory,
      clientInitialTrafficSecret->coalesce(),
      fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
}

std::unique_ptr<PacketNumberCipher> makeServerInitialHeaderCipher(
    QuicFizzFactory* factory,
    const ConnectionId& initialDestinationConnectionId,
    QuicVersion version) {
  auto serverInitialTrafficSecret =
      FizzCryptoFactory(factory).makeServerInitialTrafficSecret(
          initialDestinationConnectionId, version);
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
