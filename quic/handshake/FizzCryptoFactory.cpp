/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/handshake/FizzCryptoFactory.h>

#include <quic/handshake/FizzBridge.h>
#include <quic/handshake/HandshakeLayer.h>

namespace quic {

Buf FizzCryptoFactory::makeInitialTrafficSecret(
    folly::StringPiece label,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  DCHECK(factory_);
  auto deriver =
      factory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
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

std::unique_ptr<Aead> FizzCryptoFactory::makeInitialAead(
    folly::StringPiece label,
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  DCHECK(factory_);
  auto trafficSecret =
      makeInitialTrafficSecret(label, clientDestinationConnId, version);
  auto deriver =
      factory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto aead = factory_->makeAead(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
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

std::unique_ptr<PacketNumberCipher> FizzCryptoFactory::makePacketNumberCipher(
    folly::ByteRange baseSecret) const {
  auto pnCipher = factory_->makePacketNumberCipher(
      fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto deriver =
      factory_->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto pnKey = deriver->expandLabel(
      baseSecret, kQuicPNLabel, folly::IOBuf::create(0), pnCipher->keyLength());
  pnCipher->setKey(pnKey->coalesce());
  return pnCipher;
}

} // namespace quic
