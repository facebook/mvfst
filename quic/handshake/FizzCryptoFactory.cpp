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
    folly::StringPiece label, const ConnectionId &clientDestinationConnId,
    QuicVersion version) const {
  auto deriver =
      factory->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto connIdRange = folly::range(clientDestinationConnId);
  auto salt =
      version == QuicVersion::MVFST_OLD ? kQuicDraft17Salt : kQuicDraft22Salt;
  auto initialSecret = deriver->hkdfExtract(salt, connIdRange);
  auto trafficSecret =
      deriver->expandLabel(folly::range(initialSecret), label,
                           folly::IOBuf::create(0), fizz::Sha256::HashLen);
  return trafficSecret;
}

std::unique_ptr<Aead>
FizzCryptoFactory::makeInitialAead(folly::StringPiece label,
                                   const ConnectionId &clientDestinationConnId,
                                   QuicVersion version) const {
  auto trafficSecret =
      makeInitialTrafficSecret(label, clientDestinationConnId, version);
  auto deriver =
      factory->makeKeyDeriver(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto aead = factory->makeAead(fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
  auto key = deriver->expandLabel(trafficSecret->coalesce(), kQuicKeyLabel,
                                  folly::IOBuf::create(0), aead->keyLength());
  auto iv = deriver->expandLabel(trafficSecret->coalesce(), kQuicIVLabel,
                                 folly::IOBuf::create(0), aead->ivLength());

  fizz::TrafficKey trafficKey = {std::move(key), std::move(iv)};
  aead->setKey(std::move(trafficKey));
  return FizzAead::wrap(std::move(aead));
}

} // namespace quic
