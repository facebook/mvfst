/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/handshake/CryptoFactory.h>

#include <quic/handshake/HandshakeLayer.h>

namespace quic {

std::unique_ptr<Aead> CryptoFactory::getClientInitialCipher(
    const ConnectionId &clientDestinationConnId, QuicVersion version) const {
  return makeInitialAead(kClientInitialLabel, clientDestinationConnId, version);
}

std::unique_ptr<Aead> CryptoFactory::getServerInitialCipher(
    const ConnectionId &clientDestinationConnId, QuicVersion version) const {
  return makeInitialAead(kServerInitialLabel, clientDestinationConnId, version);
}

Buf CryptoFactory::makeServerInitialTrafficSecret(
    const ConnectionId &clientDestinationConnId, QuicVersion version) const {
  return makeInitialTrafficSecret(kServerInitialLabel, clientDestinationConnId,
                                  version);
}

Buf CryptoFactory::makeClientInitialTrafficSecret(
    const ConnectionId &clientDestinationConnId, QuicVersion version) const {
  return makeInitialTrafficSecret(kClientInitialLabel, clientDestinationConnId,
                                  version);
}

} // namespace quic
