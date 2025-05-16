/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/handshake/CryptoFactory.h>

#include <quic/handshake/HandshakeLayer.h>

namespace quic {

folly::Expected<std::unique_ptr<Aead>, QuicError>
CryptoFactory::getClientInitialCipher(
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  return makeInitialAead(kClientInitialLabel, clientDestinationConnId, version);
}

folly::Expected<std::unique_ptr<Aead>, QuicError>
CryptoFactory::getServerInitialCipher(
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  return makeInitialAead(kServerInitialLabel, clientDestinationConnId, version);
}

folly::Expected<BufPtr, QuicError>
CryptoFactory::makeServerInitialTrafficSecret(
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  return makeInitialTrafficSecret(
      kServerInitialLabel, clientDestinationConnId, version);
}

folly::Expected<BufPtr, QuicError>
CryptoFactory::makeClientInitialTrafficSecret(
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  return makeInitialTrafficSecret(
      kClientInitialLabel, clientDestinationConnId, version);
}

folly::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
CryptoFactory::makeClientInitialHeaderCipher(
    const ConnectionId& initialDestinationConnectionId,
    QuicVersion version) const {
  auto clientInitialTrafficSecretResult =
      makeClientInitialTrafficSecret(initialDestinationConnectionId, version);
  if (clientInitialTrafficSecretResult.hasError()) {
    return folly::makeUnexpected(clientInitialTrafficSecretResult.error());
  }
  auto& clientInitialTrafficSecret = clientInitialTrafficSecretResult.value();
  return makePacketNumberCipher(clientInitialTrafficSecret->coalesce());
}

folly::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
CryptoFactory::makeServerInitialHeaderCipher(
    const ConnectionId& initialDestinationConnectionId,
    QuicVersion version) const {
  auto serverInitialTrafficSecretResult =
      makeServerInitialTrafficSecret(initialDestinationConnectionId, version);
  if (serverInitialTrafficSecretResult.hasError()) {
    return folly::makeUnexpected(serverInitialTrafficSecretResult.error());
  }
  auto& serverInitialTrafficSecret = serverInitialTrafficSecretResult.value();
  return makePacketNumberCipher(serverInitialTrafficSecret->coalesce());
}

} // namespace quic
