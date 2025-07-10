/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/handshake/CryptoFactory.h>

#include <quic/handshake/HandshakeLayer.h>

namespace quic {

quic::Expected<std::unique_ptr<Aead>, QuicError>
CryptoFactory::getClientInitialCipher(
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  return makeInitialAead(kClientInitialLabel, clientDestinationConnId, version);
}

quic::Expected<std::unique_ptr<Aead>, QuicError>
CryptoFactory::getServerInitialCipher(
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  return makeInitialAead(kServerInitialLabel, clientDestinationConnId, version);
}

quic::Expected<BufPtr, QuicError> CryptoFactory::makeServerInitialTrafficSecret(
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  return makeInitialTrafficSecret(
      kServerInitialLabel, clientDestinationConnId, version);
}

quic::Expected<BufPtr, QuicError> CryptoFactory::makeClientInitialTrafficSecret(
    const ConnectionId& clientDestinationConnId,
    QuicVersion version) const {
  return makeInitialTrafficSecret(
      kClientInitialLabel, clientDestinationConnId, version);
}

quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
CryptoFactory::makeClientInitialHeaderCipher(
    const ConnectionId& initialDestinationConnectionId,
    QuicVersion version) const {
  auto clientInitialTrafficSecretResult =
      makeClientInitialTrafficSecret(initialDestinationConnectionId, version);
  if (!clientInitialTrafficSecretResult.has_value()) {
    return quic::make_unexpected(clientInitialTrafficSecretResult.error());
  }
  auto& clientInitialTrafficSecret = clientInitialTrafficSecretResult.value();
  auto packetNumberCipherResult =
      makePacketNumberCipher(clientInitialTrafficSecret->coalesce());
  if (!packetNumberCipherResult.has_value()) {
    return quic::make_unexpected(packetNumberCipherResult.error());
  }
  return std::move(packetNumberCipherResult.value());
}

quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
CryptoFactory::makeServerInitialHeaderCipher(
    const ConnectionId& initialDestinationConnectionId,
    QuicVersion version) const {
  auto serverInitialTrafficSecretResult =
      makeServerInitialTrafficSecret(initialDestinationConnectionId, version);
  if (!serverInitialTrafficSecretResult.has_value()) {
    return quic::make_unexpected(serverInitialTrafficSecretResult.error());
  }
  auto& serverInitialTrafficSecret = serverInitialTrafficSecretResult.value();
  auto packetNumberCipherResult =
      makePacketNumberCipher(serverInitialTrafficSecret->coalesce());
  if (!packetNumberCipherResult.has_value()) {
    return quic::make_unexpected(packetNumberCipherResult.error());
  }
  return std::move(packetNumberCipherResult.value());
}

} // namespace quic
