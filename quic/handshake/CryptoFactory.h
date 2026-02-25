/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/Types.h>
#include <quic/common/Expected.h>
#include <quic/handshake/Aead.h>

#include <memory>

namespace quic {

class CryptoFactory {
 public:
  [[nodiscard]] quic::Expected<std::unique_ptr<Aead>, QuicError>
  getClientInitialCipher(
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const;

  [[nodiscard]] quic::Expected<std::unique_ptr<Aead>, QuicError>
  getServerInitialCipher(
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const;

  [[nodiscard]] quic::Expected<BufPtr, QuicError>
  makeServerInitialTrafficSecret(
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const;
  [[nodiscard]] quic::Expected<BufPtr, QuicError>
  makeClientInitialTrafficSecret(
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const;

  /**
   * Makes the header cipher for writing client initial packets.
   */
  [[nodiscard]] quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
  makeClientInitialHeaderCipher(
      const ConnectionId& initialDestinationConnectionId,
      QuicVersion version) const;

  /**
   * Makes the header cipher for writing server initial packets.
   */
  [[nodiscard]] quic::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
  makeServerInitialHeaderCipher(
      const ConnectionId& initialDestinationConnectionId,
      QuicVersion version) const;

  /**
   * Crypto layer specific methods.
   */
  [[nodiscard]] virtual quic::Expected<BufPtr, QuicError>
  makeInitialTrafficSecret(
      folly::StringPiece label,
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const = 0;

  [[nodiscard]] virtual quic::Expected<std::unique_ptr<Aead>, QuicError>
  makeInitialAead(
      folly::StringPiece label,
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const = 0;

  [[nodiscard]] virtual quic::
      Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
      makePacketNumberCipher(ByteRange baseSecret) const = 0;

  // Type alias for constant-time comparison function pointer.
  // Raw function pointer is used instead of std::function since all
  // implementations are stateless (no captured state).
  using CryptoEqualFn = bool (*)(ByteRange, ByteRange);

  [[nodiscard]] virtual CryptoEqualFn getCryptoEqualFunction() const = 0;

  virtual ~CryptoFactory() = default;
};

} // namespace quic
