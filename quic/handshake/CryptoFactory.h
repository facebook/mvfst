/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Expected.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/Types.h>
#include <quic/handshake/Aead.h>

#include <memory>

namespace quic {

class CryptoFactory {
 public:
  [[nodiscard]] folly::Expected<std::unique_ptr<Aead>, QuicError>
  getClientInitialCipher(
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const;

  [[nodiscard]] folly::Expected<std::unique_ptr<Aead>, QuicError>
  getServerInitialCipher(
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const;

  [[nodiscard]] folly::Expected<BufPtr, QuicError>
  makeServerInitialTrafficSecret(
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const;
  [[nodiscard]] folly::Expected<BufPtr, QuicError>
  makeClientInitialTrafficSecret(
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const;

  /**
   * Makes the header cipher for writing client initial packets.
   */
  [[nodiscard]] folly::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
  makeClientInitialHeaderCipher(
      const ConnectionId& initialDestinationConnectionId,
      QuicVersion version) const;

  /**
   * Makes the header cipher for writing server initial packets.
   */
  [[nodiscard]] folly::Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
  makeServerInitialHeaderCipher(
      const ConnectionId& initialDestinationConnectionId,
      QuicVersion version) const;

  /**
   * Crypto layer specific methods.
   */
  [[nodiscard]] virtual folly::Expected<BufPtr, QuicError>
  makeInitialTrafficSecret(
      folly::StringPiece label,
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const = 0;

  [[nodiscard]] virtual folly::Expected<std::unique_ptr<Aead>, QuicError>
  makeInitialAead(
      folly::StringPiece label,
      const ConnectionId& clientDestinationConnId,
      QuicVersion version) const = 0;

  [[nodiscard]] virtual folly::
      Expected<std::unique_ptr<PacketNumberCipher>, QuicError>
      makePacketNumberCipher(ByteRange baseSecret) const = 0;

  [[nodiscard]] virtual std::function<bool(ByteRange, ByteRange)>
  getCryptoEqualFunction() const = 0;

  virtual ~CryptoFactory() = default;
};

} // namespace quic
