/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/Types.h>
#include <quic/handshake/Aead.h>

#include <memory>

namespace quic {

class CryptoFactory {
public:
  // TODO remove version parameter when we don't need to support MVFST_OLD
  // anymore.
  std::unique_ptr<Aead>
  getClientInitialCipher(const ConnectionId &clientDestinationConnId,
                         QuicVersion version) const;
  std::unique_ptr<Aead>
  getServerInitialCipher(const ConnectionId &clientDestinationConnId,
                         QuicVersion version) const;

  Buf makeServerInitialTrafficSecret(
      const ConnectionId &clientDestinationConnId, QuicVersion version) const;
  Buf makeClientInitialTrafficSecret(
      const ConnectionId &clientDestinationConnId, QuicVersion version) const;

  /**
   * Crypto layer specifc methods.
   */
  virtual Buf
  makeInitialTrafficSecret(folly::StringPiece label,
                           const ConnectionId &clientDestinationConnId,
                           QuicVersion version) const = 0;

  virtual std::unique_ptr<Aead>
  makeInitialAead(folly::StringPiece label,
                  const ConnectionId &clientDestinationConnId,
                  QuicVersion version) const = 0;

  virtual ~CryptoFactory() {}
};

} // namespace quic
