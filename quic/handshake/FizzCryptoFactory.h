/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/handshake/CryptoFactory.h>

#include <fizz/protocol/Factory.h>

namespace quic {

class FizzCryptoFactory : public CryptoFactory {
private:
  fizz::Factory *factory;

public:
  FizzCryptoFactory(fizz::Factory *factory) : factory(factory) {}

  Buf makeInitialTrafficSecret(folly::StringPiece label,
                               const ConnectionId &clientDestinationConnId,
                               QuicVersion version) const override;

  std::unique_ptr<Aead>
  makeInitialAead(folly::StringPiece label,
                  const ConnectionId &clientDestinationConnId,
                  QuicVersion version) const override;
};

} // namespace quic
