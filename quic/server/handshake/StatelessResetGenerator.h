/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/crypto/Hkdf.h>
#include <fizz/crypto/Sha256.h>
#include <quic/codec/Types.h>

namespace quic {

using StatelessResetSecret =
    std::array<uint8_t, kStatelessResetTokenSecretLength>;

/**
 * A StatelessResetToken generator.
 *
 * This generator takes in a StatelessResetSecret, and a string that represents
 * the server address. It generates a different StatelessResetToken given a
 * different ConnectionId.
 *
 * The StatelessResetSecret is provided to HKDF to generate a pesudorandom key.
 * Address string and ConnectionId are concated together, as app specific
 * input in HKDF-Expand. The output of HKDF will be the StatelessResetToken.
 *
 * PRK = HKDF-Extract(Salt, secret)
 * appInfo = Concat(connId, addrString);
 * Token = HKDF-Expand(PRK, appInfo, tokenLength)
 */
class StatelessResetGenerator {
 public:
  explicit StatelessResetGenerator(
      StatelessResetSecret secret,
      const std::string& addressStr);

  StatelessResetToken generateToken(const ConnectionId& connId) const;

 private:
  StatelessResetSecret secret_;
  std::string addressStr_;
  fizz::HkdfImpl<fizz::Sha256> hdkf_;
  std::vector<uint8_t> extractedSecret_;
};
} // namespace quic
