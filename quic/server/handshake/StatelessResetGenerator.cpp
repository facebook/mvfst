/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/handshake/StatelessResetGenerator.h>

#include <fizz/backend/openssl/OpenSSL.h>
#include <fizz/crypto/Crypto.h>
#include <fizz/util/Status.h>
#include <folly/Range.h>

namespace {
constexpr folly::StringPiece kSalt{"Stateless reset"};
}

namespace quic {

StatelessResetGenerator::StatelessResetGenerator(
    StatelessResetSecret secret,
    const std::string& addressStr)
    : addressStr_(std::move(addressStr)),
      hkdf_(fizz::openssl::createHkdf<fizz::Sha256>()) {
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(
      hkdf_.extract(
          extractedSecret_,
          err,
          kSalt,
          ByteRange(secret.data(), secret.size())),
      err);
}

StatelessResetToken StatelessResetGenerator::generateToken(
    const ConnectionId& connId) const {
  StatelessResetToken token;
  auto info = toData(connId);
  info.appendToChain(
      BufHelpers::wrapBuffer(addressStr_.data(), addressStr_.size()));
  std::unique_ptr<folly::IOBuf> out;
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(
      hkdf_.expand(
          out,
          err,
          ByteRange(extractedSecret_.data(), extractedSecret_.size()),
          info,
          token.size()),
      err);
  out->coalesce();
  memcpy(token.data(), out->data(), out->length());
  return token;
}

} // namespace quic
