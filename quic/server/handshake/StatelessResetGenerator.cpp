/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/handshake/StatelessResetGenerator.h>

#include <folly/Range.h>

namespace {
constexpr folly::StringPiece kSalt{"Stateless reset"};
}

namespace quic {

StatelessResetGenerator::StatelessResetGenerator(
    StatelessResetSecret secret,
    const std::string& addressStr)
    : addressStr_(std::move(addressStr)),
      hkdf_(fizz::HkdfImpl::create<fizz::Sha256>()) {
  extractedSecret_ = hkdf_.extract(kSalt, folly::range(secret));
}

StatelessResetToken StatelessResetGenerator::generateToken(
    const ConnectionId& connId) const {
  StatelessResetToken token;
  auto info = toData(connId);
  info.prependChain(
      folly::IOBuf::wrapBuffer(addressStr_.data(), addressStr_.size()));
  auto out = hkdf_.expand(folly::range(extractedSecret_), info, token.size());
  out->coalesce();
  memcpy(token.data(), out->data(), out->length());
  return token;
}

} // namespace quic
