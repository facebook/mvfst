/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/client/handshake/QuicPskCache.h>

#include <folly/Optional.h>
#include <folly/portability/GMock.h>

#include <string>

namespace quic {
class MockQuicPskCache : public QuicPskCache {
 public:
  MOCK_METHOD1(getPsk, folly::Optional<QuicCachedPsk>(const std::string&));
  MOCK_METHOD2(putPsk, void(const std::string&, QuicCachedPsk));
  MOCK_METHOD1(removePsk, void(const std::string&));
};
} // namespace quic
