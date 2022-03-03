/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/fizz/client/handshake/QuicPskCache.h>

#include <folly/Optional.h>
#include <folly/portability/GMock.h>

#include <string>

namespace quic {
class MockQuicPskCache : public QuicPskCache {
 public:
  MOCK_METHOD(folly::Optional<QuicCachedPsk>, getPsk, (const std::string&));
  MOCK_METHOD(void, putPsk, (const std::string&, QuicCachedPsk));
  MOCK_METHOD(void, removePsk, (const std::string&));
};
} // namespace quic
