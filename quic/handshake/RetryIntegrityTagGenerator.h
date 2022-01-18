/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>

namespace quic {

class RetryIntegrityTagGenerator {
 public:
  virtual ~RetryIntegrityTagGenerator() = default;

  virtual std::unique_ptr<folly::IOBuf> getRetryIntegrityTag(
      QuicVersion version,
      const folly::IOBuf* pseudoRetryPacket) = 0;
};

} // namespace quic
