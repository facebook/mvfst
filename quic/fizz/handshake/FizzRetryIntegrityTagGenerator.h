/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/handshake/RetryIntegrityTagGenerator.h>

namespace quic {

class FizzRetryIntegrityTagGenerator : public RetryIntegrityTagGenerator {
 public:
  std::unique_ptr<folly::IOBuf> getRetryIntegrityTag(
      QuicVersion version,
      const folly::IOBuf* pseudoRetryPacket) override;
};

} // namespace quic
