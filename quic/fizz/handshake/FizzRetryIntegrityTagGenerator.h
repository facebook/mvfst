// Copyright 2004-present Facebook. All Rights Reserved.

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
