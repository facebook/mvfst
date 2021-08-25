// Copyright 2004-present Facebook. All Rights Reserved.

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
