// (c) Facebook, Inc. and its affiliates. Confidential and proprietary.

#pragma once

#ifdef CCP_ENABLED
#include <quic/congestion_control/third_party/ccp/libstartccp.h>
#endif
#include <folly/Random.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <cstdint>
#include <string>

namespace quic {

class QuicCcpThreadLauncher {
 public:
  QuicCcpThreadLauncher() {
    ccpId_ = 0;
  }

  void start(const std::string& ccpConfig);
  bool hasLaunched();
  uint64_t getCcpId();
  void stop();

 private:
#ifdef CCP_ENABLED
  folly::ScopedEventBaseThread ccpEvb_;
#endif
  bool* handle_;
  uint64_t ccpId_;
};

} // namespace quic
