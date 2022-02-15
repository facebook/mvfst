/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/QuicCcpThreadLauncher.h>

namespace quic {

void QuicCcpThreadLauncher::start(
    FOLLY_MAYBE_UNUSED const std::string& ccpConfig) {
#ifdef CCP_ENABLED
  ccpId_ = folly::Random::secureRand64();
  handle_ = ccp_create_handle();
  ccpEvb_.getEventBase()->runInEventBaseThread([&, handle = handle_] {
    // NOTE second arg is fd of output device
    // hardcoded to 2 for stderr
    ccp_spawn(ccpConfig.c_str(), 2, ccpId_, handle);
  });
#else
  VLOG(2) << "WARN: tried to launch ccp, but ccp not enabled";
#endif
}

bool QuicCcpThreadLauncher::hasLaunched() {
  return ccpId_ != 0;
}

uint64_t QuicCcpThreadLauncher::getCcpId() {
#ifdef CCP_ENABLED
  return ccpId_;
#else
  return 0;
#endif
}

void QuicCcpThreadLauncher::stop() {
#ifdef CCP_ENABLED
  if (hasLaunched_()) {
    ccp_kill(handle_);
  }
#else
#endif
}
} // namespace quic
