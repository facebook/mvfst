/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/ServerCongestionControllerFactory.h>

#include <quic/congestion_control/Bbr.h>
#include <quic/congestion_control/BbrBandwidthSampler.h>
#include <quic/congestion_control/BbrRttSampler.h>
#include <quic/congestion_control/BbrTesting.h>
#include <quic/congestion_control/Copa.h>
#include <quic/congestion_control/Copa2.h>
#include <quic/congestion_control/NewReno.h>
#include <quic/congestion_control/QuicCCP.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/congestion_control/StaticCwndCongestionController.h>

#include <memory>

namespace quic {
std::unique_ptr<CongestionController>
ServerCongestionControllerFactory::makeCongestionController(
    QuicConnectionStateBase& conn,
    CongestionControlType type) {
  auto setupBBR = [&conn](BbrCongestionController* bbr) {
    bbr->setRttSampler(std::make_unique<BbrRttSampler>(
        std::chrono::seconds(kDefaultRttSamplerExpiration)));
    bbr->setBandwidthSampler(std::make_unique<BbrBandwidthSampler>(conn));
  };
  std::unique_ptr<CongestionController> congestionController;
  switch (type) {
    case CongestionControlType::NewReno:
      congestionController = std::make_unique<NewReno>(conn);
      break;
    case CongestionControlType::CCP:
#ifdef CCP_ENABLED
      congestionController = std::make_unique<CCP>(conn);
      break;
#else
      LOG(ERROR)
          << "Server CC Factory cannot make CCP (unless recompiled with -DCCP_ENABLED). Falling back to cubic.";
      FOLLY_FALLTHROUGH;
#endif
    case CongestionControlType::Cubic:
      congestionController = std::make_unique<Cubic>(conn);
      break;
    case CongestionControlType::Copa:
      congestionController = std::make_unique<Copa>(conn);
      break;
    case CongestionControlType::Copa2:
      congestionController = std::make_unique<Copa2>(conn);
      break;
    case CongestionControlType::BBR: {
      auto bbr = std::make_unique<BbrCongestionController>(conn);
      setupBBR(bbr.get());
      congestionController = std::move(bbr);
      break;
    }
    case CongestionControlType::BBRTesting: {
      auto bbr = std::make_unique<BbrTestingCongestionController>(conn);
      setupBBR(bbr.get());
      congestionController = std::move(bbr);
      break;
    }
    case CongestionControlType::StaticCwnd: {
      throw QuicInternalException(
          "StaticCwnd Congestion Controller cannot be "
          "constructed via CongestionControllerFactory.",
          LocalErrorCode::INTERNAL_ERROR);
    }
    case CongestionControlType::None:
      break;
    case CongestionControlType::MAX:
      throw QuicInternalException(
          "MAX is not a valid cc algorithm.", LocalErrorCode::INTERNAL_ERROR);
  }
  QUIC_STATS(conn.statsCallback, onNewCongestionController, type);
  return congestionController;
}
} // namespace quic
