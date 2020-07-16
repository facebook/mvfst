/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/CongestionControllerFactory.h>

#include <quic/congestion_control/Bbr.h>
#include <quic/congestion_control/BbrBandwidthSampler.h>
#include <quic/congestion_control/BbrRttSampler.h>
#include <quic/congestion_control/Copa.h>
#include <quic/congestion_control/NewReno.h>
#include <quic/congestion_control/QuicCubic.h>

#include <memory>

namespace quic {
std::unique_ptr<CongestionController>
DefaultCongestionControllerFactory::makeCongestionController(
    QuicConnectionStateBase& conn,
    CongestionControlType type) {
  std::unique_ptr<CongestionController> congestionController;
  switch (type) {
    case CongestionControlType::NewReno:
      congestionController = std::make_unique<NewReno>(conn);
      break;
    case CongestionControlType::Cubic:
      congestionController = std::make_unique<Cubic>(conn);
      break;
    case CongestionControlType::Copa:
      congestionController = std::make_unique<Copa>(conn);
      break;
    case CongestionControlType::BBR: {
      auto bbr = std::make_unique<BbrCongestionController>(conn);
      bbr->setRttSampler(std::make_unique<BbrRttSampler>(
          std::chrono::seconds(kDefaultRttSamplerExpiration)));
      bbr->setBandwidthSampler(std::make_unique<BbrBandwidthSampler>(conn));
      congestionController = std::move(bbr);
      break;
    }
    case CongestionControlType::CCP:
      throw QuicInternalException(
          "CCP congestion control only available on server (via ServerCongestionControllerFactory)",
          LocalErrorCode::INTERNAL_ERROR);
    case CongestionControlType::None:
      break;
  }
  return congestionController;
}
} // namespace quic
