/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/congestion_control/CongestionControllerFactory.h>

#include <quic/congestion_control/Copa.h>
#include <quic/congestion_control/QuicCubic.h>

#include <memory>

namespace quic {
std::unique_ptr<CongestionController>
DefaultCongestionControllerFactory::makeCongestionController(
    QuicConnectionStateBase& conn,
    CongestionControlType type) {
  std::unique_ptr<CongestionController> congestionController;
  switch (type) {
    case CongestionControlType::Cubic:
      congestionController = std::make_unique<Cubic>(conn);
      break;
    case CongestionControlType::Copa:
      congestionController = std::make_unique<Copa>(conn);
      break;
    case CongestionControlType::None:
      break;
    default:
      // Mobile builds only support Cubic and Copa
      MVLOG_ERROR << "Unsupported congestion controller for mobile: "
                  << congestionControlTypeToString(type)
                  << ". Falling back to Cubic.";
      congestionController = std::make_unique<Cubic>(conn);
      break;
  }
  QUIC_STATS(conn.statsCallback, onNewCongestionController, type);
  return congestionController;
}
} // namespace quic
