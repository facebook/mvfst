/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/BbrTesting.h>

namespace quic {

BbrTestingCongestionController::BbrTestingCongestionController(
    QuicConnectionStateBase& conn)
    : BbrCongestionController(conn) {
  // These are now set in QuicTransportBase.cpp in validateCongestionAndPacing()
  // conn.transportSettings.defaultRttFactor = {1, 1};
  // conn.transportSettings.startupRttFactor = {1, 1};
}
} // namespace quic
