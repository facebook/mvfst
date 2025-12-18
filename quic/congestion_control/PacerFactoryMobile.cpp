/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/PacerFactory.h>

namespace quic {

std::unique_ptr<Pacer> createPacer(
    const QuicConnectionStateBase& /* conn */,
    uint64_t /* minCwndInMss */) {
  // Mobile builds don't use pacing to reduce binary size.
  // The transport has null checks for the pacer throughout.
  return nullptr;
}

} // namespace quic
