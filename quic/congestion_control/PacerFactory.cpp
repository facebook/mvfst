/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/PacerFactory.h>

#include <quic/congestion_control/TokenlessPacer.h>

namespace quic {

std::unique_ptr<Pacer> createPacer(
    const QuicConnectionStateBase& conn,
    uint64_t minCwndInMss) {
  return std::make_unique<TokenlessPacer>(conn, minCwndInMss);
}

} // namespace quic
