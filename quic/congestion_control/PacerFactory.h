/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <memory>
#include <cstdint>

namespace quic {
struct Pacer;
struct QuicConnectionStateBase;

/**
 * Creates a Pacer for the given connection.
 *
 * On mobile builds, this returns nullptr to reduce binary size.
 * The transport already has null checks for the pacer throughout.
 */
std::unique_ptr<Pacer> createPacer(
    const QuicConnectionStateBase& conn,
    uint64_t minCwndInMss);

} // namespace quic
