/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/Types.h>
#include <quic/state/StateData.h>

namespace quic {

/**
 * Processes a Datagram frame
 */
void handleDatagram(
    QuicConnectionStateBase& conn,
    DatagramFrame& frame,
    TimePoint recvTimePoint);

} // namespace quic
