/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>

#include <cstdint>

namespace quic {

struct CachedServerTransportParameters {
  uint64_t idleTimeout{0};
  uint64_t maxRecvPacketSize{0};
  uint64_t initialMaxData{0};
  uint64_t initialMaxStreamDataBidiLocal{0};
  uint64_t initialMaxStreamDataBidiRemote{0};
  uint64_t initialMaxStreamDataUni{0};
  uint64_t initialMaxStreamsBidi{0};
  uint64_t initialMaxStreamsUni{0};
  uint64_t maxReceiveTimestampsPerAck{0};
  uint64_t receiveTimestampsExponent{0};
  bool knobFrameSupport{false};
  bool ackReceiveTimestampsEnabled{false};
};

} // namespace quic
