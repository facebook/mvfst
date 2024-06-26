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
  uint64_t idleTimeout;
  uint64_t maxRecvPacketSize;
  uint64_t initialMaxData;
  uint64_t initialMaxStreamDataBidiLocal;
  uint64_t initialMaxStreamDataBidiRemote;
  uint64_t initialMaxStreamDataUni;
  uint64_t initialMaxStreamsBidi;
  uint64_t initialMaxStreamsUni;
  uint64_t maxReceiveTimestampsPerAck;
  uint64_t receiveTimestampsExponent;
  bool knobFrameSupport{false};
  bool ackReceiveTimestampsEnabled{false};
};

} // namespace quic
