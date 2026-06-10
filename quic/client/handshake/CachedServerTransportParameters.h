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
  // Underlying type is currently uint8_t so this struct is still packed
  ExtendedAckFeatureMaskType extendedAckFeatures{0};
  bool knobFrameSupport{false};
  bool ackReceiveTimestampsEnabled{false};
  bool reliableStreamResetSupport{false};
  // Disambiguates whether the cached max/exponent above came from the
  // legacy TPs or the draft-02 TPs so 0-RTT resumption restores the right
  // `maybePeerReceiveTimestampsConfig`.
  AckReceiveTimestampsVersion cachedReceiveTimestampsVersion{
      AckReceiveTimestampsVersion::None};
  uint64_t draft02MaxReceiveTimestampsPerAck{0};
  uint64_t draft02ReceiveTimestampsExponent{0};
};

} // namespace quic
