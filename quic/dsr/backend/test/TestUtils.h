/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/dsr/Types.h>
#include <quic/dsr/backend/DSRPacketizer.h>

#pragma once

namespace quic::test {

quic::PacketizationRequest sendInstructionToPacketizationRequest(
    const quic::SendInstruction& instruction) {
  quic::PacketizationRequest request(
      instruction.packetNum,
      instruction.largestAckedPacketNum,
      instruction.streamId,
      instruction.offset,
      instruction.len,
      instruction.fin,
      instruction.offset - instruction.bufMetaStartingOffset);
  return request;
}

} // namespace quic::test
