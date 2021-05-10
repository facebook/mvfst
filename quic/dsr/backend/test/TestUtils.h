/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/dsr/Types.h>
#include <quic/dsr/backend/DSRPacketizer.h>

#pragma once

namespace quic::test {

quic::PacketizationRequest sendInstructionToPacketizationRequest(
    const quic::SendInstruction& instruction) {
  quic::PacketizationRequest request(instruction.dcid, instruction.scid);
  request.clientAddress = instruction.clientAddress;
  request.packetNum = instruction.packetNum;
  request.largestAckedPacketNum = instruction.largestAckedPacketNum;
  request.streamId = instruction.streamId;
  request.offset = instruction.offset;
  request.len = instruction.len;
  request.fin = instruction.fin;
  request.bufMetaStartingOffset = instruction.bufMetaStartingOffset;
  request.trafficKey.key = instruction.trafficKey.key->clone();
  request.trafficKey.iv = instruction.trafficKey.iv->clone();
  request.cipherSuite = instruction.cipherSuite;
  request.packetProtectionKey = instruction.packetProtectionKey->clone();
  return request;
}

} // namespace quic::test
