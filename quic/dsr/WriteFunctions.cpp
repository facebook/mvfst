/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/dsr/WriteFunctions.h>

namespace quic {
uint64_t writePacketizationRequest(
    QuicConnectionStateBase& connection,
    DSRStreamFrameScheduler& scheduler,
    const ConnectionId& dstCid,
    size_t packetLimit,
    const Aead& aead,
    DSRPacketizationRequestSender& sender) {
  auto writeLoopBeginTime = Clock::now();
  uint64_t packetCounter = 0;
  // TODO: Do i maintain this ad-hoc packetCounter, or should
  // DSRPacketizationRequestSender maintains a counter?
  while (scheduler.hasPendingData() && packetCounter < packetLimit &&
         (packetCounter < connection.transportSettings.maxBatchSize ||
          writeLoopTimeLimit(writeLoopBeginTime, connection))) {
    auto packetNum = getNextPacketNum(connection, PacketNumberSpace::AppData);
    ShortHeader header(ProtectionType::KeyPhaseZero, dstCid, packetNum);
    auto writableBytes = std::min(
        connection.udpSendPacketLen,
        congestionControlWritableBytes(connection));
    uint64_t cipherOverhead = aead.getCipherOverhead();
    if (writableBytes < cipherOverhead) {
      writableBytes = 0;
    } else {
      writableBytes -= cipherOverhead;
    }

    DSRPacketBuilder packetBuilder(
        writableBytes,
        std::move(header),
        getAckState(connection, PacketNumberSpace::AppData)
            .largestAckedByPeer.value_or(0));
    bool schedulerWritten = scheduler.writeStream(packetBuilder);
    if (!schedulerWritten) {
      /**
       * Scheduling can fail when we:
       * (1) run out of flow control
       * (2) there is actually no DSR stream to write - we shouldn't come here
       *     in the first place though.
       * (3) Packet is no space left - e.g., due to CC
       * (4) Error in write codec - Can that happen?
       *
       * At least for (1) and (3), we should flush the sender.
       */
      sender.flush();
      return packetCounter;
    }
    auto packet = std::move(packetBuilder).buildPacket();
    // The contract is that if scheduler can schedule, builder has to be able to
    // build.
    CHECK_GT(packet.encodedSize, 0);
    bool instructionAddError = false;
    for (const auto& instruction : packet.sendInstructions) {
      // Yes, it is wasteful to add the same conn and cipher info to every
      // instruction. On the other hand, they are very small.
      if (!sender.addSendInstruction(instruction)) {
        instructionAddError = true;
        break;
      }
    }

    // Similar to the regular write case, if we build, we update connection
    // states. The connection states are changed already no matter the result
    // of addSendInstruction() call.
    updateConnection(
        connection,
        folly::none /* Packet Event */,
        packet.packet,
        Clock::now(),
        packet.encodedSize,
        // TODO: (yangchi) Figure out how to calculate the
        // packet.encodedBodySize for the DSR case. For now, it's not being
        // used, so setting it to 0
        0,
        true /* isDSRPacket */);

    if (instructionAddError) {
      // TODO: should I flush? This depends on the sender I think.
      // TODO: Support empty write loop detection
      return packetCounter;
    }
    ++packetCounter;
  }
  sender.flush();
  return packetCounter;
}
} // namespace quic
