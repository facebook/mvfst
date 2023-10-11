/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/ScopeGuard.h>
#include <quic/dsr/frontend/WriteFunctions.h>

namespace quic {
uint64_t writePacketizationRequest(
    QuicServerConnectionState& connection,
    const ConnectionId& dstCid,
    size_t packetLimit,
    const Aead& aead,
    TimePoint writeLoopBeginTime) {
  DSRStreamFrameScheduler scheduler(connection);
  uint64_t packetCounter = 0;
  folly::F14FastSet<DSRPacketizationRequestSender*> senders;
  SCOPE_EXIT {
    for (auto sender : senders) {
      if (connection.qLogger) {
        connection.qLogger->addTransportStateUpdate("DSR flushing sender");
      }
      sender->flush();
    }
  };
  if (!writeLoopTimeLimit(writeLoopBeginTime, connection)) {
    return packetCounter;
  }
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
    auto schedulerResult = scheduler.writeStream(packetBuilder);
    if (!schedulerResult.writeSuccess) {
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
      if (schedulerResult.sender) {
        senders.insert(schedulerResult.sender);
      }
      return packetCounter;
    }
    CHECK(schedulerResult.sender);
    auto packet = std::move(packetBuilder).buildPacket();
    // The contract is that if scheduler can schedule, builder has to be able to
    // build.
    CHECK_GT(packet.encodedSize, 0u);
    bool instructionAddError = false;
    for (const auto& instruction : packet.sendInstructions) {
      if (!schedulerResult.sender->addSendInstruction(instruction)) {
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
        packet.encodedSize + cipherOverhead,
        // TODO: (yangchi) Figure out how to calculate the
        // packet.encodedBodySize for the DSR case. For now, it's not being
        // used, so setting it to 0
        0,
        true /* isDSRPacket */);
    connection.dsrPacketCount++;

    if (instructionAddError) {
      // TODO: Support empty write loop detection
      senders.insert(schedulerResult.sender);
      return packetCounter;
    }
    ++packetCounter;
    senders.insert(schedulerResult.sender);
  }
  return packetCounter;
}
} // namespace quic
