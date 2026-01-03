/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/logging/QLoggerMacros.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/observer/SocketObserverMacros.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

std::chrono::microseconds calculatePTO(const QuicConnectionStateBase& conn) {
  if (conn.lossState.srtt == 0us) {
    return 2 * conn.transportSettings.initialRtt;
  }
  return conn.lossState.srtt + 4 * conn.lossState.rttvar +
      conn.lossState.maxAckDelay;
}

bool isPersistentCongestion(
    OptionalMicros pto,
    TimePoint lostPeriodStart,
    TimePoint lostPeriodEnd,
    const CongestionController::AckEvent& ack) noexcept {
  if (!pto.has_value()) {
    return false;
  }

  auto exceedsDuration = (lostPeriodEnd - lostPeriodStart) >=
      pto.value() * kPersistentCongestionThreshold;

  if (!exceedsDuration) {
    return false;
  }

  auto it = std::find_if(
      ack.ackedPackets.cbegin(), ack.ackedPackets.cend(), [&](auto& ackPacket) {
        return ackPacket.outstandingPacketMetadata.time >= lostPeriodStart &&
            ackPacket.outstandingPacketMetadata.time <= lostPeriodEnd;
      });

  return it == ack.ackedPackets.cend();
}

quic::Expected<void, QuicError> onPTOAlarm(QuicConnectionStateBase& conn) {
  MVVLOG(10) << __func__ << " " << conn;
  if (conn.transportSettings.isPriming) {
    // No retransmits in Priming mode
    return {};
  }
  QUIC_STATS(conn.statsCallback, onPTO);
  conn.lossState.ptoCount++;
  conn.lossState.totalPTOCount++;
  QLOG(
      conn,
      addLossAlarm,
      conn.lossState.largestSent.value_or(0),
      conn.lossState.ptoCount,
      conn.outstandings.numOutstanding(),
      kPtoAlarm);
  if (conn.lossState.ptoCount >= conn.transportSettings.maxNumPTOs) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(LocalErrorCode::CONNECTION_ABANDONED),
        "Exceeded max PTO"));
  }

  // The first PTO after the oneRttWriteCipher is available is an opportunity to
  // retransmit unacknowledged 0-rtt data. It may be done only once.
  if (conn.transportSettings.earlyRetransmit0Rtt &&
      !conn.lossState.attemptedEarlyRetransmit0Rtt && conn.oneRttWriteCipher) {
    conn.lossState.attemptedEarlyRetransmit0Rtt = true;
    auto markResult = markZeroRttPacketsLost(conn, markPacketLoss);
    if (!markResult.has_value()) {
      MVVLOG(3)
          << "Closing connection due to error marking 0-RTT packets lost: "
          << markResult.error().message;
      return markResult;
    }
  }

  // We should avoid sending pointless PTOs if we don't have packets in the loss
  // buffer or enough outstanding packets to send.
  auto& packetCount = conn.outstandings.packetCount;
  auto& numProbePackets = conn.pendingEvents.numProbePackets;
  // Zero it out so we don't try to send probes for spaces without a cipher.
  numProbePackets = {};
  if (conn.initialWriteCipher) {
    numProbePackets[PacketNumberSpace::Initial] = kPacketToSendForPTO;
    if (conn.cryptoState->initialStream.lossBuffer.empty() &&
        packetCount[PacketNumberSpace::Initial] < kPacketToSendForPTO) {
      numProbePackets[PacketNumberSpace::Initial] =
          packetCount[PacketNumberSpace::Initial];
    }
  }
  if (conn.handshakeWriteCipher) {
    numProbePackets[PacketNumberSpace::Handshake] = kPacketToSendForPTO;
    if (conn.cryptoState->handshakeStream.lossBuffer.empty() &&
        packetCount[PacketNumberSpace::Handshake] < kPacketToSendForPTO) {
      numProbePackets[PacketNumberSpace::Handshake] =
          packetCount[PacketNumberSpace::Handshake];
    }
  }
  if (conn.oneRttWriteCipher) {
    numProbePackets[PacketNumberSpace::AppData] = kPacketToSendForPTO;
    if (conn.cryptoState->oneRttStream.lossBuffer.empty() &&
        !conn.streamManager->hasLoss() &&
        packetCount[PacketNumberSpace::AppData] < kPacketToSendForPTO) {
      numProbePackets[PacketNumberSpace::AppData] =
          packetCount[PacketNumberSpace::AppData];
    }
  }
  return {};
}

quic::Expected<void, QuicError> markPacketLoss(
    QuicConnectionStateBase& conn,
    PathIdType pathId,
    RegularQuicWritePacket& packet,
    bool processed) {
  QUIC_STATS(conn.statsCallback, onPacketLoss);
  InlineSet<uint64_t, 10> streamsWithAddedStreamLossForPacket;
  for (auto& packetFrame : packet.frames) {
    quic::Expected<QuicStreamState*, QuicError> streamResult = nullptr;

    switch (packetFrame.type()) {
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        MaxStreamDataFrame& frame = *packetFrame.asMaxStreamDataFrame();
        // For all other frames, we process it if it's not from a clone
        // packet, or if the clone and its siblings have never been processed.
        // But for both MaxData and MaxStreamData, we opportunistically send
        // an update to avoid stalling the peer.
        streamResult = conn.streamManager->getStream(frame.streamId);
        if (!streamResult.has_value()) {
          MVVLOG(4) << "Failed to get stream " << frame.streamId
                    << " in markPacketLoss (MaxStreamDataFrame): "
                    << streamResult.error().message;
          return quic::make_unexpected(streamResult.error());
        }
        auto* stream = streamResult.value();
        if (!stream) {
          break;
        }
        // TODO: check for the stream is in Open or HalfClosedLocal state, the
        // peer doesn't need a flow control update in these cases.
        onStreamWindowUpdateLost(*stream);
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        onConnWindowUpdateLost(conn);
        break;
      }
        // For other frame types, we only process them if the packet is not a
      // processed clone.
      case QuicWriteFrame::Type::DataBlockedFrame: {
        if (processed) {
          break;
        }
        onDataBlockedLost(conn);
        break;
      }
      case QuicWriteFrame::Type::WriteStreamFrame: {
        WriteStreamFrame frame = *packetFrame.asWriteStreamFrame();
        if (processed) {
          break;
        }
        streamResult = conn.streamManager->getStream(frame.streamId);
        if (!streamResult.has_value()) {
          MVVLOG(4) << "Failed to get stream " << frame.streamId
                    << " in markPacketLoss (WriteStreamFrame): "
                    << streamResult.error().message;
          return quic::make_unexpected(streamResult.error());
        }
        auto* stream = streamResult.value();
        if (!stream) {
          break;
        }

        auto bufferItr = stream->retransmissionBuffer.find(frame.offset);
        if (bufferItr == stream->retransmissionBuffer.end()) {
          break;
        }
        if (!streamRetransmissionDisabled(conn, *stream)) {
          stream->insertIntoLossBuffer(std::move(bufferItr->second));
        }
        if (streamsWithAddedStreamLossForPacket.find(frame.streamId) ==
            streamsWithAddedStreamLossForPacket.end()) {
          stream->streamLossCount++;
          streamsWithAddedStreamLossForPacket.insert(frame.streamId);
        }
        stream->retransmissionBuffer.erase(bufferItr);
        conn.streamManager->updateWritableStreams(*stream);
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
        WriteCryptoFrame& frame = *packetFrame.asWriteCryptoFrame();
        if (processed) {
          break;
        }
        auto protectionType = packet.header.getProtectionType();
        auto encryptionLevel = protectionTypeToEncryptionLevel(protectionType);
        auto cryptoStream = getCryptoStream(*conn.cryptoState, encryptionLevel);

        auto bufferItr = cryptoStream->retransmissionBuffer.find(frame.offset);
        if (bufferItr == cryptoStream->retransmissionBuffer.end()) {
          break;
        }
        DCHECK_EQ(bufferItr->second->offset, frame.offset);
        cryptoStream->insertIntoLossBuffer(std::move(bufferItr->second));
        cryptoStream->retransmissionBuffer.erase(bufferItr);
        break;
      }
      case QuicWriteFrame::Type::RstStreamFrame: {
        RstStreamFrame& frame = *packetFrame.asRstStreamFrame();
        if (processed) {
          break;
        }
        streamResult = conn.streamManager->getStream(frame.streamId);
        if (!streamResult.has_value()) {
          MVVLOG(4) << "Failed to get stream " << frame.streamId
                    << " in markPacketLoss (RstStreamFrame): "
                    << streamResult.error().message;
          return quic::make_unexpected(streamResult.error());
        }
        auto* stream = streamResult.value();
        if (!stream) {
          break;
        }
        conn.pendingEvents.resets.emplace(frame.streamId, frame);
        break;
      }
      case QuicWriteFrame::Type::StreamDataBlockedFrame: {
        StreamDataBlockedFrame& frame = *packetFrame.asStreamDataBlockedFrame();
        if (processed) {
          break;
        }
        streamResult = conn.streamManager->getStream(frame.streamId);
        if (!streamResult.has_value()) {
          MVVLOG(4) << "Failed to get stream " << frame.streamId
                    << " in markPacketLoss (StreamDataBlockedFrame): "
                    << streamResult.error().message;
          return quic::make_unexpected(streamResult.error());
        }
        auto* stream = streamResult.value();
        if (!stream) {
          break;
        }
        onBlockedLost(*stream);
        break;
      }
      case QuicWriteFrame::Type::QuicSimpleFrame: {
        QuicSimpleFrame& frame = *packetFrame.asQuicSimpleFrame();
        if (processed) {
          break;
        }
        updateSimpleFrameOnPacketLoss(conn, pathId, frame);
        break;
      }
      default:
        break;
    }
  }
  return {};
}

/**
 * Processes outstandings for loss and returns true if the loss timer should be
 * set. False otherwise.
 */
quic::Expected<bool, QuicError> processOutstandingsForLoss(
    QuicConnectionStateBase& conn,
    PacketNum largestAcked,
    const PacketNumberSpace& pnSpace,
    const TimePoint& lossTime,
    const std::chrono::microseconds& rttSample,
    const LossVisitor& lossVisitor,
    std::chrono::microseconds& delayUntilLost,
    CongestionController::LossEvent& lossEvent,
    Optional<SocketObserverInterface::LossEvent>& observerLossEvent) {
  bool shouldSetTimer = false;
  auto iter = getFirstOutstandingPacket(conn, pnSpace);
  while (iter != conn.outstandings.packets.end()) {
    if (iter->metadata.scheduledForDestruction) {
      iter++;
      continue;
    }

    auto& pkt = *iter;
    auto currentPacketNum = pkt.packet.header.getPacketSequenceNum();
    if (currentPacketNum >= largestAcked) {
      break;
    }
    auto currentPacketNumberSpace = pkt.packet.header.getPacketNumberSpace();
    if (currentPacketNumberSpace != pnSpace || iter->declaredLost) {
      iter++;
      continue;
    }

    auto largestAckedForComparison = largestAcked;

    // The max ensures that we don't overflow on the subtraction if the largest
    // ACKed is smaller.
    largestAckedForComparison =
        std::max(largestAckedForComparison, currentPacketNum);

    // TODO, should we ignore this if srtt == 0?
    bool lostByTimeout = (lossTime - pkt.metadata.time) > delayUntilLost;
    const auto reorderDistance = largestAckedForComparison - currentPacketNum;
    auto reorderingThreshold = conn.lossState.reorderingThreshold;

    if (conn.transportSettings.useInflightReorderingThreshold) {
      reorderingThreshold = std::max(
          conn.lossState.reorderingThreshold,
          std::min<uint32_t>(
              conn.outstandings.numOutstanding() / 2, kMaxReorderingThreshold));
    }
    const auto& skippedPacketNum = getAckState(conn, pnSpace).skippedPacketNum;
    if (skippedPacketNum && skippedPacketNum.value() >= currentPacketNum &&
        skippedPacketNum.value() <= largestAckedForComparison) {
      // A skipped packet number is in the distance we're measuring, so
      // we account for it in the reordering threshold.
      reorderingThreshold += 1;
    }
    bool lostByReorder = reorderDistance > reorderingThreshold;

    if (!(lostByTimeout || lostByReorder)) {
      shouldSetTimer = true;
      iter++;
      continue;
    }

    if (pkt.maybeClonedPacketIdentifier) {
      CHECK(conn.outstandings.clonedPacketCount[pnSpace]);
      --conn.outstandings.clonedPacketCount[pnSpace];
    }

    // Invoke LossVisitor if the packet doesn't have a associated
    // ClonedPacketIdentifier; or if the ClonedPacketIdentifier is present in
    // conn.outstandings.clonedPacketIdentifiers.
    bool processed = pkt.maybeClonedPacketIdentifier &&
        !conn.outstandings.clonedPacketIdentifiers.count(
            *pkt.maybeClonedPacketIdentifier);

    auto visitorResult =
        lossVisitor(conn, pkt.metadata.pathId, pkt.packet, processed);
    if (!visitorResult.has_value()) {
      return quic::make_unexpected(visitorResult.error());
    }

    if (pkt.maybeClonedPacketIdentifier) {
      conn.outstandings.clonedPacketIdentifiers.erase(
          *pkt.maybeClonedPacketIdentifier);
    }
    if (!processed) {
      CHECK(conn.outstandings.packetCount[currentPacketNumberSpace]);
      --conn.outstandings.packetCount[currentPacketNumberSpace];
    }

    MVVLOG(10) << __func__ << " lost packetNum=" << currentPacketNum;
    // Rather than erasing here, instead mark the packet as lost so we can
    // determine if this was spurious later.
    conn.lossState.totalPacketsMarkedLost++;
    if (lostByTimeout && rttSample.count() > 0) {
      conn.lossState.totalPacketsMarkedLostByTimeout++;
      pkt.metadata.lossTimeoutDividend = (lossTime - pkt.metadata.time) *
          conn.transportSettings.timeReorderingThreshDivisor / rttSample;
    }
    if (lostByReorder) {
      conn.lossState.totalPacketsMarkedLostByReorderingThreshold++;
      iter->metadata.lossReorderDistance = reorderDistance;
    }
    lossEvent.addLostPacket(pkt);
    if (observerLossEvent) {
      observerLossEvent->addLostPacket(
          pkt.metadata,
          pkt.packet.header.getPacketSequenceNum(),
          pkt.packet.header.getPacketNumberSpace());
    }
    conn.outstandings.declaredLostCount++;
    iter->declaredLost = true;
    iter++;
  }
  return shouldSetTimer;
}

/*
 * This function should be invoked after some event that is possible to
 * trigger loss detection, for example: packets are acked
 */
quic::Expected<Optional<CongestionController::LossEvent>, QuicError>
detectLossPackets(
    QuicConnectionStateBase& conn,
    const AckState& ackState,
    const LossVisitor& lossVisitor,
    const TimePoint lossTime,
    const PacketNumberSpace pnSpace) {
  getLossTime(conn, pnSpace).reset();
  std::chrono::microseconds rttSample =
      std::max(conn.lossState.srtt, conn.lossState.lrtt);
  std::chrono::microseconds delayUntilLost = rttSample *
      conn.transportSettings.timeReorderingThreshDividend /
      conn.transportSettings.timeReorderingThreshDivisor;
  MVVLOG(10) << __func__
             << " outstanding=" << conn.outstandings.numOutstanding()
             << " largestAcked=" << ackState.largestAckedByPeer.value_or(0)
             << " delayUntilLost=" << delayUntilLost.count() << "us" << " "
             << conn;
  CongestionController::LossEvent lossEvent(lossTime);
  Optional<SocketObserverInterface::LossEvent> observerLossEvent;
  {
    const auto socketObserverContainer = conn.getSocketObserverContainer();
    SOCKET_OBSERVER_IF(
        socketObserverContainer, SocketObserverInterface::Events::lossEvents) {
      observerLossEvent.emplace(lossTime);
    }
  }

  // Note that time based loss detection is also within the same PNSpace.

  bool shouldSetTimer = false;
  if (ackState.largestAckedByPeer.has_value()) {
    auto processResult = processOutstandingsForLoss(
        conn,
        *ackState.largestAckedByPeer,
        pnSpace,
        lossTime,
        rttSample,
        lossVisitor, // Pass the visitor (which returns Expected)
        delayUntilLost,
        lossEvent,
        observerLossEvent);

    if (!processResult.has_value()) {
      return quic::make_unexpected(processResult.error());
    }
    shouldSetTimer = processResult.value();
  }

  {
    const auto socketObserverContainer = conn.getSocketObserverContainer();
    if (observerLossEvent && observerLossEvent->hasPackets()) {
      SOCKET_OBSERVER_IF(
          socketObserverContainer,
          SocketObserverInterface::Events::lossEvents) {
        socketObserverContainer->invokeInterfaceMethod<
            SocketObserverInterface::Events::lossEvents>(
            [&](auto observer, auto observed) {
              observer->packetLossDetected(observed, *observerLossEvent);
            });
      }
    }
  }

  auto earliest = getFirstOutstandingPacket(conn, pnSpace);
  for (; earliest != conn.outstandings.packets.end();
       earliest = getNextOutstandingPacket(conn, pnSpace, earliest + 1)) {
    if (earliest->metadata.scheduledForDestruction) {
      earliest++;
    }
    if (!earliest->maybeClonedPacketIdentifier ||
        conn.outstandings.clonedPacketIdentifiers.count(
            *earliest->maybeClonedPacketIdentifier)) {
      break;
    }
  }

  if (shouldSetTimer && earliest != conn.outstandings.packets.end()) {
    // We are eligible to set a loss timer and there are a few packets which
    // are unacked, so we can set the early retransmit timer for them.
    MVVLOG(10) << __func__ << " early retransmit timer outstanding="
               << conn.outstandings.packets.empty() << " delayUntilLost"
               << delayUntilLost.count() << "us" << " " << conn;
    getLossTime(conn, pnSpace) = delayUntilLost + earliest->metadata.time;
  }

  if (lossEvent.largestLostPacketNum.has_value()) {
    DCHECK(lossEvent.largestLostSentTime && lossEvent.smallestLostSentTime);
    QLOG(
        conn,
        addPacketsLost,
        lossEvent.largestLostPacketNum.value(),
        lossEvent.lostBytes,
        lossEvent.lostPackets);

    conn.lossState.rtxCount += lossEvent.lostPackets;
    if (conn.congestionController) {
      return lossEvent;
    }
  }
  return std::nullopt;
}

quic::Expected<Optional<CongestionController::LossEvent>, QuicError>
handleAckForLoss(
    QuicConnectionStateBase& conn,
    const LossVisitor& lossVisitor,
    CongestionController::AckEvent& ack,
    PacketNumberSpace pnSpace) {
  auto& ackState = getAckState(conn, pnSpace);
  if (ack.largestNewlyAckedPacket.has_value()) {
    conn.lossState.ptoCount = 0;
    // Update the largest acked packet number
    ackState.largestAckedByPeer = std::max<PacketNum>(
        ackState.largestAckedByPeer.value_or(*ack.largestNewlyAckedPacket),
        *ack.largestNewlyAckedPacket);
  }
  auto lossEventResult =
      detectLossPackets(conn, ackState, lossVisitor, ack.ackTime, pnSpace);

  if (!lossEventResult.has_value()) {
    return quic::make_unexpected(lossEventResult.error());
  }

  conn.pendingEvents.setLossDetectionAlarm =
      conn.outstandings.numOutstanding() > 0;
  MVVLOG(10) << __func__ << " largestAckedInPacket="
             << ack.largestNewlyAckedPacket.value_or(0)
             << " setLossDetectionAlarm="
             << conn.pendingEvents.setLossDetectionAlarm
             << " outstanding=" << conn.outstandings.numOutstanding()
             << " initialPackets="
             << conn.outstandings.packetCount[PacketNumberSpace::Initial]
             << " handshakePackets="
             << conn.outstandings.packetCount[PacketNumberSpace::Handshake]
             << " " << conn;

  return lossEventResult.value();
}
} // namespace quic
