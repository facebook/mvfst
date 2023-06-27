/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/small_vector.h>
#include <quic/loss/QuicLossFunctions.h>
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
    folly::Optional<std::chrono::microseconds> pto,
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

void onPTOAlarm(QuicConnectionStateBase& conn) {
  VLOG(10) << __func__ << " " << conn;
  QUIC_STATS(conn.statsCallback, onPTO);
  conn.lossState.ptoCount++;
  conn.lossState.totalPTOCount++;
  if (conn.qLogger) {
    conn.qLogger->addLossAlarm(
        conn.lossState.largestSent.value_or(0),
        conn.lossState.ptoCount,
        conn.outstandings.numOutstanding(),
        kPtoAlarm);
  }
  if (conn.lossState.ptoCount == conn.transportSettings.maxNumPTOs) {
    throw QuicInternalException(
        "Exceeded max PTO", LocalErrorCode::CONNECTION_ABANDONED);
  }

  // The first PTO after the oneRttWriteCipher is available is an opportunity to
  // retransmit unacknowledged 0-rtt data. It may be done only once.
  if (conn.transportSettings.earlyRetransmit0Rtt &&
      !conn.lossState.attemptedEarlyRetransmit0Rtt && conn.oneRttWriteCipher) {
    conn.lossState.attemptedEarlyRetransmit0Rtt = true;
    markZeroRttPacketsLost(conn, markPacketLoss);
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
}

template <class T, size_t N>
using InlineSetVec = folly::small_vector<T, N>;

template <
    typename Value,
    size_t N,
    class Container = InlineSetVec<Value, N>,
    typename = std::enable_if_t<std::is_integral<Value>::value>>
using InlineSet = folly::heap_vector_set<
    Value,
    std::less<Value>,
    typename Container::allocator_type,
    void,
    Container>;

void markPacketLoss(
    QuicConnectionStateBase& conn,
    RegularQuicWritePacket& packet,
    bool processed) {
  QUIC_STATS(conn.statsCallback, onPacketLoss);
  InlineSet<uint64_t, 10> streamsWithAddedStreamLossForPacket;
  for (auto& packetFrame : packet.frames) {
    switch (packetFrame.type()) {
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        MaxStreamDataFrame& frame = *packetFrame.asMaxStreamDataFrame();
        // For all other frames, we process it if it's not from a clone
        // packet, or if the clone and its siblings have never been processed.
        // But for both MaxData and MaxStreamData, we opportunistically send
        // an update to avoid stalling the peer.
        auto stream = conn.streamManager->getStream(frame.streamId);
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
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (!stream) {
          break;
        }
        if (!frame.fromBufMeta) {
          auto bufferItr = stream->retransmissionBuffer.find(frame.offset);
          if (bufferItr == stream->retransmissionBuffer.end()) {
            // It's possible that the stream was reset or data on the stream was
            // skipped while we discovered that its packet was lost so we might
            // not have the offset.
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
        } else {
          auto retxBufMetaItr =
              stream->retransmissionBufMetas.find(frame.offset);
          if (retxBufMetaItr == stream->retransmissionBufMetas.end()) {
            break;
          }
          auto& bufMeta = retxBufMetaItr->second;
          CHECK_EQ(bufMeta.offset, frame.offset);
          CHECK_EQ(bufMeta.length, frame.len);
          CHECK_EQ(bufMeta.eof, frame.fin);
          if (!streamRetransmissionDisabled(conn, *stream)) {
            stream->insertIntoLossBufMeta(retxBufMetaItr->second);
          }
          if (streamsWithAddedStreamLossForPacket.find(frame.streamId) ==
              streamsWithAddedStreamLossForPacket.end()) {
            stream->streamLossCount++;
            streamsWithAddedStreamLossForPacket.insert(frame.streamId);
          }
          stream->retransmissionBufMetas.erase(retxBufMetaItr);
        }
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
          // It's possible that the stream was reset while we discovered that
          // it's packet was lost so we might not have the offset.
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
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (!stream) {
          // If the stream is dead, ignore the retransmissions of the rst
          // stream.
          break;
        }
        // Add the lost RstStreamFrame back to pendingEvents:
        conn.pendingEvents.resets.insert({frame.streamId, frame});
        break;
      }
      case QuicWriteFrame::Type::StreamDataBlockedFrame: {
        StreamDataBlockedFrame& frame = *packetFrame.asStreamDataBlockedFrame();
        if (processed) {
          break;
        }
        auto stream = conn.streamManager->getStream(frame.streamId);
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
        updateSimpleFrameOnPacketLoss(conn, frame);
        break;
      }
      default:
        // ignore the rest of the frames.
        break;
    }
  }
}

/**
 * Processes outstandings for loss and returns true if the loss timer should be
 * set. False otherwise.
 */
bool processOutstandingsForLoss(
    QuicConnectionStateBase& conn,
    PacketNum largestAcked,
    const PacketNumberSpace& pnSpace,
    const InlineMap<StreamId, PacketNum, 20>& largestDsrAcked,
    const folly::Optional<PacketNum>& largestNonDsrAcked,
    const TimePoint& lossTime,
    const std::chrono::microseconds& rttSample,
    const LossVisitor& lossVisitor,
    std::chrono::microseconds& delayUntilLost,
    CongestionController::LossEvent& lossEvent,
    folly::Optional<SocketObserverInterface::LossEvent>& observerLossEvent) {
  bool shouldSetTimer = false;
  auto iter = getFirstOutstandingPacket(conn, pnSpace);
  while (iter != conn.outstandings.packets.end()) {
    auto& pkt = *iter;
    auto currentPacketNum = pkt.packet.header.getPacketSequenceNum();
    folly::Optional<uint64_t> maybeCurrentStreamPacketIdx;
    if (currentPacketNum >= largestAcked) {
      break;
    }
    auto currentPacketNumberSpace = pkt.packet.header.getPacketNumberSpace();
    if (currentPacketNumberSpace != pnSpace || iter->declaredLost) {
      iter++;
      continue;
    }

    // We now have to determine the largest ACKed packet number we should use
    // for the reordering threshold loss determination.
    auto maybeStreamFrame = pkt.packet.frames.empty()
        ? nullptr
        : pkt.packet.frames.front().asWriteStreamFrame();
    // For DSR we use the stream packet index (monotonic index of packets
    // within a stream) to determine reordering loss. This effectively puts
    // DSR packets on their own packet number timeline.
    auto largestAckedForComparison = [&]() -> PacketNum {
      if (maybeStreamFrame && maybeStreamFrame->fromBufMeta) {
        maybeCurrentStreamPacketIdx = maybeStreamFrame->streamPacketIdx;
        // If the packet being considered is a DSR packet, we use the
        // largest ACKed for that stream. The default value here covers the
        // case where no DSR packets were ACKed, in which case we should
        // not declare reorder loss.
        CHECK(pkt.isDSRPacket);
        return folly::get_default(
            largestDsrAcked,
            maybeStreamFrame->streamId,
            *maybeCurrentStreamPacketIdx);
      } else {
        // If the packet being considered is a non-DSR packet, the
        // straightforward case is to use the largest non-DSR ACKed.
        // If DSR packets have been ACKed, we need to use the largest
        // non-DSR ACKed. If there were no non-DSR ACKed, we shouldn't
        // declare reorder loss.
        if (largestDsrAcked.empty()) {
          return largestNonDsrAcked.value();
        } else {
          return largestNonDsrAcked.value_or(currentPacketNum);
        }
      }
    }();

    // Use the translated virtual number for the current packet if it's a DSR
    // packet, or the non DSR sequence number otherwise.
    if (maybeCurrentStreamPacketIdx.has_value()) {
      currentPacketNum = *maybeCurrentStreamPacketIdx;
    } else if (pkt.nonDsrPacketSequenceNumber.has_value()) {
      currentPacketNum = pkt.nonDsrPacketSequenceNumber.value();
    }
    // The max ensures that we don't overflow on the subtraction if the largest
    // ACKed is smaller.
    largestAckedForComparison =
        std::max(largestAckedForComparison, currentPacketNum);

    bool lostByTimeout = (lossTime - pkt.metadata.time) > delayUntilLost;
    const auto reorderDistance = largestAckedForComparison - currentPacketNum;
    bool lostByReorder = reorderDistance > conn.lossState.reorderingThreshold;

    if (!(lostByTimeout || lostByReorder)) {
      shouldSetTimer = true;
      iter++;
      continue;
    }

    if (pkt.isDSRPacket) {
      CHECK_GT(conn.outstandings.dsrCount, 0);
      --conn.outstandings.dsrCount;
    }
    if (pkt.associatedEvent) {
      CHECK(conn.outstandings.clonedPacketCount[pnSpace]);
      --conn.outstandings.clonedPacketCount[pnSpace];
    }
    // Invoke LossVisitor if the packet doesn't have a associated PacketEvent;
    // or if the PacketEvent is present in conn.outstandings.packetEvents.
    bool processed = pkt.associatedEvent &&
        !conn.outstandings.packetEvents.count(*pkt.associatedEvent);
    lossVisitor(conn, pkt.packet, processed);
    // Remove the PacketEvent from the outstandings.packetEvents set
    if (pkt.associatedEvent) {
      conn.outstandings.packetEvents.erase(*pkt.associatedEvent);
    }
    if (!processed) {
      CHECK(conn.outstandings.packetCount[currentPacketNumberSpace]);
      --conn.outstandings.packetCount[currentPacketNumberSpace];
    }
    VLOG(10) << __func__ << " lost packetNum=" << currentPacketNum
             << " handshake=" << pkt.metadata.isHandshake << " " << conn;
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
folly::Optional<CongestionController::LossEvent> detectLossPackets(
    QuicConnectionStateBase& conn,
    const folly::Optional<PacketNum> largestAcked,
    const LossVisitor& lossVisitor,
    const TimePoint lossTime,
    const PacketNumberSpace pnSpace,
    const CongestionController::AckEvent* ackEvent) {
  getLossTime(conn, pnSpace).reset();
  std::chrono::microseconds rttSample =
      std::max(conn.lossState.srtt, conn.lossState.lrtt);
  std::chrono::microseconds delayUntilLost = rttSample *
      conn.transportSettings.timeReorderingThreshDividend /
      conn.transportSettings.timeReorderingThreshDivisor;
  VLOG(10) << __func__ << " outstanding=" << conn.outstandings.numOutstanding()
           << " largestAcked=" << largestAcked.value_or(0)
           << " delayUntilLost=" << delayUntilLost.count() << "us"
           << " " << conn;
  CongestionController::LossEvent lossEvent(lossTime);
  folly::Optional<SocketObserverInterface::LossEvent> observerLossEvent;
  {
    const auto socketObserverContainer = conn.getSocketObserverContainer();
    if (socketObserverContainer &&
        socketObserverContainer->hasObserversForEvent<
            SocketObserverInterface::Events::lossEvents>()) {
      observerLossEvent.emplace(lossTime);
    }
  }
  // Note that time based loss detection is also within the same PNSpace.

  // Loop over all ACKed packets and collect the largest ACKed packet per DSR
  // stream. This facilitates only considering the reordering threshold per DSR
  // sender, which avoids the problem of "natural" reordering caused by
  // multiple DSR senders. Similarly track the largest non-DSR ACKed, for the
  // reason but when DSR packets are reordered "before" non-DSR packets.
  InlineMap<StreamId, PacketNum, 20> largestDsrAcked;
  folly::Optional<PacketNum> largestNonDsrAcked;
  if (ackEvent) {
    for (const auto& ackPacket : ackEvent->ackedPackets) {
      for (auto& [stream, details] : ackPacket.detailsPerStream) {
        if (details.streamPacketIdx) {
          largestDsrAcked[stream] = std::max(
              folly::get_default(
                  largestDsrAcked, stream, *details.streamPacketIdx),
              *details.streamPacketIdx);
        } else {
          largestNonDsrAcked = std::max(
              largestNonDsrAcked.value_or(0),
              ackPacket.nonDsrPacketSequenceNumber);
        }
      }
      // If there are no streams, then it's not a DSR packet.
      if (ackPacket.detailsPerStream.empty()) {
        largestNonDsrAcked = std::max(
            largestNonDsrAcked.value_or(0),
            ackPacket.nonDsrPacketSequenceNumber);
      }
    }
  }
  // This covers the case where there's no ackedPackets.
  if (largestDsrAcked.empty() && largestAcked.has_value()) {
    largestNonDsrAcked = largestNonDsrAcked.value_or(largestAcked.value());
  }

  bool shouldSetTimer = false;
  if (largestAcked.has_value()) {
    shouldSetTimer = processOutstandingsForLoss(
        conn,
        *largestAcked,
        pnSpace,
        largestDsrAcked,
        largestNonDsrAcked,
        lossTime,
        rttSample,
        lossVisitor,
        delayUntilLost,
        lossEvent,
        observerLossEvent);
  }

  // notify observers
  {
    const auto socketObserverContainer = conn.getSocketObserverContainer();
    if (observerLossEvent && observerLossEvent->hasPackets() &&
        socketObserverContainer &&
        socketObserverContainer->hasObserversForEvent<
            SocketObserverInterface::Events::lossEvents>()) {
      socketObserverContainer
          ->invokeInterfaceMethod<SocketObserverInterface::Events::lossEvents>(
              [observerLossEvent](auto observer, auto observed) {
                observer->packetLossDetected(observed, *observerLossEvent);
              });
    }
  }

  auto earliest = getFirstOutstandingPacket(conn, pnSpace);
  for (; earliest != conn.outstandings.packets.end();
       earliest = getNextOutstandingPacket(conn, pnSpace, earliest + 1)) {
    if (!earliest->associatedEvent ||
        conn.outstandings.packetEvents.count(*earliest->associatedEvent)) {
      break;
    }
  }
  if (shouldSetTimer && earliest != conn.outstandings.packets.end()) {
    // We are eligible to set a loss timer and there are a few packets which
    // are unacked, so we can set the early retransmit timer for them.
    VLOG(10) << __func__ << " early retransmit timer outstanding="
             << conn.outstandings.packets.empty() << " delayUntilLost"
             << delayUntilLost.count() << "us"
             << " " << conn;
    getLossTime(conn, pnSpace) = delayUntilLost + earliest->metadata.time;
  }
  if (lossEvent.largestLostPacketNum.hasValue()) {
    DCHECK(lossEvent.largestLostSentTime && lossEvent.smallestLostSentTime);
    if (conn.qLogger) {
      conn.qLogger->addPacketsLost(
          lossEvent.largestLostPacketNum.value(),
          lossEvent.lostBytes,
          lossEvent.lostPackets);
    }

    conn.lossState.rtxCount += lossEvent.lostPackets;
    if (conn.congestionController) {
      return lossEvent;
    }
  }
  return folly::none;
}

folly::Optional<CongestionController::LossEvent> handleAckForLoss(
    QuicConnectionStateBase& conn,
    const LossVisitor& lossVisitor,
    CongestionController::AckEvent& ack,
    PacketNumberSpace pnSpace) {
  auto& largestAcked = getAckState(conn, pnSpace).largestAckedByPeer;
  if (ack.largestNewlyAckedPacket.has_value()) {
    conn.lossState.ptoCount = 0;
    largestAcked = std::max<PacketNum>(
        largestAcked.value_or(*ack.largestNewlyAckedPacket),
        *ack.largestNewlyAckedPacket);
  }
  auto lossEvent = detectLossPackets(
      conn,
      getAckState(conn, pnSpace).largestAckedByPeer,
      lossVisitor,
      ack.ackTime,
      pnSpace,
      &ack);
  conn.pendingEvents.setLossDetectionAlarm =
      conn.outstandings.numOutstanding() > 0;
  VLOG(10) << __func__ << " largestAckedInPacket="
           << ack.largestNewlyAckedPacket.value_or(0)
           << " setLossDetectionAlarm="
           << conn.pendingEvents.setLossDetectionAlarm
           << " outstanding=" << conn.outstandings.numOutstanding()
           << " initialPackets="
           << conn.outstandings.packetCount[PacketNumberSpace::Initial]
           << " handshakePackets="
           << conn.outstandings.packetCount[PacketNumberSpace::Handshake] << " "
           << conn;
  return lossEvent;
}

} // namespace quic
