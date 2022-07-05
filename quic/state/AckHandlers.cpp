/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/MapUtil.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <iterator>

namespace quic {

namespace {
/**
 * Structure used to to enable packets to be processed in sent order.
 *
 * Contains context required for deferred processing.
 */
struct OutstandingPacketWithHandlerContext {
  explicit OutstandingPacketWithHandlerContext(
      OutstandingPacket outstandingPacketIn)
      : outstandingPacket(std::move(outstandingPacketIn)) {}

  OutstandingPacket outstandingPacket;
  bool processAllFrames{false};
};

} // namespace

/**
 * Process ack frame and acked outstanding packets.
 *
 * This function process incoming ack blocks which is sorted in the descending
 * order of packet number. For each ack block, we try to find a continuous range
 * of outstanding packets in the connection's outstanding packets list that is
 * acked by the current ack block. The search is in the reverse order of the
 * outstandings.packets given that the list is sorted in the ascending order of
 * packet number. For each outstanding packet that is acked by current ack
 * frame, ack and loss visitors are invoked on the sent frames. The outstanding
 * packets may contain packets from all three packet number spaces. But ack is
 * always restrained to a single space. So we also need to skip packets that are
 * not in the current packet number space.
 *
 */

AckEvent processAckFrame(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    const ReadAckFrame& frame,
    const AckVisitor& ackVisitor,
    const LossVisitor& lossVisitor,
    const TimePoint& ackReceiveTime) {
  const auto nowTime = Clock::now();

  // TODO: send error if we get an ack for a packet we've not sent t18721184
  auto ack = AckEvent::Builder()
                 .setAckTime(ackReceiveTime)
                 .setAdjustedAckTime(ackReceiveTime - frame.ackDelay)
                 .setAckDelay(frame.ackDelay)
                 .setPacketNumberSpace(pnSpace)
                 .setLargestAckedPacket(frame.largestAcked)
                 .setIsImplicitAck(frame.implicit)
                 .build();

  // temporary storage to enable packets to be processed in sent order
  SmallVec<OutstandingPacketWithHandlerContext, 50, uint64_t>
      packetsWithHandlerContext;

  auto currentPacketIt = getLastOutstandingPacketIncludingLost(conn, pnSpace);
  uint64_t dsrPacketsAcked = 0;
  folly::Optional<decltype(conn.lossState.lastAckedPacketSentTime)>
      lastAckedPacketSentTime;
  folly::Optional<LegacyObserver::SpuriousLossEvent> spuriousLossEvent;
  // Used for debug only.
  const auto originalPacketCount = conn.outstandings.packetCount;
  if (conn.observerContainer &&
      conn.observerContainer->hasObserversForEvent<
          SocketObserverInterface::Events::spuriousLossEvents>()) {
    spuriousLossEvent.emplace(ackReceiveTime);
  }
  auto ackBlockIt = frame.ackBlocks.cbegin();
  while (ackBlockIt != frame.ackBlocks.cend() &&
         currentPacketIt != conn.outstandings.packets.rend()) {
    // In reverse order, find the first outstanding packet that has a packet
    // number LE the endPacket of the current ack range.
    auto rPacketIt = std::lower_bound(
        currentPacketIt,
        conn.outstandings.packets.rend(),
        ackBlockIt->endPacket,
        [&](const auto& packetWithTime, const auto& val) {
          return packetWithTime.packet.header.getPacketSequenceNum() > val;
        });
    if (rPacketIt == conn.outstandings.packets.rend()) {
      // This means that all the packets are greater than the end packet.
      // Since we iterate the ACK blocks in reverse order of end packets, our
      // work here is done.
      VLOG(10) << __func__ << " less than all outstanding packets outstanding="
               << conn.outstandings.numOutstanding() << " range=["
               << ackBlockIt->startPacket << ", " << ackBlockIt->endPacket
               << "]"
               << " " << conn;
      ackBlockIt++;
      break;
    }

    auto eraseEnd = rPacketIt;
    while (rPacketIt != conn.outstandings.packets.rend()) {
      auto currentPacketNum = rPacketIt->packet.header.getPacketSequenceNum();
      auto currentPacketNumberSpace =
          rPacketIt->packet.header.getPacketNumberSpace();
      if (pnSpace != currentPacketNumberSpace) {
        // When the next packet is not in the same packet number space, we need
        // to skip it in current ack processing. If the iterator has moved, that
        // means we have found packets in the current space that are acked by
        // this ack block. So the code erases the current iterator range and
        // move the iterator to be the next search point.
        if (rPacketIt != eraseEnd) {
          auto nextElem = conn.outstandings.packets.erase(
              rPacketIt.base(), eraseEnd.base());
          rPacketIt = std::reverse_iterator<decltype(nextElem)>(nextElem) + 1;
          eraseEnd = rPacketIt;
        } else {
          rPacketIt++;
          eraseEnd = rPacketIt;
        }
        continue;
      }
      if (currentPacketNum < ackBlockIt->startPacket) {
        break;
      }
      VLOG(10) << __func__ << " acked packetNum=" << currentPacketNum
               << " space=" << currentPacketNumberSpace << " handshake="
               << (int)((rPacketIt->metadata.isHandshake) ? 1 : 0) << " "
               << conn;
      // If we hit a packet which has been lost we need to count the spurious
      // loss and ignore all other processing.
      if (rPacketIt->declaredLost) {
        CHECK_GT(conn.outstandings.declaredLostCount, 0);
        conn.lossState.totalPacketsSpuriouslyMarkedLost++;
        if (conn.transportSettings.useAdaptiveLossReorderingThresholds) {
          if (rPacketIt->lossReorderDistance.hasValue() &&
              rPacketIt->lossReorderDistance.value() >
                  conn.lossState.reorderingThreshold) {
            conn.lossState.reorderingThreshold =
                rPacketIt->lossReorderDistance.value();
          }
        }
        if (conn.transportSettings.useAdaptiveLossTimeThresholds) {
          if (rPacketIt->lossTimeoutDividend.hasValue() &&
              rPacketIt->lossTimeoutDividend.value() >
                  conn.transportSettings.timeReorderingThreshDividend) {
            conn.transportSettings.timeReorderingThreshDividend =
                rPacketIt->lossTimeoutDividend.value();
          }
        }
        if (conn.transportSettings.removeFromLossBufferOnSpurious) {
          for (auto& f : rPacketIt->packet.frames) {
            auto streamFrame = f.asWriteStreamFrame();
            if (streamFrame) {
              auto stream =
                  conn.streamManager->findStream(streamFrame->streamId);
              if (stream) {
                stream->removeFromLossBuffer(
                    streamFrame->offset, streamFrame->len, streamFrame->fin);
                conn.streamManager->updateLossStreams(*stream);
                conn.streamManager->updateWritableStreams(*stream);
              }
            }
          }
        }
        QUIC_STATS(conn.statsCallback, onPacketSpuriousLoss);
        // Decrement the counter, trust that we will erase this as part of
        // the bulk erase.
        CHECK_GT(conn.outstandings.declaredLostCount, 0);
        conn.outstandings.declaredLostCount--;
        if (spuriousLossEvent) {
          spuriousLossEvent->addSpuriousPacket(*rPacketIt);
        }
        rPacketIt++;
        continue;
      }
      bool needsProcess = !rPacketIt->associatedEvent ||
          conn.outstandings.packetEvents.count(*rPacketIt->associatedEvent);
      if (needsProcess) {
        CHECK(conn.outstandings.packetCount[currentPacketNumberSpace]);
        --conn.outstandings.packetCount[currentPacketNumberSpace];
      }
      ack.ackedBytes += rPacketIt->metadata.encodedSize;
      if (rPacketIt->associatedEvent) {
        CHECK(conn.outstandings.clonedPacketCount[currentPacketNumberSpace]);
        --conn.outstandings.clonedPacketCount[currentPacketNumberSpace];
      }
      if (rPacketIt->isDSRPacket) {
        ++dsrPacketsAcked;
      }

      // Update RTT if current packet is the largestAcked in the frame
      //
      // An RTT sample is generated using only the largest acknowledged packet
      // in the received ACK frame. To avoid generating multiple RTT samples
      // for a single packet, an ACK frame SHOULD NOT be used to update RTT
      // estimates if it does not newly acknowledge the largest acknowledged
      // packet (RFC9002). This includes for minRTT estimates.
      if (!ack.implicit && currentPacketNum == frame.largestAcked) {
        auto ackReceiveTimeOrNow = ackReceiveTime > rPacketIt->metadata.time
            ? ackReceiveTime
            : nowTime;

        // Use ceil to round up to next microsecond during conversion.
        //
        // While unlikely, it's still technically possible for the RTT to be
        // zero; ignore if this is the case.
        auto rttSample = std::chrono::ceil<std::chrono::microseconds>(
            ackReceiveTimeOrNow - rPacketIt->metadata.time);
        if (rttSample != rttSample.zero()) {
          // notify observers
          if (conn.observerContainer &&
              conn.observerContainer->hasObserversForEvent<
                  SocketObserverInterface::Events::rttSamples>()) {
            conn.observerContainer->invokeInterfaceMethod<
                SocketObserverInterface::Events::rttSamples>(
                [event = SocketObserverInterface::PacketRTT(
                     ackReceiveTimeOrNow,
                     rttSample,
                     frame.ackDelay,
                     *rPacketIt)](auto observer, auto observed) {
                  observer->rttSampleGenerated(observed, event);
                });
          }

          // update AckEvent RTTs, which are used by CCA and other processing
          CHECK(!ack.rttSample.has_value());
          CHECK(!ack.rttSampleNoAckDelay.has_value());
          ack.rttSample = rttSample;
          ack.rttSampleNoAckDelay = (rttSample >= frame.ackDelay)
              ? folly::make_optional(
                    std::chrono::ceil<std::chrono::microseconds>(
                        rttSample - frame.ackDelay))
              : folly::none;

          // update transport RTT
          updateRtt(conn, rttSample, frame.ackDelay);
        } // if (rttSample != rttSample.zero())
      } // if (!ack.implicit && currentPacketNum == frame.largestAcked)

      // D6D probe acked. Only if it's for the last probe do we
      // trigger state change
      if (rPacketIt->metadata.isD6DProbe) {
        CHECK(conn.d6d.lastProbe);
        if (!rPacketIt->declaredLost) {
          ++conn.d6d.meta.totalAckedProbes;
          if (currentPacketNum == conn.d6d.lastProbe->packetNum) {
            onD6DLastProbeAcked(conn);
          }
        }
      }
      // Remove this PacketEvent from the outstandings.packetEvents set
      if (rPacketIt->associatedEvent) {
        conn.outstandings.packetEvents.erase(*rPacketIt->associatedEvent);
      }
      if (!ack.largestNewlyAckedPacket ||
          *ack.largestNewlyAckedPacket < currentPacketNum) {
        ack.largestNewlyAckedPacket = currentPacketNum;
        ack.largestNewlyAckedPacketSentTime = rPacketIt->metadata.time;
        ack.largestNewlyAckedPacketAppLimited = rPacketIt->isAppLimited;
      }
      if (!ack.implicit) {
        conn.lossState.totalBytesAcked += rPacketIt->metadata.encodedSize;
        conn.lossState.totalBytesSentAtLastAck = conn.lossState.totalBytesSent;
        conn.lossState.totalBytesAckedAtLastAck =
            conn.lossState.totalBytesAcked;
        conn.lossState.totalBodyBytesAcked +=
            rPacketIt->metadata.encodedBodySize;
        if (!lastAckedPacketSentTime) {
          lastAckedPacketSentTime = rPacketIt->metadata.time;
        }
        conn.lossState.lastAckedTime = ackReceiveTime;
        conn.lossState.adjustedLastAckedTime = ackReceiveTime - frame.ackDelay;
        ack.totalBytesAcked = conn.lossState.totalBytesAcked;
      }

      {
        auto tmpIt = packetsWithHandlerContext.emplace(
            std::find_if(
                packetsWithHandlerContext.rbegin(),
                packetsWithHandlerContext.rend(),
                [&currentPacketNum](const auto& packetWithHandlerContext) {
                  return packetWithHandlerContext.outstandingPacket.packet
                             .header.getPacketSequenceNum() > currentPacketNum;
                })
                .base(),
            std::move(*rPacketIt));
        tmpIt->processAllFrames = needsProcess;
      }

      rPacketIt++;
    }
    // Done searching for acked outstanding packets in current ack block. Erase
    // the current iterator range which is the last batch of continuous
    // outstanding packets that are in this ack block. Move the iterator to be
    // the next search point.
    if (rPacketIt != eraseEnd) {
      auto nextElem =
          conn.outstandings.packets.erase(rPacketIt.base(), eraseEnd.base());
      currentPacketIt = std::reverse_iterator<decltype(nextElem)>(nextElem);
    } else {
      currentPacketIt = rPacketIt;
    }
    ackBlockIt++;
  }

  // Invoke AckVisitor for WriteAckFrames all the time. Invoke it for other
  // frame types only if the packet doesn't have an associated PacketEvent;
  // or the PacketEvent is in conn.outstandings.packetEvents
  ack.ackedPackets.reserve(packetsWithHandlerContext.size());
  for (auto packetWithHandlerContextItr = packetsWithHandlerContext.rbegin();
       packetWithHandlerContextItr != packetsWithHandlerContext.rend();
       packetWithHandlerContextItr++) {
    auto& outstandingPacket = packetWithHandlerContextItr->outstandingPacket;
    const auto processAllFrames = packetWithHandlerContextItr->processAllFrames;
    AckEvent::AckPacket::DetailsPerStream detailsPerStream;
    for (auto& packetFrame : outstandingPacket.packet.frames) {
      if (!processAllFrames &&
          packetFrame.type() != QuicWriteFrame::Type::WriteAckFrame) {
        continue; // skip processing this frame
      }

      // We do a few things here for ACKs of WriteStreamFrames:
      //  1. To understand whether the ACK of this frame changes the
      //     stream's delivery offset, we record the delivery offset before
      //     running the ackVisitor, run it, and then check if the stream's
      //     delivery offset changed.
      //
      //  2. To understand whether the ACK of this frame is redundant (e.g.
      //     the frame was already ACKed before), we record the version of
      //     the stream's ACK IntervalSet before running the ackVisitor,
      //     run it, and then check if the version changed. If it changed,
      //     we know that _this_ ACK of _this_ frame had an impact.
      //
      //  3. If we determine that the ACK of the frame is not-redundant,
      //     and the frame was retransmitted, we record the number of bytes
      //     ACKed by a retransmit as well.

      // Part 1: Record delivery offset prior to running ackVisitor.
      struct PreAckVisitorState {
        const uint64_t ackIntervalSetVersion;
        const folly::Optional<uint64_t> maybeLargestDeliverableOffset;
      };
      const auto maybePreAckVisitorState =
          [&conn](
              const auto& packetFrame) -> folly::Optional<PreAckVisitorState> {
        // check if it's a WriteStreamFrame being ACKed
        if (packetFrame.type() != QuicWriteFrame::Type::WriteStreamFrame) {
          return folly::none;
        }

        // check if the stream is alive (could be ACK for dead stream)
        const WriteStreamFrame& ackedFrame = *packetFrame.asWriteStreamFrame();
        if (!conn.streamManager->streamExists(ackedFrame.streamId)) {
          return folly::none;
        }
        auto ackedStream =
            CHECK_NOTNULL(conn.streamManager->getStream(ackedFrame.streamId));

        // stream is alive and frame is WriteStreamFrame
        return PreAckVisitorState{
            getAckIntervalSetVersion(*ackedStream),
            getLargestDeliverableOffset(*ackedStream)};
      }(packetFrame);

      // run the ACK visitor
      ackVisitor(outstandingPacket, packetFrame, frame);

      // Part 2 and 3: Process current state relative to the PreAckVistorState.
      if (maybePreAckVisitorState.has_value()) {
        const auto& preAckVisitorState = maybePreAckVisitorState.value();
        const WriteStreamFrame& ackedFrame = *packetFrame.asWriteStreamFrame();
        auto ackedStream =
            CHECK_NOTNULL(conn.streamManager->getStream(ackedFrame.streamId));

        // determine if this frame was a retransmission
        const bool retransmission = ([&outstandingPacket, &ackedFrame]() {
          // in some cases (some unit tests), stream details are not available
          // in these cases, we assume it is not a retransmission
          if (const auto maybeStreamDetails = folly::get_optional(
                  outstandingPacket.metadata.detailsPerStream,
                  ackedFrame.streamId)) {
            const auto& maybeFirstNewStreamByteOffset =
                maybeStreamDetails->maybeFirstNewStreamByteOffset;
            return (
                !maybeFirstNewStreamByteOffset.has_value() ||
                maybeFirstNewStreamByteOffset.value() > ackedFrame.offset);
          }
          return false; // assume not a retransmission
        })();

        // check for change in ACK IntervalSet version
        if (preAckVisitorState.ackIntervalSetVersion !=
            getAckIntervalSetVersion(*ackedStream)) {
          // we were able to fill in a hole in the ACK interval
          detailsPerStream.recordFrameDelivered(ackedFrame, retransmission);

          // check for change in delivery offset
          const auto maybeLargestDeliverableOffset =
              getLargestDeliverableOffset(*ackedStream);
          if (preAckVisitorState.maybeLargestDeliverableOffset !=
              maybeLargestDeliverableOffset) {
            CHECK(maybeLargestDeliverableOffset.has_value());
            detailsPerStream.recordDeliveryOffsetUpdate(
                ackedFrame.streamId, maybeLargestDeliverableOffset.value());
          }
        } else {
          // we got an ACK of a frame that was already marked as delivered
          // when handling the ACK of some earlier packet; mark as such
          detailsPerStream.recordFrameAlreadyDelivered(
              ackedFrame, retransmission);

          // should be no change in delivery offset
          DCHECK(
              preAckVisitorState.maybeLargestDeliverableOffset ==
              getLargestDeliverableOffset(*CHECK_NOTNULL(ackedStream)));
        }
      }
    }
    ack.ackedPackets.emplace_back(
        CongestionController::AckEvent::AckPacket::Builder()
            .setPacketNum(
                outstandingPacket.packet.header.getPacketSequenceNum())
            .setOutstandingPacketMetadata(std::move(outstandingPacket.metadata))
            .setDetailsPerStream(std::move(detailsPerStream))
            .setLastAckedPacketInfo(
                std::move(outstandingPacket.lastAckedPacketInfo))
            .setAppLimited(outstandingPacket.isAppLimited)
            .build());
  }
  if (lastAckedPacketSentTime) {
    conn.lossState.lastAckedPacketSentTime = *lastAckedPacketSentTime;
  }
  CHECK_GE(conn.outstandings.dsrCount, dsrPacketsAcked);
  conn.outstandings.dsrCount -= dsrPacketsAcked;
  CHECK_GE(
      conn.outstandings.packets.size(), conn.outstandings.declaredLostCount);
  auto updatedOustandingPacketsCount = conn.outstandings.numOutstanding();
  const auto& packetCount = conn.outstandings.packetCount;
  LOG_IF(
      DFATAL,
      updatedOustandingPacketsCount <
          packetCount[PacketNumberSpace::Handshake] +
              packetCount[PacketNumberSpace::Initial] +
              packetCount[PacketNumberSpace::AppData])
      << "QUIC packetCount inconsistency: "
         "numOutstanding: "
      << updatedOustandingPacketsCount << " packetCount: {"
      << packetCount[PacketNumberSpace::Initial] << ","
      << packetCount[PacketNumberSpace::Handshake] << ","
      << packetCount[PacketNumberSpace::AppData] << "}"
      << " originalPacketCount: {"
      << originalPacketCount[PacketNumberSpace::Initial] << ","
      << originalPacketCount[PacketNumberSpace::Handshake] << ","
      << originalPacketCount[PacketNumberSpace::AppData] << "}";
  CHECK_GE(updatedOustandingPacketsCount, conn.outstandings.numClonedPackets());
  auto lossEvent = handleAckForLoss(conn, lossVisitor, ack, pnSpace);
  if (conn.congestionController &&
      (ack.largestNewlyAckedPacket.has_value() || lossEvent)) {
    if (lossEvent) {
      CHECK(lossEvent->largestLostSentTime && lossEvent->smallestLostSentTime);
      // TODO it's not clear that we should be using the smallest and largest
      // lost times here. It may perhaps be better to only consider the latest
      // contiguous lost block and determine if that block is larger than the
      // congestion period. Alternatively we could consider every lost block
      // and check if any of them constitute persistent congestion.
      lossEvent->persistentCongestion = isPersistentCongestion(
          conn.lossState.srtt == 0s ? folly::none
                                    : folly::Optional(calculatePTO(conn)),
          *lossEvent->smallestLostSentTime,
          *lossEvent->largestLostSentTime,
          ack);
      if (lossEvent->persistentCongestion) {
        QUIC_STATS(conn.statsCallback, onPersistentCongestion);
      }
    }
    conn.congestionController->onPacketAckOrLoss(&ack, lossEvent.get_pointer());
    for (auto& packetProcessor : conn.packetProcessors) {
      packetProcessor->onPacketAck(&ack);
    }
    ack.ccState = conn.congestionController->getState();
  }
  clearOldOutstandingPackets(conn, ackReceiveTime, pnSpace);

  if (spuriousLossEvent && conn.observerContainer &&
      conn.observerContainer->hasObserversForEvent<
          SocketObserverInterface::Events::spuriousLossEvents>()) {
    conn.observerContainer->invokeInterfaceMethod<
        SocketObserverInterface::Events::spuriousLossEvents>(
        [spuriousLossEvent](auto observer, auto observed) {
          observer->spuriousLossDetected(observed, *spuriousLossEvent);
        });
  }

  return ack;
}

void clearOldOutstandingPackets(
    QuicConnectionStateBase& conn,
    TimePoint time,
    PacketNumberSpace pnSpace) {
  if (conn.outstandings.declaredLostCount) {
    // Reap any old packets declared lost that are unlikely to be ACK'd.
    auto threshold = calculatePTO(conn);
    auto opItr = conn.outstandings.packets.begin();
    auto eraseBegin = opItr;
    while (opItr != conn.outstandings.packets.end()) {
      // This case can happen when we have buffered an undecryptable ACK and
      // are able to decrypt it later.
      if (time < opItr->metadata.time) {
        break;
      }
      if (opItr->packet.header.getPacketNumberSpace() != pnSpace) {
        if (eraseBegin != opItr) {
          // We want to keep [eraseBegin, opItr) within a single PN space.
          opItr = conn.outstandings.packets.erase(eraseBegin, opItr);
        }
        opItr++;
        eraseBegin = opItr;
        continue;
      }
      auto timeSinceSent = time - opItr->metadata.time;
      if (opItr->declaredLost && timeSinceSent > threshold) {
        opItr++;
        CHECK_GT(conn.outstandings.declaredLostCount, 0);
        conn.outstandings.declaredLostCount--;
      } else {
        break;
      }
    }
    if (eraseBegin != opItr) {
      conn.outstandings.packets.erase(eraseBegin, opItr);
    }
  }
}

void commonAckVisitorForAckFrame(
    AckState& ackState,
    const WriteAckFrame& frame) {
  // Remove ack interval from ackState if an outstandingPacket with a AckFrame
  // is acked.
  // We may remove the current largest acked packet here, but keep its receive
  // time behind. But then right after this updateLargestReceivedPacketNum will
  // update that time stamp. Please note that this assume the peer isn't buggy
  // in the sense that packet numbers it issues are only increasing.
  auto iter = frame.ackBlocks.crbegin();
  while (iter != frame.ackBlocks.crend()) {
    ackState.acks.withdraw(*iter);
    iter++;
  }
  if (!frame.ackBlocks.empty()) {
    auto largestAcked = frame.ackBlocks.front().end;
    if (largestAcked > kAckPurgingThresh) {
      ackState.acks.withdraw({0, largestAcked - kAckPurgingThresh});
    }
  }
}
} // namespace quic
