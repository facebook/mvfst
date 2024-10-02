/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/MapUtil.h>
#include <folly/tracing/StaticTracepoint.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/AckedPacketIterator.h>
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
      OutstandingPacketWrapper* outstandingPacketIn)
      : outstandingPacket(outstandingPacketIn) {}

  OutstandingPacketWrapper* outstandingPacket;
  bool processAllFrames{false};
};

} // namespace

void removeOutstandingsForAck(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    const ReadAckFrame& frame) {
  AckedPacketIterator ackedPacketIterator(frame.ackBlocks, conn, pnSpace);
  ackedPacketIterator.eraseAckedOutstandings();
}

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
    const AckedPacketVisitor& ackedPacketVisitor,
    const AckedFrameVisitor& ackedFrameVisitor,
    const LossVisitor& lossVisitor,
    const TimePoint& ackReceiveTime) {
  const auto nowTime = Clock::now();

  updateEcnCountEchoed(conn, pnSpace, frame);

  // TODO: send error if we get an ack for a packet we've not sent t18721184
  auto ack = AckEvent::Builder()
                 .setAckTime(ackReceiveTime)
                 .setAdjustedAckTime(ackReceiveTime - frame.ackDelay)
                 .setAckDelay(frame.ackDelay)
                 .setPacketNumberSpace(pnSpace)
                 .setLargestAckedPacket(frame.largestAcked)
                 .setIsImplicitAck(frame.implicit)
                 .setEcnCounts(
                     frame.ecnECT0Count, frame.ecnECT1Count, frame.ecnCECount)
                 .build();

  FOLLY_SDT(
      quic,
      process_ack_frame_num_outstanding,
      conn.outstandings.numOutstanding());

  // temporary storage to enable packets to be processed in sent order
  SmallVec<OutstandingPacketWithHandlerContext, 50> packetsWithHandlerContext;

  // Store first outstanding packet number to ignore old receive timestamps.
  const auto& firstOutstandingPacket =
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  Optional<PacketNum> firstPacketNum =
      (firstOutstandingPacket != conn.outstandings.packets.end())
      ? folly::make_optional(firstOutstandingPacket->getPacketSequenceNum())
      : none;

  uint64_t dsrPacketsAcked = 0;
  Optional<decltype(conn.lossState.lastAckedPacketSentTime)>
      lastAckedPacketSentTime;
  Optional<LegacyObserver::SpuriousLossEvent> spuriousLossEvent;
  // Used for debug only.
  const auto originalPacketCount = conn.outstandings.packetCount;
  const auto originalNumOutstanding = conn.outstandings.numOutstanding();
  SCOPE_EXIT {
    FOLLY_SDT(
        quic,
        process_ack_frame_num_erased,
        originalNumOutstanding - conn.outstandings.numOutstanding());
  };
  {
    const auto socketObserverContainer = conn.getSocketObserverContainer();
    if (socketObserverContainer &&
        socketObserverContainer->hasObserversForEvent<
            SocketObserverInterface::Events::spuriousLossEvents>()) {
      spuriousLossEvent.emplace(ackReceiveTime);
    }
  }

  AckedPacketIterator ackedPacketIterator(frame.ackBlocks, conn, pnSpace);
  while (ackedPacketIterator.valid()) {
    auto currentPacketNum =
        ackedPacketIterator->packet.header.getPacketSequenceNum();
    auto currentPacketNumberSpace =
        ackedPacketIterator->packet.header.getPacketNumberSpace();
    ackedPacketIterator->metadata.scheduledForDestruction = true;
    conn.outstandings.scheduledForDestructionCount++;
    VLOG(10) << __func__ << " acked packetNum=" << currentPacketNum
             << " space=" << currentPacketNumberSpace << conn;
    // If we hit a packet which has been lost we need to count the spurious
    // loss and ignore all other processing.
    if (ackedPacketIterator->declaredLost) {
      modifyStateForSpuriousLoss(conn, *ackedPacketIterator);
      QUIC_STATS(conn.statsCallback, onPacketSpuriousLoss);
      if (spuriousLossEvent) {
        spuriousLossEvent->addSpuriousPacket(
            ackedPacketIterator->metadata,
            ackedPacketIterator->packet.header.getPacketSequenceNum(),
            ackedPacketIterator->packet.header.getPacketNumberSpace());
      }
      ackedPacketIterator.next();
      continue;
    }
    bool needsProcess = !ackedPacketIterator->maybeClonedPacketIdentifier ||
        conn.outstandings.clonedPacketIdentifiers.count(
            *ackedPacketIterator->maybeClonedPacketIdentifier);
    if (needsProcess) {
      CHECK(conn.outstandings.packetCount[currentPacketNumberSpace]);
      --conn.outstandings.packetCount[currentPacketNumberSpace];
    }
    ack.ackedBytes += ackedPacketIterator->metadata.encodedSize;
    if (ackedPacketIterator->maybeClonedPacketIdentifier) {
      CHECK(conn.outstandings.clonedPacketCount[currentPacketNumberSpace]);
      --conn.outstandings.clonedPacketCount[currentPacketNumberSpace];
    }
    if (ackedPacketIterator->isDSRPacket) {
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
      auto ackReceiveTimeOrNow =
          ackReceiveTime > ackedPacketIterator->metadata.time ? ackReceiveTime
                                                              : nowTime;

      // Use ceil to round up to next microsecond during conversion.
      //
      // While unlikely, it's still technically possible for the RTT to be
      // zero; ignore if this is the case.
      auto rttSample = std::chrono::ceil<std::chrono::microseconds>(
          ackReceiveTimeOrNow - ackedPacketIterator->metadata.time);
      if (rttSample != rttSample.zero()) {
        // notify observers
        {
          const auto socketObserverContainer =
              conn.getSocketObserverContainer();
          if (socketObserverContainer &&
              socketObserverContainer->hasObserversForEvent<
                  SocketObserverInterface::Events::rttSamples>()) {
            socketObserverContainer->invokeInterfaceMethod<
                SocketObserverInterface::Events::rttSamples>(
                [event = SocketObserverInterface::PacketRTT(
                     ackReceiveTimeOrNow,
                     rttSample,
                     frame.ackDelay,
                     *ackedPacketIterator)](auto observer, auto observed) {
                  observer->rttSampleGenerated(observed, event);
                });
          }
        }

        // update AckEvent RTTs, which are used by CCA and other processing
        CHECK(!ack.rttSample.has_value());
        CHECK(!ack.rttSampleNoAckDelay.has_value());
        ack.rttSample = rttSample;
        ack.rttSampleNoAckDelay = (rttSample >= frame.ackDelay)
            ? OptionalMicros(std::chrono::ceil<std::chrono::microseconds>(
                  rttSample - frame.ackDelay))
            : std::nullopt;

        // update transport RTT
        updateRtt(conn, rttSample, frame.ackDelay);
      } // if (rttSample != rttSample.zero())
    } // if (!ack.implicit && currentPacketNum == frame.largestAcked)

    // Remove this ClonedPacketIdentifier from the
    // outstandings.clonedPacketIdentifiers set
    if (ackedPacketIterator->maybeClonedPacketIdentifier) {
      conn.outstandings.clonedPacketIdentifiers.erase(
          *ackedPacketIterator->maybeClonedPacketIdentifier);
    }
    if (!ack.largestNewlyAckedPacket ||
        *ack.largestNewlyAckedPacket < currentPacketNum) {
      ack.largestNewlyAckedPacket = currentPacketNum;
      ack.largestNewlyAckedPacketSentTime = ackedPacketIterator->metadata.time;
      ack.largestNewlyAckedPacketAppLimited = ackedPacketIterator->isAppLimited;
    }
    if (!ack.implicit) {
      conn.lossState.totalBytesAcked +=
          ackedPacketIterator->metadata.encodedSize;
      conn.lossState.totalBytesSentAtLastAck = conn.lossState.totalBytesSent;
      conn.lossState.totalBytesAckedAtLastAck = conn.lossState.totalBytesAcked;
      conn.lossState.totalBodyBytesAcked +=
          ackedPacketIterator->metadata.encodedBodySize;
      if (!lastAckedPacketSentTime) {
        lastAckedPacketSentTime = ackedPacketIterator->metadata.time;
      }
      conn.lossState.lastAckedTime = ackReceiveTime;
      conn.lossState.adjustedLastAckedTime = ackReceiveTime - frame.ackDelay;
    }
    ack.totalBytesAcked = conn.lossState.totalBytesAcked;

    {
      OutstandingPacketWrapper* wrapper = &(*ackedPacketIterator);
      auto tmpIt = packetsWithHandlerContext.emplace(
          std::find_if(
              packetsWithHandlerContext.rbegin(),
              packetsWithHandlerContext.rend(),
              [&currentPacketNum](const auto& packetWithHandlerContext) {
                return packetWithHandlerContext.outstandingPacket->packet.header
                           .getPacketSequenceNum() > currentPacketNum;
              })
              .base(),
          OutstandingPacketWithHandlerContext(wrapper));
      tmpIt->processAllFrames = needsProcess;
    }
    ackedPacketIterator.next();
  }

  // Store any (new) Rx timestamps reported by the peer.
  folly::F14FastMap<PacketNum, uint64_t> packetReceiveTimeStamps;
  if (pnSpace == PacketNumberSpace::AppData) {
    parseAckReceiveTimestamps(
        conn, frame, packetReceiveTimeStamps, firstPacketNum);
  }

  // Invoke AckVisitor for WriteAckFrames all the time. Invoke it for other
  // frame types only if the packet doesn't have an associated
  // ClonedPacketIdentifier; or the ClonedPacketIdentifier is in
  // conn.outstandings.clonedPacketIdentifiers
  ack.ackedPackets.reserve(packetsWithHandlerContext.size());
  for (auto packetWithHandlerContextItr = packetsWithHandlerContext.rbegin();
       packetWithHandlerContextItr != packetsWithHandlerContext.rend();
       packetWithHandlerContextItr++) {
    auto& outstandingPacket = packetWithHandlerContextItr->outstandingPacket;

    // run the ACKed packet visitor
    ackedPacketVisitor(*outstandingPacket);

    // Update ecn counts
    incrementEcnCountForAckedPacket(conn, pnSpace);

    const auto processAllFrames = packetWithHandlerContextItr->processAllFrames;
    AckEvent::AckPacket::DetailsPerStream detailsPerStream;
    for (auto& packetFrame : outstandingPacket->packet.frames) {
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
        const Optional<uint64_t> maybeLargestDeliverableOffset;
      };
      QuicStreamState* maybeAckedStreamState = nullptr;
      const auto maybePreAckVisitorState =
          [&conn, &maybeAckedStreamState](
              const auto& packetFrame) -> Optional<PreAckVisitorState> {
        // check if it's a WriteStreamFrame being ACKed
        if (packetFrame.type() != QuicWriteFrame::Type::WriteStreamFrame) {
          return none;
        }

        // check if the stream is alive (could be ACK for dead stream)
        const WriteStreamFrame& ackedFrame = *packetFrame.asWriteStreamFrame();
        maybeAckedStreamState =
            conn.streamManager->findStream(ackedFrame.streamId);
        if (!maybeAckedStreamState) {
          return none;
        }

        // stream is alive and frame is WriteStreamFrame
        return PreAckVisitorState{
            getAckIntervalSetVersion(*maybeAckedStreamState),
            getLargestDeliverableOffset(*maybeAckedStreamState)};
      }(packetFrame);

      // run the ACKed frame visitor
      ackedFrameVisitor(*outstandingPacket, packetFrame);

      // Part 2 and 3: Process current state relative to the PreAckVistorState.
      if (maybePreAckVisitorState.has_value()) {
        const auto& preAckVisitorState = maybePreAckVisitorState.value();
        const WriteStreamFrame& ackedFrame = *packetFrame.asWriteStreamFrame();

        // check for change in ACK IntervalSet version
        CHECK(maybeAckedStreamState);
        if (preAckVisitorState.ackIntervalSetVersion !=
            getAckIntervalSetVersion(*maybeAckedStreamState)) {
          // we were able to fill in a hole in the ACK interval
          detailsPerStream.recordFrameDelivered(ackedFrame);
        } else {
          // we got an ACK of a frame that was already marked as delivered
          // when handling the ACK of some earlier packet; mark as such
          detailsPerStream.recordFrameAlreadyDelivered(ackedFrame);

          // should be no change in delivery offset
          DCHECK(
              preAckVisitorState.maybeLargestDeliverableOffset ==
              getLargestDeliverableOffset(*maybeAckedStreamState));
        }
      }
    }
    auto maybeRxTimestamp = packetReceiveTimeStamps.find(
        outstandingPacket->packet.header.getPacketSequenceNum());
    CongestionController::AckEvent::AckPacket::Builder()
        .setPacketNum(outstandingPacket->packet.header.getPacketSequenceNum())
        .setNonDsrPacketSequenceNumber(
            outstandingPacket->nonDsrPacketSequenceNumber.value_or(0))
        .setOutstandingPacketMetadata(outstandingPacket->metadata)
        .setDetailsPerStream(std::move(detailsPerStream))
        .setLastAckedPacketInfo(
            outstandingPacket->lastAckedPacketInfo
                ? &outstandingPacket->lastAckedPacketInfo.value()
                : nullptr)
        .setAppLimited(outstandingPacket->isAppLimited)
        .setReceiveDeltaTimeStamp(
            maybeRxTimestamp != packetReceiveTimeStamps.end()
                ? OptionalMicros(
                      std::chrono::microseconds(maybeRxTimestamp->second))
                : std::nullopt)
        .buildInto(ack.ackedPackets);
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
          conn.lossState.srtt == 0s ? std::nullopt
                                    : OptionalMicros(calculatePTO(conn)),
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

  // notify observers
  {
    const auto socketObserverContainer = conn.getSocketObserverContainer();
    if (spuriousLossEvent && spuriousLossEvent->hasPackets() &&
        socketObserverContainer &&
        socketObserverContainer->hasObserversForEvent<
            SocketObserverInterface::Events::spuriousLossEvents>()) {
      socketObserverContainer->invokeInterfaceMethod<
          SocketObserverInterface::Events::spuriousLossEvents>(
          [spuriousLossEvent](auto observer, auto observed) {
            observer->spuriousLossDetected(observed, *spuriousLossEvent);
          });
    }
  }

  removeOutstandingsForAck(conn, pnSpace, frame);

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
      if (opItr->packet.header.getPacketNumberSpace() != pnSpace ||
          opItr->metadata.scheduledForDestruction) {
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

void parseAckReceiveTimestamps(
    const QuicConnectionStateBase& conn,
    const quic::ReadAckFrame& frame,
    folly::F14FastMap<PacketNum, uint64_t>& packetReceiveTimeStamps,
    Optional<PacketNum> firstPacketNum) {
  if (frame.frameType != FrameType::ACK_RECEIVE_TIMESTAMPS) {
    return;
  }

  // Ignore if we didn't request packet receive timestamps from the peer.
  if (!conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer
           .has_value()) {
    return;
  }

  DCHECK(frame.maybeLatestRecvdPacketNum.has_value());

  // Confirm there is at least one timestamp range and one timestamp delta
  // within that range.
  if (frame.recvdPacketsTimestampRanges.empty() ||
      frame.recvdPacketsTimestampRanges[0].deltas.empty()) {
    return;
  }
  auto receivedPacketNum = frame.maybeLatestRecvdPacketNum.value();

  // Don't parse for packets already ACKed.
  if (!firstPacketNum.has_value() ||
      receivedPacketNum < firstPacketNum.value()) {
    return;
  }

  const auto& maxReceiveTimestampsRequestedFromPeer =
      conn.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer.value()
          .maxReceiveTimestampsPerAck;

  auto decrementPacketNum = [](PacketNum pktNum) {
    return pktNum > 0 ? --pktNum : 0;
  };

  /*
   * From RFC, the first delta timestamp is relative to connection start time on
   * the peer while the rest of the timestamps are relative to the previous
   * delta timestamp. Since peer's connection start time isn't known, receive
   * timestamps will be stored as deltas to previous packet's receive timestamp.
   * We do not want to use our connection start time as a proxy for the peer's,
   * as the two clocks might not be in sync and propagation delay isn't
   * accounted for.
   */

  // First delta timestamp is relative to connection start time, so multiply by
  // 2 to keep loop semantics consistent for this first timestamp as well. T0 =
  // 2D0 - D0 = D0 for the first timestamp.
  // Tn = Tn-1 - Dn for other timestamps.
  auto receiveTimeStamp = 2 * frame.recvdPacketsTimestampRanges[0].deltas[0];
  // Walk through each timestamp range (separated by gaps) and calculate the
  // Rx timestamp.
  for (auto& timeStampRange : frame.recvdPacketsTimestampRanges) {
    receivedPacketNum -= timeStampRange.gap;

    for (const auto& delta : timeStampRange.deltas) {
      // // Don't parse for packets already ACKed.
      if (!firstPacketNum.has_value() ||
          receivedPacketNum < firstPacketNum.value()) {
        return;
      }
      // We don't need to process more than the requested Receive timestamps
      // sent by peer.
      if (packetReceiveTimeStamps.size() >=
          maxReceiveTimestampsRequestedFromPeer) {
        LOG(ERROR) << " Received more timestamps "
                   << packetReceiveTimeStamps.size()
                   << " than requested timestamps from peer: "
                   << maxReceiveTimestampsRequestedFromPeer << " current PN "
                   << receivedPacketNum << " largest PN "
                   << frame.maybeLatestRecvdPacketNum.value() << " deltas  "
                   << timeStampRange.deltas.size();
        return;
      }
      receiveTimeStamp -= delta;
      packetReceiveTimeStamps[receivedPacketNum] = receiveTimeStamp;
      receivedPacketNum = decrementPacketNum(receivedPacketNum);
    }
    // Additional decrement to maintain a gap of "2" for subsequent timestamp
    // ranges per RFC.
    receivedPacketNum = decrementPacketNum(receivedPacketNum);
  }
}

void commonAckVisitorForAckFrame(
    AckState& ackState,
    const WriteAckFrame& frame) {
  /**
   * Purge old timestamps to avoid sending duplicate timestamps in the next ACK.
   * We use ACKs received for the WriteAck we sent earlier to the peer to enable
   * this purge.
   */
  auto purgeAckReceiveTimestamps = [&](AckState& ackState) {
    if (ackState.recvdPacketInfos.empty()) {
      return;
    }
    // No ACKs tracked locally, which means all were confirmed to be received.
    // Clear all the timestamps.
    if (ackState.acks.empty()) {
      ackState.recvdPacketInfos.clear();
      return;
    }

    for (auto recvdPacketInfoIt = ackState.recvdPacketInfos.begin();
         recvdPacketInfoIt != ackState.recvdPacketInfos.end();) {
      if (!ackState.acks.contains(
              recvdPacketInfoIt->pktNum, recvdPacketInfoIt->pktNum)) {
        recvdPacketInfoIt = ackState.recvdPacketInfos.erase(recvdPacketInfoIt);
      } else {
        ++recvdPacketInfoIt;
      }
    }
  };

  // Remove intervals when OutstandingPacket with a AckFrame is acked.
  //
  // We may remove the current largest acked packet here, but keep its receive
  // time behind. But then right after this addPacketToAckState will update that
  // time stamp. Please note that this assume the peer isn't buggy
  // in the sense that packet numbers it issues are only increasing.
  auto iter = frame.ackBlocks.crbegin();
  while (iter != frame.ackBlocks.crend()) {
    ackState.acks.withdraw(*iter);
    iter++;
  }
  // Purge all received timestamps sent in ACKs that have been received by
  // the peer. We don't want to purge using kAckPurgingThresh as the latest
  // timestamps may not have been received by the peer yet. Also max
  // timestamps is limited already by its own config.
  purgeAckReceiveTimestamps(ackState);

  if (!frame.ackBlocks.empty()) {
    auto largestAcked = frame.ackBlocks.front().end;
    if (largestAcked > kAckPurgingThresh) {
      ackState.acks.withdraw({0, largestAcked - kAckPurgingThresh});
    }
  }
}

void incrementEcnCountForAckedPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) {
  if (conn.ecnState == ECNState::NotAttempted ||
      conn.ecnState == ECNState::FailedValidation) {
    // Nothing to update.
    return;
  }
  auto& ackState = getAckState(conn, pnSpace);
  ackState.minimumExpectedEcnMarksEchoed++;
}

void updateEcnCountEchoed(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace,
    const ReadAckFrame& readAckFrame) {
  // Track the reflected ECN markings in the current pn space
  auto& ackState = getAckState(conn, pnSpace);
  ackState.ecnECT0CountEchoed =
      std::max(ackState.ecnECT0CountEchoed, readAckFrame.ecnECT0Count);
  ackState.ecnECT1CountEchoed =
      std::max(ackState.ecnECT1CountEchoed, readAckFrame.ecnECT1Count);
  ackState.ecnCECountEchoed =
      std::max(ackState.ecnCECountEchoed, readAckFrame.ecnCECount);
}

void modifyStateForSpuriousLoss(
    QuicConnectionStateBase& conn,
    OutstandingPacketWrapper& spuriouslyLostPacket) {
  CHECK_GT(conn.outstandings.declaredLostCount, 0);
  conn.lossState.totalPacketsSpuriouslyMarkedLost++;
  if (conn.transportSettings.useAdaptiveLossReorderingThresholds) {
    if (spuriouslyLostPacket.metadata.lossReorderDistance.has_value() &&
        spuriouslyLostPacket.metadata.lossReorderDistance.value() >
            conn.lossState.reorderingThreshold) {
      conn.lossState.reorderingThreshold =
          spuriouslyLostPacket.metadata.lossReorderDistance.value();
    }
  }
  if (conn.transportSettings.useAdaptiveLossTimeThresholds) {
    if (spuriouslyLostPacket.metadata.lossTimeoutDividend.has_value() &&
        spuriouslyLostPacket.metadata.lossTimeoutDividend.value() >
            conn.transportSettings.timeReorderingThreshDividend) {
      conn.transportSettings.timeReorderingThreshDividend =
          spuriouslyLostPacket.metadata.lossTimeoutDividend.value();
    }
  }
  if (conn.transportSettings.removeFromLossBufferOnSpurious) {
    for (auto& f : spuriouslyLostPacket.packet.frames) {
      auto streamFrame = f.asWriteStreamFrame();
      if (streamFrame) {
        auto stream = conn.streamManager->findStream(streamFrame->streamId);
        if (stream) {
          stream->removeFromLossBuffer(
              streamFrame->offset, streamFrame->len, streamFrame->fin);
          stream->updateAckedIntervals(
              streamFrame->offset, streamFrame->len, streamFrame->fin);
          conn.streamManager->updateWritableStreams(*stream);
        }
      }
    }
  }
  CHECK_GT(conn.outstandings.declaredLostCount, 0);
  conn.outstandings.declaredLostCount--;
}
} // namespace quic
