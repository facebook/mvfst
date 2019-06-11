/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/QuicTransportFunctions.h>

#include <folly/Overload.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/api/IoBufQuicBatch.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>
#include <quic/logging/QuicLogger.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>

namespace {

std::string optionalToString(
    const folly::Optional<quic::PacketNum>& packetNum) {
  if (!packetNum) {
    return "-";
  }
  return folly::to<std::string>(*packetNum);
}

std::string largestAckScheduledToString(
    const quic::QuicConnectionStateBase& conn) noexcept {
  return folly::to<std::string>(
      "[",
      optionalToString(conn.ackStates.initialAckState.largestAckScheduled),
      ",",
      optionalToString(conn.ackStates.handshakeAckState.largestAckScheduled),
      ",",
      optionalToString(conn.ackStates.appDataAckState.largestAckScheduled),
      "]");
}

std::string largestAckToSendToString(
    const quic::QuicConnectionStateBase& conn) noexcept {
  return folly::to<std::string>(
      "[",
      optionalToString(largestAckToSend(conn.ackStates.initialAckState)),
      ",",
      optionalToString(largestAckToSend(conn.ackStates.handshakeAckState)),
      ",",
      optionalToString(largestAckToSend(conn.ackStates.appDataAckState)),
      "]");
}

bool toWriteInitialAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.initialWriteCipher &&
      hasAcksToSchedule(conn.ackStates.initialAckState) &&
      conn.ackStates.initialAckState.needsToSendAckImmediately);
}

bool toWriteHandshakeAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.handshakeWriteCipher &&
      hasAcksToSchedule(conn.ackStates.handshakeAckState) &&
      conn.ackStates.handshakeAckState.needsToSendAckImmediately);
}

bool toWriteAppDataAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.oneRttWriteCipher &&
      hasAcksToSchedule(conn.ackStates.appDataAckState) &&
      conn.ackStates.appDataAckState.needsToSendAckImmediately);
}

} // namespace

namespace quic {

void handleNewStreamDataWritten(
    QuicConnectionStateBase& conn,
    QuicStreamLike& stream,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace) {
  auto originalOffset = stream.currentWriteOffset;
  VLOG(10) << nodeToString(conn.nodeType) << " sent"
           << " packetNum=" << packetNum << " space=" << packetNumberSpace
           << " " << conn;
  // Idealy we should also check this data doesn't exist in either retx buffer
  // or loss buffer, but that's an expensive search.
  stream.currentWriteOffset += frameLen;
  auto bufWritten = stream.writeBuffer.split(folly::to<size_t>(frameLen));
  stream.currentWriteOffset += frameFin ? 1 : 0;
  auto insertIt = std::upper_bound(
      stream.retransmissionBuffer.begin(),
      stream.retransmissionBuffer.end(),
      originalOffset,
      [](const auto& offset, const auto& compare) {
        // TODO: huh? why isn't this a >= ?
        return compare.offset > offset;
      });
  stream.retransmissionBuffer.emplace(
      insertIt, std::move(bufWritten), originalOffset, frameFin);
}

void handleRetransmissionWritten(
    QuicConnectionStateBase& conn,
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum) {
  conn.lossState.totalBytesRetransmitted += frameLen;
  auto lossBufferIter = std::find_if(
      stream.lossBuffer.begin(),
      stream.lossBuffer.end(),
      [&](const auto& buffer) { return frameOffset == buffer.offset; });
  CHECK(lossBufferIter != stream.lossBuffer.end());
  VLOG(10) << nodeToString(conn.nodeType) << " sent retransmission"
           << " packetNum=" << packetNum << " " << conn;
  auto bufferLen = lossBufferIter->data.chainLength();
  Buf bufWritten;
  if (frameLen == bufferLen && frameFin == lossBufferIter->eof) {
    // The buffer is entirely retransmitted
    bufWritten = lossBufferIter->data.move();
    stream.lossBuffer.erase(lossBufferIter);
  } else {
    lossBufferIter->offset += frameLen;
    bufWritten = lossBufferIter->data.split(frameLen);
  }
  stream.retransmissionBuffer.emplace(
      std::upper_bound(
          stream.retransmissionBuffer.begin(),
          stream.retransmissionBuffer.end(),
          frameOffset,
          [](const auto& offsetIn, const auto& buffer) {
            return offsetIn < buffer.offset;
          }),
      std::move(bufWritten),
      frameOffset,
      frameFin);
}

/**
 * Update the connection and stream state after stream data is written and deal
 * with new data, as well as retranmissions. Returns true if the data sent is
 * new data.
 */
bool handleStreamWritten(
    QuicConnectionStateBase& conn,
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace) {
  // Handle new data first
  if (frameOffset == stream.currentWriteOffset) {
    handleNewStreamDataWritten(
        conn, stream, frameLen, frameFin, packetNum, packetNumberSpace);
    return true;
  }

  // If the data is in retx buffer, this is a clone write
  auto retxBufferIter = std::find_if(
      stream.retransmissionBuffer.begin(),
      stream.retransmissionBuffer.end(),
      [&](const auto& buffer) {
        return frameOffset == buffer.offset &&
            frameLen == buffer.data.chainLength() && frameFin == buffer.eof;
      });
  if (retxBufferIter != stream.retransmissionBuffer.end()) {
    conn.lossState.totalStreamBytesCloned += frameLen;
    return false;
  }

  // If it's neither new data nor clone data, then it is a retransmission and
  // the data has to be in loss buffer.
  handleRetransmissionWritten(
      conn, stream, frameOffset, frameLen, frameFin, packetNum);
  QUIC_STATS(conn.infoCallback, onPacketRetransmission);
  return false;
}

void updateConnection(
    QuicConnectionStateBase& conn,
    folly::Optional<PacketEvent> packetEvent,
    RegularQuicWritePacket packet,
    TimePoint sentTime,
    uint32_t encodedSize) {
  auto packetNum = folly::variant_match(
      packet.header, [](const auto& h) { return h.getPacketSequenceNum(); });
  bool retransmittable = false; // AckFrame and PaddingFrame are not retx-able.
  bool isHandshake = false;
  uint32_t connWindowUpdateSent = 0;
  uint32_t ackFrameCounter = 0;
  auto packetNumberSpace = folly::variant_match(
      packet.header, [](const auto& h) { return h.getPacketNumberSpace(); });
  VLOG(10) << nodeToString(conn.nodeType) << " sent packetNum=" << packetNum
           << " in space=" << packetNumberSpace << " size=" << encodedSize
           << " " << conn;
  for (const auto& frame : packet.frames) {
    folly::variant_match(
        frame,
        [&](const WriteStreamFrame& writeStreamFrame) {
          retransmittable = true;
          auto stream = CHECK_NOTNULL(
              conn.streamManager->getStream(writeStreamFrame.streamId));
          auto newStreamDataWritten = handleStreamWritten(
              conn,
              *stream,
              writeStreamFrame.offset,
              writeStreamFrame.len,
              writeStreamFrame.fin,
              packetNum,
              packetNumberSpace);
          if (newStreamDataWritten) {
            updateFlowControlOnWriteToSocket(*stream, writeStreamFrame.len);
            maybeWriteBlockAfterSocketWrite(*stream);
            conn.streamManager->updateWritableStreams(*stream);
          }
          conn.streamManager->updateLossStreams(*stream);
        },
        [&](const WriteCryptoFrame& writeCryptoFrame) {
          retransmittable = true;
          auto protectionType = folly::variant_match(
              packet.header,
              [](const auto& h) { return h.getProtectionType(); });
          // NewSessionTicket is sent in crypto frame encrypted with 1-rtt key,
          // however, it is not part of handshake
          isHandshake =
              (protectionType == ProtectionType::Initial ||
               protectionType == ProtectionType::Handshake);
          auto encryptionLevel =
              protectionTypeToEncryptionLevel(protectionType);
          handleStreamWritten(
              conn,
              *getCryptoStream(*conn.cryptoState, encryptionLevel),
              writeCryptoFrame.offset,
              writeCryptoFrame.len,
              false,
              packetNum,
              packetNumberSpace);
        },
        [&](const WriteAckFrame& writeAckFrame) {
          DCHECK(!ackFrameCounter++)
              << "Send more than one WriteAckFrame " << conn;
          auto largestAckedPacketWritten = writeAckFrame.ackBlocks.back().end;
          VLOG(10) << nodeToString(conn.nodeType)
                   << " sent packet with largestAcked="
                   << largestAckedPacketWritten << " packetNum=" << packetNum
                   << " " << conn;
          updateAckSendStateOnSentPacketWithAcks(
              conn,
              getAckState(conn, packetNumberSpace),
              largestAckedPacketWritten);
        },
        [&](const RstStreamFrame& rstStreamFrame) {
          retransmittable = true;
          VLOG(10) << nodeToString(conn.nodeType)
                   << " sent reset streams in packetNum=" << packetNum << " "
                   << conn;
          auto resetIter =
              conn.pendingEvents.resets.find(rstStreamFrame.streamId);
          // TODO: this can happen because we clone RST_STREAM frames. Should we
          // start to treat RST_STREAM in the same way we treat window update?
          if (resetIter != conn.pendingEvents.resets.end()) {
            conn.pendingEvents.resets.erase(resetIter);
          } else {
            DCHECK(packetEvent.hasValue())
                << " reset missing from pendingEvents for non-clone packet";
          }
        },
        [&](const MaxDataFrame& maxDataFrame) {
          CHECK(!connWindowUpdateSent++)
              << "Send more than one connection window update " << conn;
          VLOG(10) << nodeToString(conn.nodeType)
                   << " sent conn window update packetNum=" << packetNum << " "
                   << conn;
          retransmittable = true;
          VLOG(10) << nodeToString(conn.nodeType)
                   << " sent conn window update in packetNum=" << packetNum
                   << " " << conn;
          onConnWindowUpdateSent(
              conn, packetNum, maxDataFrame.maximumData, sentTime);
        },
        [&](const MaxStreamDataFrame& maxStreamDataFrame) {
          auto stream = CHECK_NOTNULL(
              conn.streamManager->getStream(maxStreamDataFrame.streamId));
          retransmittable = true;
          VLOG(10) << nodeToString(conn.nodeType)
                   << " sent packet with window update packetNum=" << packetNum
                   << " stream=" << maxStreamDataFrame.streamId << " " << conn;
          onStreamWindowUpdateSent(
              *stream, packetNum, maxStreamDataFrame.maximumData, sentTime);
        },
        [&](const StreamDataBlockedFrame& streamBlockedFrame) {
          VLOG(10) << nodeToString(conn.nodeType)
                   << " sent blocked stream frame packetNum=" << packetNum
                   << " " << conn;
          retransmittable = true;
          conn.streamManager->removeBlocked(streamBlockedFrame.streamId);
        },
        [&](const PaddingFrame&) {
          // do not mark padding as retransmittable. There are several reasons
          // for this:
          // 1. We might need to pad ACK packets to make it so that we can
          //    sample them correctly for header encryption. ACK packets may not
          //    count towards congestion window, so the padding frames in those
          //    ack packets should not count towards the window either
          // 2. Of course we do not want to retransmit the ACK frames.
        },
        [&](const QuicSimpleFrame& simpleFrame) {
          retransmittable = true;
          // We don't want this triggered for cloned frames.
          if (!packetEvent.hasValue()) {
            updateSimpleFrameOnPacketSent(conn, simpleFrame);
          }
        },
        [&](const auto&) { retransmittable = true; });
  }

  // TODO: Now pureAck is equivalent to non retransmittable packet. This might
  // change in the future.
  auto pureAck = !retransmittable;
  OutstandingPacket pkt(
      std::move(packet),
      std::move(sentTime),
      encodedSize,
      isHandshake,
      pureAck,
      conn.lossState.totalBytesSent + encodedSize);
  pkt.isAppLimited = conn.congestionController
      ? conn.congestionController->isAppLimited()
      : false;
  if (conn.lossState.lastAckedTime.hasValue() &&
      conn.lossState.lastAckedPacketSentTime.hasValue()) {
    pkt.lastAckedPacketInfo.emplace(
        *conn.lossState.lastAckedPacketSentTime,
        *conn.lossState.lastAckedTime,
        conn.lossState.totalBytesSentAtLastAck,
        conn.lossState.totalBytesAckedAtLastAck);
  }
  if (packetEvent) {
    DCHECK(conn.outstandingPacketEvents.count(*packetEvent));
    // CloningScheduler doesn't clone handshake packets or pureAck, and the
    // clone result cannot be pureAck either.
    DCHECK(!isHandshake);
    DCHECK(!pureAck);
    pkt.associatedEvent = std::move(packetEvent);
    conn.lossState.totalBytesCloned += encodedSize;
  }

  increaseNextPacketNum(conn, packetNumberSpace);
  QUIC_TRACE(
      packet_sent,
      conn,
      toString(packetNumberSpace),
      packetNum,
      (uint64_t)encodedSize,
      (int)isHandshake,
      (int)pureAck,
      pkt.isAppLimited);
  conn.lossState.largestSent = std::max(conn.lossState.largestSent, packetNum);
  if (conn.congestionController && !pureAck) {
    conn.congestionController->onPacketSent(pkt);
    // An approximation of the app being blocked. The app
    // technically might not have bytes to write.
    auto writableBytes = conn.congestionController->getWritableBytes();
    bool cwndBlocked = writableBytes < kBlockedSizeBytes;
    if (cwndBlocked) {
      QUIC_TRACE(
          cwnd_may_block,
          conn,
          writableBytes,
          conn.congestionController->getCongestionWindow());
    }
  }
  if (pkt.isHandshake) {
    ++conn.outstandingHandshakePacketsCount;
    conn.lossState.lastHandshakePacketSentTime = pkt.time;
  }
  if (pureAck) {
    ++conn.outstandingPureAckPacketsCount;
  } else {
    conn.lossState.lastRetransmittablePacketSentTime = pkt.time;
  }
  if (pkt.associatedEvent) {
    CHECK_EQ(packetNumberSpace, PacketNumberSpace::AppData);
    ++conn.outstandingClonedPacketsCount;
    ++conn.lossState.timeoutBasedRtxCount;
  }

  auto packetIt = std::lower_bound(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      packetNum,
      [&](const auto& packetWithTime, const auto& val) {
        return folly::variant_match(
            packetWithTime.packet.header,
            [&val](const auto& h) { return h.getPacketSequenceNum() < val; });
      });
  conn.outstandingPackets.insert(packetIt, std::move(pkt));

  auto opCount = conn.outstandingPackets.size();
  DCHECK_GE(opCount, conn.outstandingPureAckPacketsCount);
  DCHECK_GE(opCount, conn.outstandingHandshakePacketsCount);
  DCHECK_GE(opCount, conn.outstandingClonedPacketsCount);
  // updateConnection may be called multiple times during write. If before or
  // during any updateConnection, setLossDetectionAlarm is already set, we
  // shouldn't clear it:
  if (!conn.pendingEvents.setLossDetectionAlarm) {
    conn.pendingEvents.setLossDetectionAlarm = retransmittable;
  }
  conn.lossState.totalBytesSent += encodedSize;
}

uint64_t congestionControlWritableBytes(const QuicConnectionStateBase& conn) {
  uint64_t writableBytes = std::numeric_limits<uint64_t>::max();
  if (conn.writableBytesLimit) {
    if (*conn.writableBytesLimit <= conn.lossState.totalBytesSent) {
      return 0;
    }
    writableBytes = std::min<uint64_t>(
        writableBytes,
        *conn.writableBytesLimit - conn.lossState.totalBytesSent);
  }
  if (conn.congestionController) {
    writableBytes = std::min<uint64_t>(
        writableBytes, conn.congestionController->getWritableBytes());
  }

  return writableBytes;
}

uint64_t unlimitedWritableBytes(const QuicConnectionStateBase&) {
  return std::numeric_limits<uint64_t>::max();
}

HeaderBuilder LongHeaderBuilder(LongHeader::Types packetType) {
  return [packetType](
             const ConnectionId& srcConnId,
             const ConnectionId& dstConnId,
             PacketNum packetNum,
             QuicVersion version,
             Buf token) {
    return LongHeader(
        packetType,
        srcConnId,
        dstConnId,
        packetNum,
        version,
        token ? std::move(token) : nullptr);
  };
}

HeaderBuilder ShortHeaderBuilder() {
  return [](const ConnectionId& /* srcConnId */,
            const ConnectionId& dstConnId,
            PacketNum packetNum,
            QuicVersion,
            Buf) {
    return ShortHeader(ProtectionType::KeyPhaseZero, dstConnId, packetNum);
  };
}

uint64_t writeQuicDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit) {
  auto builder = ShortHeaderBuilder();
  // TODO: In FrameScheduler, Retx is prioritized over new data. We should
  // add a flag to the Scheduler to control the priority between them and see
  // which way is better.
  uint64_t written = 0;
  if (connection.pendingEvents.numProbePackets) {
    auto probeScheduler = std::move(FrameScheduler::Builder(
                                        connection,
                                        fizz::EncryptionLevel::AppTraffic,
                                        PacketNumberSpace::AppData,
                                        "ProbeScheduler")
                                        .streamFrames()
                                        .streamRetransmissions()
                                        .cryptoFrames())
                              .build();
    written = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        PacketNumberSpace::AppData,
        probeScheduler,
        std::min<uint64_t>(
            packetLimit, connection.pendingEvents.numProbePackets),
        aead,
        headerCipher,
        version);
    connection.pendingEvents.numProbePackets = 0;
  }
  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           connection,
                                           fizz::EncryptionLevel::AppTraffic,
                                           PacketNumberSpace::AppData,
                                           "FrameScheduler")
                                           .streamFrames()
                                           .ackFrames()
                                           .streamRetransmissions()
                                           .resetFrames()
                                           .windowUpdateFrames()
                                           .blockedFrames()
                                           .cryptoFrames()
                                           .simpleFrames())
                                 .build();
  written += writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      builder,
      PacketNumberSpace::AppData,
      scheduler,
      congestionControlWritableBytes,
      packetLimit - written,
      aead,
      headerCipher,
      version);
  VLOG_IF(10, written > 0) << nodeToString(connection.nodeType)
                           << " written data to socket packets=" << written
                           << " " << connection;
  DCHECK_GE(packetLimit, written);
  return written;
}

uint64_t writeCryptoAndAckDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types packetType,
    Aead& cleartextCipher,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    Buf token) {
  auto encryptionLevel = protectionTypeToEncryptionLevel(
      longHeaderTypeToProtectionType(packetType));
  FrameScheduler scheduler =
      std::move(FrameScheduler::Builder(
                    connection,
                    encryptionLevel,
                    longHeaderTypeToPacketNumberSpace(packetType),
                    "CryptoAndAcksScheduler")
                    .ackFrames()
                    .cryptoFrames())
          .build();
  auto builder = LongHeaderBuilder(packetType);
  // Crypto data is written without aead protection.
  auto written = writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      builder,
      longHeaderTypeToPacketNumberSpace(packetType),
      scheduler,
      congestionControlWritableBytes,
      packetLimit,
      cleartextCipher,
      headerCipher,
      version,
      token ? std::move(token) : nullptr);
  VLOG_IF(10, written > 0) << nodeToString(connection.nodeType)
                           << " written crypto and acks data type="
                           << packetType << " packets=" << written << " "
                           << connection;
  DCHECK_GE(packetLimit, written);
  return written;
}

uint64_t writeQuicDataExceptCryptoStreamToSocket(
    folly::AsyncUDPSocket& socket,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit) {
  auto builder = ShortHeaderBuilder();
  uint64_t written = 0;
  if (connection.pendingEvents.numProbePackets) {
    auto probeScheduler = std::move(FrameScheduler::Builder(
                                      connection,
                                      fizz::EncryptionLevel::AppTraffic,
                                      PacketNumberSpace::AppData,
                                      "ProbeWithoutCrypto")
                                      .streamFrames()
                                      .streamRetransmissions())
                            .build();
    written = writeProbingDataToSocket(
        socket,
        connection,
        srcConnId,
        dstConnId,
        builder,
        PacketNumberSpace::AppData,
        probeScheduler,
        std::min<uint64_t>(
            packetLimit, connection.pendingEvents.numProbePackets),
        aead,
        headerCipher,
        version);
    connection.pendingEvents.numProbePackets = 0;
  }
  FrameScheduler scheduler = std::move(FrameScheduler::Builder(
                                           connection,
                                           fizz::EncryptionLevel::AppTraffic,
                                           PacketNumberSpace::AppData,
                                           "FrameSchedulerWithoutCrypto")
                                           .streamFrames()
                                           .ackFrames()
                                           .streamRetransmissions()
                                           .resetFrames()
                                           .windowUpdateFrames()
                                           .blockedFrames()
                                           .simpleFrames())
                                 .build();
  written += writeConnectionDataToSocket(
      socket,
      connection,
      srcConnId,
      dstConnId,
      builder,
      PacketNumberSpace::AppData,
      scheduler,
      congestionControlWritableBytes,
      packetLimit - written,
      aead,
      headerCipher,
      version);
  VLOG_IF(10, written > 0) << nodeToString(connection.nodeType)
                           << " written data except crypto data, packets="
                           << written << " " << connection;
  DCHECK_GE(packetLimit, written);
  return written;
}

uint64_t writeZeroRttDataToSocket(
    folly::AsyncUDPSocket& socket,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit) {
  auto type = LongHeader::Types::ZeroRtt;
  auto encryptionLevel =
      protectionTypeToEncryptionLevel(longHeaderTypeToProtectionType(type));
  auto builder = LongHeaderBuilder(type);
  // Probe is not useful for zero rtt because we will always have handshake
  // packets outstanding when sending zero rtt data.
  FrameScheduler scheduler =
      std::move(FrameScheduler::Builder(
                    connection,
                    encryptionLevel,
                    longHeaderTypeToPacketNumberSpace(type),
                    "ZeroRttScheduler")
                    .streamFrames()
                    .streamRetransmissions()
                    .resetFrames()
                    .windowUpdateFrames()
                    .blockedFrames()
                    .simpleFrames())
          .build();
  auto written = writeConnectionDataToSocket(
      socket,
      connection,
      srcConnId,
      dstConnId,
      builder,
      longHeaderTypeToPacketNumberSpace(type),
      scheduler,
      congestionControlWritableBytes,
      packetLimit,
      aead,
      headerCipher,
      version);
  VLOG_IF(10, written > 0) << nodeToString(connection.nodeType)
                           << " written zero rtt data, packets=" << written
                           << " " << connection;
  DCHECK_GE(packetLimit, written);
  return written;
}

void writeCloseCommon(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    PacketHeader&& header,
    folly::Optional<std::pair<QuicErrorCode, std::string>> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  // close is special, we're going to bypass all the packet sent logic for all
  // packets we send with a connection close frame.
  auto pnSpace = folly::variant_match(
      header, [](const auto& h) { return h.getPacketNumberSpace(); });
  PacketNum packetNum = folly::variant_match(
      header, [](const auto& h) { return h.getPacketSequenceNum(); });
  RegularQuicPacketBuilder packetBuilder(
      connection.udpSendPacketLen,
      std::move(header),
      getAckState(connection, pnSpace).largestAckedByPeer);
  packetBuilder.setCipherOverhead(aead.getCipherOverhead());
  size_t written = 0;
  if (!closeDetails) {
    written = writeFrame(
        ConnectionCloseFrame(
            TransportErrorCode::NO_ERROR, std::string("No error")),
        packetBuilder);
  } else {
    written = folly::variant_match(
        closeDetails->first,
        [&](ApplicationErrorCode code) {
          return writeFrame(
              ApplicationCloseFrame(code, closeDetails->second), packetBuilder);
        },
        [&](TransportErrorCode code) {
          return writeFrame(
              ConnectionCloseFrame(code, closeDetails->second), packetBuilder);
        },
        [&](LocalErrorCode /*code*/) {
          return writeFrame(
              ConnectionCloseFrame(
                  TransportErrorCode::INTERNAL_ERROR,
                  std::string("Internal error")),
              packetBuilder);
        });
  }
  if (written == 0) {
    LOG(ERROR) << "Close frame too large " << connection;
    return;
  }
  auto packet = std::move(packetBuilder).buildPacket();
  auto body =
      aead.encrypt(std::move(packet.body), packet.header.get(), packetNum);
  HeaderForm headerForm = folly::variant_match(
      header,
      [](const ShortHeader&) { return HeaderForm::Short; },
      [](const LongHeader&) { return HeaderForm::Long; });
  encryptPacketHeader(headerForm, *packet.header, *body, headerCipher);
  auto packetBuf = std::move(packet.header);
  packetBuf->prependChain(std::move(body));
  auto packetSize = packetBuf->computeChainDataLength();
  QUIC_TRACE(
      packet_sent,
      connection,
      toString(pnSpace),
      packetNum,
      (uint64_t)packetSize,
      (int)false,
      (int)false);
  VLOG(10) << nodeToString(connection.nodeType)
           << " sent close packetNum=" << packetNum << " in space=" << pnSpace
           << " " << connection;
  // Increment the sequence number.
  // TODO: Do not increase pn if write fails
  increaseNextPacketNum(connection, pnSpace);
  // best effort writing to the socket, ignore any errors.
  auto ret = sock.write(connection.peerAddress, packetBuf);
  connection.lossState.totalBytesSent += packetSize;
  if (ret < 0) {
    VLOG(4) << "Error writing connection close " << folly::errnoStr(errno)
            << " " << connection;
  } else {
    QUIC_STATS(connection.infoCallback, onWrite, ret);
  }
}

void writeLongClose(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types headerType,
    folly::Optional<std::pair<QuicErrorCode, std::string>> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version) {
  if (!connection.serverConnectionId) {
    // It's possible that servers encountered an error before binding to a
    // connection id.
    return;
  }
  LongHeader header(
      headerType,
      srcConnId,
      dstConnId,
      getNextPacketNum(
          connection, longHeaderTypeToPacketNumberSpace(headerType)),
      version);
  writeCloseCommon(
      sock,
      connection,
      std::move(header),
      std::move(closeDetails),
      aead,
      headerCipher);
}

void writeShortClose(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& connId,
    folly::Optional<std::pair<QuicErrorCode, std::string>> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  auto header = ShortHeader(
      ProtectionType::KeyPhaseZero,
      connId,
      getNextPacketNum(connection, PacketNumberSpace::AppData));
  writeCloseCommon(
      sock,
      connection,
      std::move(header),
      std::move(closeDetails),
      aead,
      headerCipher);
}

void encryptPacketHeader(
    HeaderForm headerForm,
    folly::IOBuf& header,
    folly::IOBuf& encryptedBody,
    const PacketNumberCipher& headerCipher) {
  // Header encryption.
  auto packetNumberLength = parsePacketNumberLength(header.data()[0]);
  Sample sample;
  size_t sampleBytesToUse = kMaxPacketNumEncodingSize - packetNumberLength;
  folly::io::Cursor sampleCursor(&encryptedBody);
  // If there were less than 4 bytes in the packet number, some of the payload
  // bytes will also be skipped during sampling.
  sampleCursor.skip(sampleBytesToUse);
  CHECK(sampleCursor.canAdvance(sample.size())) << "Not enough sample bytes";
  sampleCursor.pull(sample.data(), sample.size());

  // This should already be a single buffer.
  header.coalesce();
  folly::MutableByteRange initialByteRange(header.writableData(), 1);
  folly::MutableByteRange packetNumByteRange(
      header.writableData() + header.length() - packetNumberLength,
      packetNumberLength);
  if (headerForm == HeaderForm::Short) {
    headerCipher.encryptShortHeader(
        sample, initialByteRange, packetNumByteRange);
  } else {
    headerCipher.encryptLongHeader(
        sample, initialByteRange, packetNumByteRange);
  }
}

uint64_t writeConnectionDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const HeaderBuilder& builder,
    PacketNumberSpace pnSpace,
    QuicPacketScheduler& scheduler,
    const WritableBytesFunc& writableBytesFunc,
    uint64_t packetLimit,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    Buf token) {
  VLOG(10) << nodeToString(connection.nodeType)
           << " writing data using scheduler=" << scheduler.name() << " "
           << connection;

  auto batchWriter = BatchWriterFactory::makeBatchWriter(
      sock,
      connection.transportSettings.batchingMode,
      connection.transportSettings.maxBatchSize);

  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter),
      sock,
      connection.peerAddress,
      connection,
      connection.happyEyeballsState);
  ioBufBatch.setContinueOnNetworkUnreachable(
      connection.transportSettings.continueOnNetworkUnreachable);

  while (scheduler.hasData() && ioBufBatch.getPktSent() < packetLimit) {
    auto packetNum = getNextPacketNum(connection, pnSpace);
    auto header = builder(
        srcConnId,
        dstConnId,
        packetNum,
        version,
        token ? token->clone() : nullptr);
    uint32_t writableBytes = folly::to<uint32_t>(std::min<uint64_t>(
        connection.udpSendPacketLen, writableBytesFunc(connection)));
    uint64_t cipherOverhead = aead.getCipherOverhead();
    if (writableBytes < cipherOverhead) {
      writableBytes = 0;
    } else {
      writableBytes -= cipherOverhead;
    }
    RegularQuicPacketBuilder pktBuilder(
        connection.udpSendPacketLen,
        std::move(header),
        getAckState(connection, pnSpace).largestAckedByPeer);
    pktBuilder.setCipherOverhead(cipherOverhead);
    auto result =
        scheduler.scheduleFramesForPacket(std::move(pktBuilder), writableBytes);
    auto& packet = result.second;
    if (!packet || packet->packet.frames.empty()) {
      ioBufBatch.flush();
      return ioBufBatch.getPktSent();
    }
    if (!packet->body) {
      // No more space remaining.
      ioBufBatch.flush();
      return ioBufBatch.getPktSent();
    }
    auto body =
        aead.encrypt(std::move(packet->body), packet->header.get(), packetNum);

    HeaderForm headerForm = folly::variant_match(
        packet->packet.header,
        [](const LongHeader&) { return HeaderForm::Long; },
        [](const ShortHeader&) { return HeaderForm::Short; });
    encryptPacketHeader(headerForm, *packet->header, *body, headerCipher);

    auto packetBuf = std::move(packet->header);
    packetBuf->prependChain(std::move(body));
    auto encodedSize = packetBuf->computeChainDataLength();

    bool ret = ioBufBatch.write(std::move(packetBuf), encodedSize);

    if (ret) {
      // update stats and connection
      QUIC_STATS(connection.infoCallback, onWrite, encodedSize);
      QUIC_STATS(connection.infoCallback, onPacketSent);
    }

    updateConnection(
        connection,
        std::move(result.first),
        std::move(result.second->packet),
        Clock::now(),
        folly::to<uint32_t>(encodedSize));

    // if ioBufBatch.write returns false
    // it is because a flush() call failed
    if (!ret) {
      return ioBufBatch.getPktSent();
    }
  }

  ioBufBatch.flush();
  return ioBufBatch.getPktSent();
}

uint64_t writeProbingDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const HeaderBuilder& builder,
    PacketNumberSpace pnSpace,
    FrameScheduler scheduler,
    uint8_t probesToSend,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version) {
  CloningScheduler cloningScheduler(
      scheduler, connection, "CloningScheduler", aead.getCipherOverhead());
  auto written = writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      builder,
      pnSpace,
      cloningScheduler,
      unlimitedWritableBytes,
      probesToSend,
      aead,
      headerCipher,
      version);
  VLOG_IF(10, written > 0)
      << nodeToString(connection.nodeType)
      << " writing probes using scheduler=CloningScheduler " << connection;
  return written;
}

bool shouldWriteData(const QuicConnectionStateBase& conn) {
  if (conn.pendingEvents.numProbePackets) {
    VLOG(10) << nodeToString(conn.nodeType) << " needs write because of PTO"
             << conn;
    return true;
  }
  if (hasAckDataToWrite(conn)) {
    VLOG(10) << nodeToString(conn.nodeType) << " needs write because of ACKs "
             << conn;
    return true;
  }
  const size_t minimumDataSize = std::max(
      kLongHeaderHeaderSize + kCipherOverheadHeuristic, sizeof(Sample));
  if (conn.writableBytesLimit &&
      (*conn.writableBytesLimit <= conn.lossState.totalBytesSent ||
       *conn.writableBytesLimit - conn.lossState.totalBytesSent <=
           minimumDataSize)) {
    QUIC_STATS(conn.infoCallback, onCwndBlocked);
    return false;
  }
  if (conn.congestionController &&
      conn.congestionController->getWritableBytes() <= minimumDataSize) {
    QUIC_STATS(conn.infoCallback, onCwndBlocked);
    return false;
  }
  return hasNonAckDataToWrite(conn);
}

bool hasAckDataToWrite(const QuicConnectionStateBase& conn) {
  // hasAcksToSchedule tells us whether we have acks.
  // needsToSendAckImmediately tells us when to schedule the acks. If we don't
  // have an immediate need to schedule the acks then we need to wait till we
  // satisfy a condition where there is immediate need, so we shouldn't
  // consider the acks to be writable.
  bool writeAcks =
      (toWriteInitialAcks(conn) || toWriteHandshakeAcks(conn) ||
       toWriteAppDataAcks(conn));
  VLOG_IF(10, writeAcks) << nodeToString(conn.nodeType)
                         << " needs write because of acks largestAck="
                         << largestAckToSendToString(conn) << " largestSentAck="
                         << largestAckScheduledToString(conn)
                         << " ackTimeoutSet="
                         << conn.pendingEvents.scheduleAckTimeout << " "
                         << conn;
  return writeAcks;
}

bool hasNonAckDataToWrite(const QuicConnectionStateBase& conn) {
  if (cryptoHasWritableData(conn)) {
    VLOG(10) << nodeToString(conn.nodeType)
             << " needs write because of crypto stream"
             << " " << conn;
    return true;
  }
  if (!conn.oneRttWriteCipher && !conn.zeroRttWriteCipher) {
    // All the rest of the types of data need either a 1-rtt or 0-rtt cipher to
    // be written.
    return false;
  }
  bool hasStreamData = getSendConnFlowControlBytesWire(conn) != 0 &&
      conn.streamManager->hasWritable();
  bool hasLoss = conn.streamManager->hasLoss();
  bool hasBlocked = conn.streamManager->hasBlocked();
  bool hasStreamWindowUpdates = conn.streamManager->hasWindowUpdates();
  bool hasConnWindowUpdate = conn.pendingEvents.connWindowUpdate;
  bool hasSimple = !conn.pendingEvents.frames.empty();
  bool hasResets = !conn.pendingEvents.resets.empty();
  bool hasPathChallenge = (conn.pendingEvents.pathChallenge != folly::none);
  return hasStreamData || hasLoss || hasBlocked || hasStreamWindowUpdates ||
      hasConnWindowUpdate || hasResets || hasSimple || hasPathChallenge;
}
} // namespace quic
