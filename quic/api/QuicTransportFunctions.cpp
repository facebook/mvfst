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
#include <quic/api/QuicTransportFunctions.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>
#include <quic/logging/QuicLogger.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>

namespace {

/*
 *  Check whether crypto has pending data.
 */
bool cryptoHasWritableData(const quic::QuicConnectionStateBase& conn) {
  return (conn.initialWriteCipher &&
          (!conn.cryptoState->initialStream.writeBuffer.empty() ||
           !conn.cryptoState->initialStream.lossBuffer.empty())) ||
      (conn.handshakeWriteCipher &&
       (!conn.cryptoState->handshakeStream.writeBuffer.empty() ||
        !conn.cryptoState->handshakeStream.lossBuffer.empty())) ||
      (conn.oneRttWriteCipher &&
       (!conn.cryptoState->oneRttStream.writeBuffer.empty() ||
        !conn.cryptoState->oneRttStream.lossBuffer.empty()));
}

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

using namespace quic;

uint64_t writeQuicDataToSocketImpl(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    bool exceptCryptoStream) {
  auto builder = ShortHeaderBuilder();
  // TODO: In FrameScheduler, Retx is prioritized over new data. We should
  // add a flag to the Scheduler to control the priority between them and see
  // which way is better.
  uint64_t written = 0;
  if (connection.pendingEvents.numProbePackets) {
    auto probeSchedulerBuilder =
        FrameScheduler::Builder(
            connection,
            EncryptionLevel::AppData,
            PacketNumberSpace::AppData,
            exceptCryptoStream ? "ProbeWithoutCrypto" : "ProbeScheduler")
            .blockedFrames()
            .windowUpdateFrames()
            .simpleFrames()
            .resetFrames()
            .streamFrames()
            .streamRetransmissions()
            .pingFrames();
    if (!exceptCryptoStream) {
      probeSchedulerBuilder.cryptoFrames();
    }
    auto probeScheduler = std::move(probeSchedulerBuilder).build();
    written = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        EncryptionLevel::AppData,
        PacketNumberSpace::AppData,
        probeScheduler,
        std::min<uint64_t>(
            packetLimit, connection.pendingEvents.numProbePackets),
        aead,
        headerCipher,
        version);
    CHECK_GE(connection.pendingEvents.numProbePackets, written);
    connection.pendingEvents.numProbePackets -= written;
  }
  auto schedulerBuilder =
      FrameScheduler::Builder(
          connection,
          EncryptionLevel::AppData,
          PacketNumberSpace::AppData,
          exceptCryptoStream ? "FrameSchedulerWithoutCrypto" : "FrameScheduler")
          .streamFrames()
          .ackFrames()
          .streamRetransmissions()
          .resetFrames()
          .windowUpdateFrames()
          .blockedFrames()
          .simpleFrames()
          .pingFrames();
  if (!exceptCryptoStream) {
    schedulerBuilder.cryptoFrames();
  }
  FrameScheduler scheduler = std::move(schedulerBuilder).build();
  written += writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      std::move(builder),
      PacketNumberSpace::AppData,
      scheduler,
      congestionControlWritableBytes,
      packetLimit - written,
      aead,
      headerCipher,
      version);
  VLOG_IF(10, written > 0) << nodeToString(connection.nodeType)
                           << " written data "
                           << (exceptCryptoStream ? "without crypto data " : "")
                           << "to socket packets=" << written << " "
                           << connection;
  DCHECK_GE(packetLimit, written);
  return written;
}

DataPathResult continuousMemoryBuildScheduleEncrypt(
    QuicConnectionStateBase& connection,
    PacketHeader header,
    PacketNumberSpace pnSpace,
    PacketNum packetNum,
    uint64_t cipherOverhead,
    QuicPacketScheduler& scheduler,
    uint64_t writableBytes,
    IOBufQuicBatch& ioBufBatch,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  auto buf = connection.bufAccessor->obtain();
  auto prevSize = buf->length();
  connection.bufAccessor->release(std::move(buf));

  auto rollbackBuf = [&]() {
    auto buf = connection.bufAccessor->obtain();
    buf->trimEnd(buf->length() - prevSize);
    connection.bufAccessor->release(std::move(buf));
  };

  // It's the scheduler's job to invoke encode header
  InplaceQuicPacketBuilder pktBuilder(
      *connection.bufAccessor,
      connection.udpSendPacketLen,
      std::move(header),
      getAckState(connection, pnSpace).largestAckedByPeer.value_or(0));
  pktBuilder.accountForCipherOverhead(cipherOverhead);
  CHECK(scheduler.hasData());
  auto result =
      scheduler.scheduleFramesForPacket(std::move(pktBuilder), writableBytes);
  CHECK(connection.bufAccessor->ownsBuffer());
  auto& packet = result.packet;
  if (!packet || packet->packet.frames.empty()) {
    rollbackBuf();
    ioBufBatch.flush();
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::NO_FRAME;
    }
    return DataPathResult::makeBuildFailure();
  }
  if (!packet->body) {
    // No more space remaining.
    rollbackBuf();
    ioBufBatch.flush();
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::NO_BODY;
    }
    return DataPathResult::makeBuildFailure();
  }
  CHECK(!packet->header->isChained());
  auto headerLen = packet->header->length();
  buf = connection.bufAccessor->obtain();
  CHECK(
      packet->body->data() > buf->data() &&
      packet->body->tail() <= buf->tail());
  CHECK(
      packet->header->data() >= buf->data() &&
      packet->header->tail() < buf->tail());
  // Trim off everything before the current packet, and the header length, so
  // buf's data starts from the body part of buf.
  buf->trimStart(prevSize + headerLen);
  // buf and packetBuf is actually the same.
  auto packetBuf =
      aead.inplaceEncrypt(std::move(buf), packet->header.get(), packetNum);
  CHECK(packetBuf->headroom() == headerLen + prevSize);
  // Include header back.
  packetBuf->prepend(headerLen);

  HeaderForm headerForm = packet->packet.header.getHeaderForm();
  encryptPacketHeader(
      headerForm,
      packetBuf->writableData(),
      headerLen,
      packetBuf->data() + headerLen,
      packetBuf->length() - headerLen,
      headerCipher);
  CHECK(!packetBuf->isChained());
  auto encodedSize = packetBuf->length();
  // Include previous packets back.
  packetBuf->prepend(prevSize);
  connection.bufAccessor->release(std::move(packetBuf));
#if !FOLLY_MOBILE
  if (encodedSize > connection.udpSendPacketLen) {
    LOG_EVERY_N(ERROR, 5000)
        << "Quic sending pkt larger than limit, encodedSize=" << encodedSize;
  }
#endif
  // TODO: I think we should add an API that doesn't need a buffer.
  bool ret = ioBufBatch.write(nullptr /* no need to pass buf */, encodedSize);
  // update stats and connection
  if (ret) {
    QUIC_STATS(connection.statsCallback, onWrite, encodedSize);
    QUIC_STATS(connection.statsCallback, onPacketSent);
  }
  return DataPathResult::makeWriteResult(ret, std::move(result), encodedSize);
}

DataPathResult iobufChainBasedBuildScheduleEncrypt(
    QuicConnectionStateBase& connection,
    PacketHeader header,
    PacketNumberSpace pnSpace,
    PacketNum packetNum,
    uint64_t cipherOverhead,
    QuicPacketScheduler& scheduler,
    uint64_t writableBytes,
    IOBufQuicBatch& ioBufBatch,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  RegularQuicPacketBuilder pktBuilder(
      connection.udpSendPacketLen,
      std::move(header),
      getAckState(connection, pnSpace).largestAckedByPeer.value_or(0));
  // It's the scheduler's job to invoke encode header
  pktBuilder.accountForCipherOverhead(cipherOverhead);
  auto result =
      scheduler.scheduleFramesForPacket(std::move(pktBuilder), writableBytes);
  auto& packet = result.packet;
  if (!packet || packet->packet.frames.empty()) {
    ioBufBatch.flush();
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::NO_FRAME;
    }
    return DataPathResult::makeBuildFailure();
  }
  if (!packet->body) {
    // No more space remaining.
    ioBufBatch.flush();
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::NO_BODY;
    }
    return DataPathResult::makeBuildFailure();
  }
  packet->header->coalesce();
  auto headerLen = packet->header->length();
  auto bodyLen = packet->body->computeChainDataLength();
  auto unencrypted =
      folly::IOBuf::create(headerLen + bodyLen + aead.getCipherOverhead());
  auto bodyCursor = folly::io::Cursor(packet->body.get());
  bodyCursor.pull(unencrypted->writableData() + headerLen, bodyLen);
  unencrypted->advance(headerLen);
  unencrypted->append(bodyLen);
  auto packetBuf = aead.inplaceEncrypt(
      std::move(unencrypted), packet->header.get(), packetNum);
  DCHECK(packetBuf->headroom() == headerLen);
  packetBuf->clear();
  auto headerCursor = folly::io::Cursor(packet->header.get());
  headerCursor.pull(packetBuf->writableData(), headerLen);
  packetBuf->append(headerLen + bodyLen + aead.getCipherOverhead());

  HeaderForm headerForm = packet->packet.header.getHeaderForm();
  encryptPacketHeader(
      headerForm,
      packetBuf->writableData(),
      headerLen,
      packetBuf->data() + headerLen,
      packetBuf->length() - headerLen,
      headerCipher);
  auto encodedSize = packetBuf->computeChainDataLength();
#if !FOLLY_MOBILE
  if (encodedSize > connection.udpSendPacketLen) {
    LOG_EVERY_N(ERROR, 5000)
        << "Quic sending pkt larger than limit, encodedSize=" << encodedSize;
  }
#endif
  bool ret = ioBufBatch.write(std::move(packetBuf), encodedSize);
  if (ret) {
    // update stats and connection
    QUIC_STATS(connection.statsCallback, onWrite, encodedSize);
    QUIC_STATS(connection.statsCallback, onPacketSent);
  }
  return DataPathResult::makeWriteResult(ret, std::move(result), encodedSize);
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
  auto bufWritten = stream.writeBuffer.splitAtMost(folly::to<size_t>(frameLen));
  DCHECK_EQ(bufWritten->computeChainDataLength(), frameLen);
  stream.currentWriteOffset += frameFin ? 1 : 0;
  CHECK(stream.retransmissionBuffer
            .emplace(
                std::piecewise_construct,
                std::forward_as_tuple(originalOffset),
                std::forward_as_tuple(std::make_unique<StreamBuffer>(
                    std::move(bufWritten), originalOffset, frameFin)))
            .second);
}

void handleRetransmissionWritten(
    QuicConnectionStateBase& conn,
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    std::deque<StreamBuffer>::iterator lossBufferIter) {
  conn.lossState.totalBytesRetransmitted += frameLen;
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
    bufWritten = lossBufferIter->data.splitAtMost(frameLen);
  }
  CHECK(stream.retransmissionBuffer
            .emplace(
                std::piecewise_construct,
                std::forward_as_tuple(frameOffset),
                std::forward_as_tuple(std::make_unique<StreamBuffer>(
                    std::move(bufWritten), frameOffset, frameFin)))
            .second);
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

  // If the data is in the loss buffer, it is a retransmission.
  auto lossBufferIter = std::lower_bound(
      stream.lossBuffer.begin(),
      stream.lossBuffer.end(),
      frameOffset,
      [](const auto& buf, auto off) { return buf.offset < off; });
  if (lossBufferIter != stream.lossBuffer.end() &&
      lossBufferIter->offset == frameOffset) {
    handleRetransmissionWritten(
        conn,
        stream,
        frameOffset,
        frameLen,
        frameFin,
        packetNum,
        lossBufferIter);
    QUIC_STATS(conn.statsCallback, onPacketRetransmission);
    return false;
  }

  // Otherwise it must be a clone write.
  conn.lossState.totalStreamBytesCloned += frameLen;
  return false;
}

void updateConnection(
    QuicConnectionStateBase& conn,
    folly::Optional<PacketEvent> packetEvent,
    RegularQuicWritePacket packet,
    TimePoint sentTime,
    uint32_t encodedSize) {
  auto packetNum = packet.header.getPacketSequenceNum();
  bool retransmittable = false; // AckFrame and PaddingFrame are not retx-able.
  bool isHandshake = false;
  bool isPing = false;
  uint32_t connWindowUpdateSent = 0;
  uint32_t ackFrameCounter = 0;
  auto packetNumberSpace = packet.header.getPacketNumberSpace();
  VLOG(10) << nodeToString(conn.nodeType) << " sent packetNum=" << packetNum
           << " in space=" << packetNumberSpace << " size=" << encodedSize
           << " " << conn;
  if (conn.qLogger) {
    conn.qLogger->addPacket(packet, encodedSize);
  }
  for (const auto& frame : packet.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::WriteStreamFrame_E: {
        const WriteStreamFrame& writeStreamFrame = *frame.asWriteStreamFrame();
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
          maybeWriteDataBlockedAfterSocketWrite(conn);
          conn.streamManager->updateWritableStreams(*stream);
          conn.streamManager->addTx(writeStreamFrame.streamId);
        }
        conn.streamManager->updateLossStreams(*stream);
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame_E: {
        const WriteCryptoFrame& writeCryptoFrame = *frame.asWriteCryptoFrame();
        retransmittable = true;
        auto protectionType = packet.header.getProtectionType();
        // NewSessionTicket is sent in crypto frame encrypted with 1-rtt key,
        // however, it is not part of handshake
        isHandshake =
            (protectionType == ProtectionType::Initial ||
             protectionType == ProtectionType::Handshake);
        auto encryptionLevel = protectionTypeToEncryptionLevel(protectionType);
        handleStreamWritten(
            conn,
            *getCryptoStream(*conn.cryptoState, encryptionLevel),
            writeCryptoFrame.offset,
            writeCryptoFrame.len,
            false,
            packetNum,
            packetNumberSpace);
        break;
      }
      case QuicWriteFrame::Type::WriteAckFrame_E: {
        const WriteAckFrame& writeAckFrame = *frame.asWriteAckFrame();
        DCHECK(!ackFrameCounter++)
            << "Send more than one WriteAckFrame " << conn;
        auto largestAckedPacketWritten = writeAckFrame.ackBlocks.front().end;
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent packet with largestAcked="
                 << largestAckedPacketWritten << " packetNum=" << packetNum
                 << " " << conn;
        updateAckSendStateOnSentPacketWithAcks(
            conn,
            getAckState(conn, packetNumberSpace),
            largestAckedPacketWritten);
        break;
      }
      case QuicWriteFrame::Type::RstStreamFrame_E: {
        const RstStreamFrame& rstStreamFrame = *frame.asRstStreamFrame();
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
          DCHECK(packetEvent.has_value())
              << " reset missing from pendingEvents for non-clone packet";
        }
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame_E: {
        const MaxDataFrame& maxDataFrame = *frame.asMaxDataFrame();
        CHECK(!connWindowUpdateSent++)
            << "Send more than one connection window update " << conn;
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent conn window update packetNum=" << packetNum << " "
                 << conn;
        retransmittable = true;
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent conn window update in packetNum=" << packetNum << " "
                 << conn;
        onConnWindowUpdateSent(
            conn, packetNum, maxDataFrame.maximumData, sentTime);
        break;
      }
      case QuicWriteFrame::Type::DataBlockedFrame_E: {
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent conn data blocked frame=" << packetNum << " "
                 << conn;
        retransmittable = true;
        conn.pendingEvents.sendDataBlocked = false;
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame_E: {
        const MaxStreamDataFrame& maxStreamDataFrame =
            *frame.asMaxStreamDataFrame();
        auto stream = CHECK_NOTNULL(
            conn.streamManager->getStream(maxStreamDataFrame.streamId));
        retransmittable = true;
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent packet with window update packetNum=" << packetNum
                 << " stream=" << maxStreamDataFrame.streamId << " " << conn;
        onStreamWindowUpdateSent(
            *stream, packetNum, maxStreamDataFrame.maximumData, sentTime);
        break;
      }
      case QuicWriteFrame::Type::StreamDataBlockedFrame_E: {
        const StreamDataBlockedFrame& streamBlockedFrame =
            *frame.asStreamDataBlockedFrame();
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent blocked stream frame packetNum=" << packetNum << " "
                 << conn;
        retransmittable = true;
        conn.streamManager->removeBlocked(streamBlockedFrame.streamId);
        break;
      }
      case QuicWriteFrame::Type::PingFrame_E:
        conn.pendingEvents.sendPing = false;
        isPing = true;
        break;
      case QuicWriteFrame::Type::QuicSimpleFrame_E: {
        const QuicSimpleFrame& simpleFrame = *frame.asQuicSimpleFrame();
        retransmittable = true;
        // We don't want this triggered for cloned frames.
        if (!packetEvent.has_value()) {
          updateSimpleFrameOnPacketSent(conn, simpleFrame);
        }
        break;
      }
      case QuicWriteFrame::Type::PaddingFrame_E: {
        // do not mark padding as retransmittable. There are several reasons
        // for this:
        // 1. We might need to pad ACK packets to make it so that we can
        //    sample them correctly for header encryption. ACK packets may not
        //    count towards congestion window, so the padding frames in those
        //    ack packets should not count towards the window either
        // 2. Of course we do not want to retransmit the ACK frames.
        break;
      }
      default:
        retransmittable = true;
    }
  }

  increaseNextPacketNum(conn, packetNumberSpace);
  conn.lossState.largestSent =
      std::max(conn.lossState.largestSent.value_or(packetNum), packetNum);
  // updateConnection may be called multiple times during write. If before or
  // during any updateConnection, setLossDetectionAlarm is already set, we
  // shouldn't clear it:
  if (!conn.pendingEvents.setLossDetectionAlarm) {
    conn.pendingEvents.setLossDetectionAlarm = retransmittable;
  }
  conn.lossState.totalBytesSent += encodedSize;

  if (!retransmittable && !isPing) {
    DCHECK(!packetEvent);
    return;
  }
  auto packetIt =
      std::find_if(
          conn.outstandings.packets.rbegin(),
          conn.outstandings.packets.rend(),
          [packetNum](const auto& packetWithTime) {
            return packetWithTime.packet.header.getPacketSequenceNum() <
                packetNum;
          })
          .base();
  auto& pkt = *conn.outstandings.packets.emplace(
      packetIt,
      std::move(packet),
      std::move(sentTime),
      encodedSize,
      isHandshake,
      conn.lossState.totalBytesSent);
  pkt.isAppLimited = conn.congestionController
      ? conn.congestionController->isAppLimited()
      : false;
  if (conn.lossState.lastAckedTime.has_value() &&
      conn.lossState.lastAckedPacketSentTime.has_value()) {
    pkt.lastAckedPacketInfo.emplace(
        *conn.lossState.lastAckedPacketSentTime,
        *conn.lossState.lastAckedTime,
        conn.lossState.totalBytesSentAtLastAck,
        conn.lossState.totalBytesAckedAtLastAck);
  }
  if (packetEvent) {
    DCHECK(conn.outstandings.packetEvents.count(*packetEvent));
    pkt.associatedEvent = std::move(packetEvent);
    conn.lossState.totalBytesCloned += encodedSize;
  }

  if (conn.congestionController) {
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
  if (conn.pacer) {
    conn.pacer->onPacketSent();
  }
  if (conn.pathValidationLimiter &&
      (conn.pendingEvents.pathChallenge || conn.outstandingPathValidation)) {
    conn.pathValidationLimiter->onPacketSent(pkt.encodedSize);
  }
  if (pkt.isHandshake) {
    if (!pkt.associatedEvent) {
      if (packetNumberSpace == PacketNumberSpace::Initial) {
        ++conn.outstandings.initialPacketsCount;
      } else {
        CHECK_EQ(packetNumberSpace, PacketNumberSpace::Handshake);
        ++conn.outstandings.handshakePacketsCount;
      }
    }
    conn.lossState.lastHandshakePacketSentTime = pkt.time;
  }
  conn.lossState.lastRetransmittablePacketSentTime = pkt.time;
  if (pkt.associatedEvent) {
    ++conn.outstandings.clonedPacketsCount;
    ++conn.lossState.timeoutBasedRtxCount;
  }

  auto opCount = conn.outstandings.numOutstanding();
  DCHECK_GE(opCount, conn.outstandings.initialPacketsCount);
  DCHECK_GE(opCount, conn.outstandings.handshakePacketsCount);
  DCHECK_GE(opCount, conn.outstandings.clonedPacketsCount);
}

uint64_t congestionControlWritableBytes(const QuicConnectionStateBase& conn) {
  uint64_t writableBytes = std::numeric_limits<uint64_t>::max();

  if (conn.pendingEvents.pathChallenge || conn.outstandingPathValidation) {
    CHECK(conn.pathValidationLimiter);
    // 0-RTT and path validation  rate limiting should be mutually exclusive.
    CHECK(!conn.writableBytesLimit);

    // Use the default RTT measurement when starting a new path challenge (CC is
    // reset). This shouldn't be an RTT sample, so we do not update the CC with
    // this value.
    writableBytes = conn.pathValidationLimiter->currentCredit(
        std::chrono::steady_clock::now(),
        conn.lossState.srtt == 0us ? kDefaultInitialRtt : conn.lossState.srtt);
  } else if (conn.writableBytesLimit) {
    if (*conn.writableBytesLimit <= conn.lossState.totalBytesSent) {
      return 0;
    }
    writableBytes = *conn.writableBytesLimit - conn.lossState.totalBytesSent;
  }

  if (conn.congestionController) {
    writableBytes = std::min<uint64_t>(
        writableBytes, conn.congestionController->getWritableBytes());
  }

  if (writableBytes == std::numeric_limits<uint64_t>::max()) {
    return writableBytes;
  }

  // For real-CC/PathChallenge cases, round the result up to the nearest
  // multiple of udpSendPacketLen.
  return (writableBytes + conn.udpSendPacketLen - 1) / conn.udpSendPacketLen *
      conn.udpSendPacketLen;
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
             const std::string& token) {
    return LongHeader(
        packetType, srcConnId, dstConnId, packetNum, version, token);
  };
}

HeaderBuilder ShortHeaderBuilder() {
  return [](const ConnectionId& /* srcConnId */,
            const ConnectionId& dstConnId,
            PacketNum packetNum,
            QuicVersion,
            const std::string&) {
    return ShortHeader(ProtectionType::KeyPhaseZero, dstConnId, packetNum);
  };
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
    const std::string& token) {
  auto encryptionLevel = protectionTypeToEncryptionLevel(
      longHeaderTypeToProtectionType(packetType));
  FrameScheduler scheduler =
      std::move(FrameScheduler::Builder(
                    connection,
                    encryptionLevel,
                    LongHeader::typeToPacketNumberSpace(packetType),
                    "CryptoAndAcksScheduler")
                    .ackFrames()
                    .cryptoFrames())
          .build();
  auto builder = LongHeaderBuilder(packetType);
  uint64_t written = 0;
  auto& cryptoStream =
      *getCryptoStream(*connection.cryptoState, encryptionLevel);
  if ((connection.pendingEvents.numProbePackets &&
       cryptoStream.retransmissionBuffer.size()) ||
      scheduler.hasData()) {
    written = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        encryptionLevel,
        LongHeader::typeToPacketNumberSpace(packetType),
        scheduler,
        std::min<uint64_t>(
            packetLimit, connection.pendingEvents.numProbePackets),
        cleartextCipher,
        headerCipher,
        version,
        token);
    CHECK_GE(connection.pendingEvents.numProbePackets, written);
    connection.pendingEvents.numProbePackets -= written;
  }
  // Crypto data is written without aead protection.
  written += writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      std::move(builder),
      LongHeader::typeToPacketNumberSpace(packetType),
      scheduler,
      congestionControlWritableBytes,
      packetLimit - written,
      cleartextCipher,
      headerCipher,
      version,
      token);
  VLOG_IF(10, written > 0) << nodeToString(connection.nodeType)
                           << " written crypto and acks data type="
                           << packetType << " packets=" << written << " "
                           << connection;
  CHECK_GE(packetLimit, written);
  return written;
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
  return writeQuicDataToSocketImpl(
      sock,
      connection,
      srcConnId,
      dstConnId,
      aead,
      headerCipher,
      version,
      packetLimit,
      /*exceptCryptoStream=*/false);
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
  return writeQuicDataToSocketImpl(
      socket,
      connection,
      srcConnId,
      dstConnId,
      aead,
      headerCipher,
      version,
      packetLimit,
      /*exceptCryptoStream=*/true);
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
                    LongHeader::typeToPacketNumberSpace(type),
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
      std::move(builder),
      LongHeader::typeToPacketNumberSpace(type),
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
  PacketNumberSpace pnSpace = header.getPacketNumberSpace();
  HeaderForm headerForm = header.getHeaderForm();
  PacketNum packetNum = header.getPacketSequenceNum();
  // TODO: This too needs to be switchable between regular and inplace builder.
  RegularQuicPacketBuilder packetBuilder(
      connection.udpSendPacketLen,
      std::move(header),
      getAckState(connection, pnSpace).largestAckedByPeer.value_or(0));
  packetBuilder.encodePacketHeader();
  packetBuilder.accountForCipherOverhead(aead.getCipherOverhead());
  size_t written = 0;
  if (!closeDetails) {
    written = writeFrame(
        ConnectionCloseFrame(
            QuicErrorCode(TransportErrorCode::NO_ERROR),
            std::string("No error")),
        packetBuilder);
  } else {
    switch (closeDetails->first.type()) {
      case QuicErrorCode::Type::ApplicationErrorCode_E:
        written = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(*closeDetails->first.asApplicationErrorCode()),
                closeDetails->second,
                quic::FrameType::CONNECTION_CLOSE_APP_ERR),
            packetBuilder);
        break;
      case QuicErrorCode::Type::TransportErrorCode_E:
        written = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(*closeDetails->first.asTransportErrorCode()),
                closeDetails->second,
                quic::FrameType::CONNECTION_CLOSE),
            packetBuilder);
        break;
      case QuicErrorCode::Type::LocalErrorCode_E:
        written = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
                std::string("Internal error"),
                quic::FrameType::CONNECTION_CLOSE),
            packetBuilder);
        break;
    }
  }
  if (written == 0) {
    LOG(ERROR) << "Close frame too large " << connection;
    return;
  }
  auto packet = std::move(packetBuilder).buildPacket();
  packet.header->coalesce();
  auto body = aead.inplaceEncrypt(
      std::move(packet.body), packet.header.get(), packetNum);
  body->coalesce();
  encryptPacketHeader(
      headerForm,
      packet.header->writableData(),
      packet.header->length(),
      body->data(),
      body->length(),
      headerCipher);
  auto packetBuf = std::move(packet.header);
  packetBuf->prependChain(std::move(body));
  auto packetSize = packetBuf->computeChainDataLength();
  if (connection.qLogger) {
    connection.qLogger->addPacket(packet.packet, packetSize);
  }
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
    QUIC_STATS(connection.statsCallback, onWrite, ret);
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
          connection, LongHeader::typeToPacketNumberSpace(headerType)),
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
    uint8_t* header,
    size_t headerLen,
    const uint8_t* encryptedBody,
    size_t bodyLen,
    const PacketNumberCipher& headerCipher) {
  // Header encryption.
  auto packetNumberLength = parsePacketNumberLength(*header);
  Sample sample;
  size_t sampleBytesToUse = kMaxPacketNumEncodingSize - packetNumberLength;
  // If there were less than 4 bytes in the packet number, some of the payload
  // bytes will also be skipped during sampling.
  CHECK_GE(bodyLen, sampleBytesToUse + sample.size());
  encryptedBody += sampleBytesToUse;
  memcpy(sample.data(), encryptedBody, sample.size());

  folly::MutableByteRange initialByteRange(header, 1);
  folly::MutableByteRange packetNumByteRange(
      header + headerLen - packetNumberLength, packetNumberLength);
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
    HeaderBuilder builder,
    PacketNumberSpace pnSpace,
    QuicPacketScheduler& scheduler,
    const WritableBytesFunc& writableBytesFunc,
    uint64_t packetLimit,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    const std::string& token) {
  VLOG(10) << nodeToString(connection.nodeType)
           << " writing data using scheduler=" << scheduler.name() << " "
           << connection;

  auto batchWriter = BatchWriterFactory::makeBatchWriter(
      sock,
      connection.transportSettings.batchingMode,
      connection.transportSettings.maxBatchSize,
      connection.transportSettings.useThreadLocalBatching,
      connection.transportSettings.threadLocalDelay,
      connection.transportSettings.dataPathType,
      connection);

  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter),
      connection.transportSettings.useThreadLocalBatching,
      sock,
      connection.peerAddress,
      connection,
      connection.happyEyeballsState);

  if (connection.loopDetectorCallback) {
    connection.writeDebugState.schedulerName = scheduler.name();
    connection.writeDebugState.noWriteReason = NoWriteReason::WRITE_OK;
    if (!scheduler.hasData()) {
      connection.writeDebugState.noWriteReason = NoWriteReason::EMPTY_SCHEDULER;
    }
  }
  auto writeLoopBeginTime = Clock::now();
  // helper functor to check if we have been write in a loop for longer than the
  // RTT fraction that we are allowed to write. Only kicks in if we have write
  // one batch in batching write mode.
  auto timeLimitHelper = [&]() -> bool {
    auto batchSize = connection.transportSettings.batchingMode ==
            quic::QuicBatchingMode::BATCHING_MODE_NONE
        ? connection.transportSettings.writeConnectionDataPacketsLimit
        : connection.transportSettings.maxBatchSize;
    return ioBufBatch.getPktSent() < batchSize ||
        connection.lossState.srtt == 0us ||
        Clock::now() - writeLoopBeginTime < connection.lossState.srtt /
            connection.transportSettings.writeLimitRttFraction;
  };
  while (scheduler.hasData() && ioBufBatch.getPktSent() < packetLimit &&
         timeLimitHelper()) {
    auto packetNum = getNextPacketNum(connection, pnSpace);
    auto header = builder(srcConnId, dstConnId, packetNum, version, token);
    uint32_t writableBytes = folly::to<uint32_t>(std::min<uint64_t>(
        connection.udpSendPacketLen, writableBytesFunc(connection)));
    uint64_t cipherOverhead = aead.getCipherOverhead();
    if (writableBytes < cipherOverhead) {
      writableBytes = 0;
    } else {
      writableBytes -= cipherOverhead;
    }

    // TODO: Select a different DataPathFunc based on TransportSettings
    const auto& dataPlainFunc =
        connection.transportSettings.dataPathType == DataPathType::ChainedMemory
        ? iobufChainBasedBuildScheduleEncrypt
        : continuousMemoryBuildScheduleEncrypt;
    auto ret = dataPlainFunc(
        connection,
        std::move(header),
        pnSpace,
        packetNum,
        cipherOverhead,
        scheduler,
        writableBytes,
        ioBufBatch,
        aead,
        headerCipher);

    if (!ret.buildSuccess) {
      return ioBufBatch.getPktSent();
    }

    // If we build a packet, we updateConnection(), even if write might have
    // been failed. Because if it builds, a lot of states need to be updated no
    // matter the write result. We are basically treating this case as if we
    // pretend write was also successful but packet is lost somewhere in the
    // network.
    auto& result = ret.result;
    updateConnection(
        connection,
        std::move(result->packetEvent),
        std::move(result->packet->packet),
        Clock::now(),
        folly::to<uint32_t>(ret.encodedSize));

    // if ioBufBatch.write returns false
    // it is because a flush() call failed
    if (!ret.writeSuccess) {
      if (connection.loopDetectorCallback) {
        connection.writeDebugState.noWriteReason =
            NoWriteReason::SOCKET_FAILURE;
      }
      return ioBufBatch.getPktSent();
    }
  }

  ioBufBatch.flush();
  if (connection.transportSettings.dataPathType ==
      DataPathType::ContinuousMemory) {
    CHECK(connection.bufAccessor->ownsBuffer());
    auto buf = connection.bufAccessor->obtain();
    CHECK(buf->length() == 0 && buf->headroom() == 0);
    connection.bufAccessor->release(std::move(buf));
  }
  return ioBufBatch.getPktSent();
}

uint64_t writeProbingDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const HeaderBuilder& builder,
    EncryptionLevel encryptionLevel,
    PacketNumberSpace pnSpace,
    FrameScheduler scheduler,
    uint8_t probesToSend,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    const std::string& token) {
  // Skip a packet number for probing packets to elicit acks
  increaseNextPacketNum(connection, pnSpace);
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
      version,
      token);
  if (probesToSend && !written) {
    // Fall back to send a ping:
    connection.pendingEvents.sendPing = true;
    auto pingScheduler =
        std::move(FrameScheduler::Builder(
                      connection, encryptionLevel, pnSpace, "PingScheduler")
                      .pingFrames())
            .build();
    written += writeConnectionDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        pnSpace,
        pingScheduler,
        unlimitedWritableBytes,
        probesToSend - written,
        aead,
        headerCipher,
        version);
  }
  VLOG_IF(10, written > 0)
      << nodeToString(connection.nodeType)
      << " writing probes using scheduler=CloningScheduler " << connection;
  return written;
}

WriteDataReason shouldWriteData(const QuicConnectionStateBase& conn) {
  if (conn.pendingEvents.numProbePackets) {
    VLOG(10) << nodeToString(conn.nodeType) << " needs write because of PTO"
             << conn;
    return WriteDataReason::PROBES;
  }
  if (hasAckDataToWrite(conn)) {
    VLOG(10) << nodeToString(conn.nodeType) << " needs write because of ACKs "
             << conn;
    return WriteDataReason::ACK;
  }

  if (!congestionControlWritableBytes(conn)) {
    QUIC_STATS(conn.statsCallback, onCwndBlocked);
    return WriteDataReason::NO_WRITE;
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

WriteDataReason hasNonAckDataToWrite(const QuicConnectionStateBase& conn) {
  if (cryptoHasWritableData(conn)) {
    VLOG(10) << nodeToString(conn.nodeType)
             << " needs write because of crypto stream"
             << " " << conn;
    return WriteDataReason::CRYPTO_STREAM;
  }
  if (!conn.oneRttWriteCipher && !conn.zeroRttWriteCipher) {
    // All the rest of the types of data need either a 1-rtt or 0-rtt cipher to
    // be written.
    return WriteDataReason::NO_WRITE;
  }
  if (!conn.pendingEvents.resets.empty()) {
    return WriteDataReason::RESET;
  }
  if (conn.streamManager->hasWindowUpdates()) {
    return WriteDataReason::STREAM_WINDOW_UPDATE;
  }
  if (conn.pendingEvents.connWindowUpdate) {
    return WriteDataReason::CONN_WINDOW_UPDATE;
  }
  if (conn.streamManager->hasBlocked()) {
    return WriteDataReason::BLOCKED;
  }
  if (conn.streamManager->hasLoss()) {
    return WriteDataReason::LOSS;
  }
  if (getSendConnFlowControlBytesWire(conn) != 0 &&
      conn.streamManager->hasWritable()) {
    return WriteDataReason::STREAM;
  }
  if (!conn.pendingEvents.frames.empty()) {
    return WriteDataReason::SIMPLE;
  }
  if ((conn.pendingEvents.pathChallenge != folly::none)) {
    return WriteDataReason::PATHCHALLENGE;
  }
  if (conn.pendingEvents.sendPing) {
    return WriteDataReason::PING;
  }
  return WriteDataReason::NO_WRITE;
}

void maybeSendStreamLimitUpdates(QuicConnectionStateBase& conn) {
  auto update = conn.streamManager->remoteBidirectionalStreamLimitUpdate();
  if (update) {
    sendSimpleFrame(conn, (MaxStreamsFrame(*update, true)));
  }
  update = conn.streamManager->remoteUnidirectionalStreamLimitUpdate();
  if (update) {
    sendSimpleFrame(conn, (MaxStreamsFrame(*update, false)));
  }
}

void implicitAckCryptoStream(
    QuicConnectionStateBase& conn,
    EncryptionLevel encryptionLevel) {
  auto implicitAckTime = Clock::now();
  auto packetNumSpace = encryptionLevel == EncryptionLevel::Handshake
      ? PacketNumberSpace::Handshake
      : PacketNumberSpace::Initial;
  auto& ackState = getAckState(conn, packetNumSpace);
  AckBlocks ackBlocks;
  ReadAckFrame implicitAck;
  implicitAck.ackDelay = 0ms;
  for (const auto& op : conn.outstandings.packets) {
    if (op.packet.header.getPacketNumberSpace() == packetNumSpace) {
      ackBlocks.insert(op.packet.header.getPacketSequenceNum());
    }
  }
  if (ackBlocks.empty()) {
    return;
  }
  // Construct an implicit ack covering the entire range of packets.
  // If some of these have already been ACK'd then processAckFrame
  // should simply ignore them.
  implicitAck.largestAcked = ackBlocks.back().end;
  implicitAck.ackBlocks.emplace_back(
      ackBlocks.front().start, implicitAck.largestAcked);
  processAckFrame(
      conn,
      packetNumSpace,
      implicitAck,
      [&](auto&, auto& packetFrame, auto&) {
        switch (packetFrame.type()) {
          case QuicWriteFrame::Type::WriteCryptoFrame_E: {
            const WriteCryptoFrame& frame = *packetFrame.asWriteCryptoFrame();
            auto cryptoStream =
                getCryptoStream(*conn.cryptoState, encryptionLevel);
            processCryptoStreamAck(*cryptoStream, frame.offset, frame.len);
            break;
          }
          case QuicWriteFrame::Type::WriteAckFrame_E: {
            const WriteAckFrame& frame = *packetFrame.asWriteAckFrame();
            commonAckVisitorForAckFrame(ackState, frame);
            break;
          }
          default: {
            // We don't bother checking for valid packets, since these are
            // our outstanding packets.
          }
        }
      },
      // We shouldn't mark anything as lost from the implicit ACK, as it should
      // be ACKing the entire rangee.
      [](auto&, auto&, auto, auto) {
        LOG(FATAL) << "Got loss from implicit crypto ACK.";
      },
      implicitAckTime);
  // Clear our the loss buffer explicity. The implicit ACK itself will not
  // remove data already in the loss buffer.
  auto cryptoStream = getCryptoStream(*conn.cryptoState, encryptionLevel);
  cryptoStream->lossBuffer.clear();
  CHECK(cryptoStream->retransmissionBuffer.empty());
  // The write buffer should be empty, there's no optional crypto data.
  CHECK(cryptoStream->writeBuffer.empty());
}

void handshakeConfirmed(QuicConnectionStateBase& conn) {
  // If we've supposedly confirmed the handshake and don't have the 1RTT
  // ciphers installed, we are going to have problems.
  CHECK(conn.oneRttWriteCipher);
  CHECK(conn.oneRttWriteHeaderCipher);
  CHECK(conn.readCodec->getOneRttReadCipher());
  CHECK(conn.readCodec->getOneRttHeaderCipher());
  conn.readCodec->onHandshakeDone(Clock::now());
  conn.initialWriteCipher.reset();
  conn.initialHeaderCipher.reset();
  conn.readCodec->setInitialReadCipher(nullptr);
  conn.readCodec->setInitialHeaderCipher(nullptr);
  implicitAckCryptoStream(conn, EncryptionLevel::Initial);
  conn.handshakeWriteCipher.reset();
  conn.handshakeWriteHeaderCipher.reset();
  conn.readCodec->setHandshakeReadCipher(nullptr);
  conn.readCodec->setHandshakeHeaderCipher(nullptr);
  implicitAckCryptoStream(conn, EncryptionLevel::Handshake);
}

} // namespace quic
