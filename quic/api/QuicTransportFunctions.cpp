/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>

#include <quic/state/AckHandlers.h>
#include <quic/state/QuicAckFrequencyFunctions.h>
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
      optionalToString(
          conn.ackStates.initialAckState
              ? conn.ackStates.initialAckState->largestAckScheduled
              : folly::none),
      ",",
      optionalToString(
          conn.ackStates.handshakeAckState
              ? conn.ackStates.handshakeAckState->largestAckScheduled
              : folly::none),
      ",",
      optionalToString(conn.ackStates.appDataAckState.largestAckScheduled),
      "]");
}

std::string largestAckToSendToString(
    const quic::QuicConnectionStateBase& conn) noexcept {
  return folly::to<std::string>(
      "[",
      optionalToString(
          conn.ackStates.initialAckState
              ? largestAckToSend(*conn.ackStates.initialAckState)
              : folly::none),
      ",",
      optionalToString(
          conn.ackStates.handshakeAckState
              ? largestAckToSend(*conn.ackStates.handshakeAckState)
              : folly::none),
      ",",
      optionalToString(largestAckToSend(conn.ackStates.appDataAckState)),
      "]");
}

using namespace quic;

/**
 * This function returns the number of write bytes that are available until we
 * reach the writableBytesLimit. It may or may not be the limiting factor on the
 * number of bytes we can write on the wire.
 *
 * If the client's address has not been verified, this will return the number of
 * write bytes available until writableBytesLimit is reached.
 *
 * Otherwise if the client's address is validated, it will return unlimited
 * number of bytes to write.
 */
uint64_t maybeUnvalidatedClientWritableBytes(
    quic::QuicConnectionStateBase& conn) {
  if (!conn.writableBytesLimit) {
    return unlimitedWritableBytes(conn);
  }

  if (*conn.writableBytesLimit <= conn.lossState.totalBytesSent) {
    QUIC_STATS(conn.statsCallback, onConnectionWritableBytesLimited);
    return 0;
  }

  uint64_t writableBytes =
      *conn.writableBytesLimit - conn.lossState.totalBytesSent;

  // round the result up to the nearest multiple of udpSendPacketLen.
  return (writableBytes + conn.udpSendPacketLen - 1) / conn.udpSendPacketLen *
      conn.udpSendPacketLen;
}

WriteQuicDataResult writeQuicDataToSocketImpl(
    QuicAsyncUDPSocketWrapper& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    bool exceptCryptoStream,
    TimePoint writeLoopBeginTime) {
  auto builder = ShortHeaderBuilder();
  WriteQuicDataResult result;
  auto& packetsWritten = result.packetsWritten;
  auto& probesWritten = result.probesWritten;
  auto& bytesWritten = result.bytesWritten;
  auto& numProbePackets =
      connection.pendingEvents.numProbePackets[PacketNumberSpace::AppData];
  if (numProbePackets) {
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
            .pingFrames()
            .immediateAckFrames();
    if (!exceptCryptoStream) {
      probeSchedulerBuilder.cryptoFrames();
    }
    auto probeScheduler = std::move(probeSchedulerBuilder).build();
    auto probeResult = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        EncryptionLevel::AppData,
        PacketNumberSpace::AppData,
        probeScheduler,
        numProbePackets, // This possibly bypasses the packetLimit.
        aead,
        headerCipher,
        version);
    probesWritten = probeResult.probesWritten;
    bytesWritten += probeResult.bytesWritten;
    // We only get one chance to write out the probes.
    numProbePackets = 0;
    packetLimit =
        probesWritten > packetLimit ? 0 : (packetLimit - probesWritten);
  }
  auto schedulerBuilder =
      FrameScheduler::Builder(
          connection,
          EncryptionLevel::AppData,
          PacketNumberSpace::AppData,
          exceptCryptoStream ? "FrameSchedulerWithoutCrypto" : "FrameScheduler")
          .streamFrames()
          .resetFrames()
          .windowUpdateFrames()
          .blockedFrames()
          .simpleFrames()
          .pingFrames()
          .datagramFrames()
          .immediateAckFrames();
  // Only add ACK frames if we need to send an ACK, or if the write reason isn't
  // just streams.
  if (connection.transportSettings.opportunisticAcking ||
      toWriteAppDataAcks(connection) ||
      (hasNonAckDataToWrite(connection) != WriteDataReason::STREAM)) {
    schedulerBuilder.ackFrames();
  }
  if (!exceptCryptoStream) {
    schedulerBuilder.cryptoFrames();
  }
  FrameScheduler scheduler = std::move(schedulerBuilder).build();
  auto connectionDataResult = writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      std::move(builder),
      PacketNumberSpace::AppData,
      scheduler,
      congestionControlWritableBytes,
      packetLimit,
      aead,
      headerCipher,
      version,
      writeLoopBeginTime);
  packetsWritten += connectionDataResult.packetsWritten;
  bytesWritten += connectionDataResult.bytesWritten;
  VLOG_IF(10, packetsWritten || probesWritten)
      << nodeToString(connection.nodeType) << " written data "
      << (exceptCryptoStream ? "without crypto data " : "")
      << "to socket packets=" << packetsWritten << " probes=" << probesWritten
      << " " << connection;
  return result;
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
  auto encodedBodySize = encodedSize - headerLen;
  // Include previous packets back.
  packetBuf->prepend(prevSize);
  connection.bufAccessor->release(std::move(packetBuf));
  if (encodedSize > connection.udpSendPacketLen) {
    VLOG(3) << "Quic sending pkt larger than limit, encodedSize="
            << encodedSize;
  }
  // TODO: I think we should add an API that doesn't need a buffer.
  bool ret = ioBufBatch.write(nullptr /* no need to pass buf */, encodedSize);
  // update stats and connection
  if (ret) {
    QUIC_STATS(connection.statsCallback, onWrite, encodedSize);
    QUIC_STATS(connection.statsCallback, onPacketSent);
  }
  return DataPathResult::makeWriteResult(
      ret, std::move(result), encodedSize, encodedBodySize);
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
  auto unencrypted = folly::IOBuf::createCombined(
      headerLen + bodyLen + aead.getCipherOverhead());
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
  auto encodedBodySize = encodedSize - headerLen;
  if (encodedSize > connection.udpSendPacketLen) {
    VLOG(3) << "Quic sending pkt larger than limit, encodedSize=" << encodedSize
            << " encodedBodySize=" << encodedBodySize;
  }
  bool ret = ioBufBatch.write(std::move(packetBuf), encodedSize);
  if (ret) {
    // update stats and connection
    QUIC_STATS(connection.statsCallback, onWrite, encodedSize);
    QUIC_STATS(connection.statsCallback, onPacketSent);
  }
  return DataPathResult::makeWriteResult(
      ret, std::move(result), encodedSize, encodedBodySize);
}

} // namespace

namespace quic {

void handleNewStreamBufMetaWritten(
    QuicStreamState& stream,
    uint64_t frameLen,
    bool frameFin);

void handleRetransmissionBufMetaWritten(
    QuicStreamState& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    const decltype(stream.lossBufMetas)::iterator lossBufMetaIter);

bool writeLoopTimeLimit(
    TimePoint loopBeginTime,
    const QuicConnectionStateBase& connection) {
  return connection.lossState.srtt == 0us ||
      connection.transportSettings.writeLimitRttFraction == 0 ||
      Clock::now() - loopBeginTime < connection.lossState.srtt /
          connection.transportSettings.writeLimitRttFraction;
}

void handleNewStreamDataWritten(
    QuicStreamLike& stream,
    uint64_t frameLen,
    bool frameFin) {
  auto originalOffset = stream.currentWriteOffset;
  // Idealy we should also check this data doesn't exist in either retx buffer
  // or loss buffer, but that's an expensive search.
  stream.currentWriteOffset += frameLen;
  auto bufWritten = stream.writeBuffer.splitAtMost(folly::to<size_t>(frameLen));
  DCHECK_EQ(bufWritten->computeChainDataLength(), frameLen);
  // TODO: If we want to be able to write FIN out of order for DSR-ed streams,
  // this needs to be fixed:
  stream.currentWriteOffset += frameFin ? 1 : 0;
  CHECK(stream.retransmissionBuffer
            .emplace(
                std::piecewise_construct,
                std::forward_as_tuple(originalOffset),
                std::forward_as_tuple(std::make_unique<StreamBuffer>(
                    std::move(bufWritten), originalOffset, frameFin)))
            .second);
}

void handleNewStreamBufMetaWritten(
    QuicStreamState& stream,
    uint64_t frameLen,
    bool frameFin) {
  CHECK_GT(stream.writeBufMeta.offset, 0);
  auto originalOffset = stream.writeBufMeta.offset;
  auto bufMetaSplit = stream.writeBufMeta.split(frameLen);
  CHECK_EQ(bufMetaSplit.offset, originalOffset);
  if (frameFin) {
    // If FIN is written, nothing should be left in the writeBufMeta.
    CHECK_EQ(0, stream.writeBufMeta.length);
    ++stream.writeBufMeta.offset;
    CHECK_GT(stream.writeBufMeta.offset, *stream.finalWriteOffset);
  }
  CHECK(stream.retransmissionBufMetas
            .emplace(
                std::piecewise_construct,
                std::forward_as_tuple(originalOffset),
                std::forward_as_tuple(bufMetaSplit))
            .second);
}

void handleRetransmissionWritten(
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    std::deque<StreamBuffer>::iterator lossBufferIter) {
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

void handleRetransmissionBufMetaWritten(
    QuicStreamState& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    const decltype(stream.lossBufMetas)::iterator lossBufMetaIter) {
  if (frameLen == lossBufMetaIter->length && frameFin == lossBufMetaIter->eof) {
    stream.lossBufMetas.erase(lossBufMetaIter);
  } else {
    CHECK_GT(lossBufMetaIter->length, frameLen);
    lossBufMetaIter->length -= frameLen;
    lossBufMetaIter->offset += frameLen;
  }
  CHECK(stream.retransmissionBufMetas
            .emplace(
                std::piecewise_construct,
                std::forward_as_tuple(frameOffset),
                std::forward_as_tuple(WriteBufferMeta::Builder()
                                          .setOffset(frameOffset)
                                          .setLength(frameLen)
                                          .setEOF(frameFin)
                                          .build()))
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
  auto writtenNewData = false;
  // Handle new data first
  if (frameOffset == stream.currentWriteOffset) {
    handleNewStreamDataWritten(stream, frameLen, frameFin);
    writtenNewData = true;
  } else if (frameOffset > stream.currentWriteOffset) {
    throw QuicTransportException(
        fmt::format(
            "Byte offset of first byte in written stream frame ({}) is "
            "greater than stream's current write offset ({})",
            frameOffset,
            stream.currentWriteOffset),
        TransportErrorCode::INTERNAL_ERROR);
  }

  if (writtenNewData) {
    // Count packet. It's based on the assumption that schedluing scheme will
    // only writes one STREAM frame for a stream in a packet. If that doesn't
    // hold, we need to avoid double-counting.
    ++stream.numPacketsTxWithNewData;
    VLOG(10) << nodeToString(conn.nodeType) << " sent"
             << " packetNum=" << packetNum << " space=" << packetNumberSpace
             << " " << conn;
    return true;
  }

  bool writtenRetx = false;
  // If the data is in the loss buffer, it is a retransmission.
  auto lossBufferIter = std::lower_bound(
      stream.lossBuffer.begin(),
      stream.lossBuffer.end(),
      frameOffset,
      [](const auto& buf, auto off) { return buf.offset < off; });
  if (lossBufferIter != stream.lossBuffer.end() &&
      lossBufferIter->offset == frameOffset) {
    handleRetransmissionWritten(
        stream, frameOffset, frameLen, frameFin, lossBufferIter);
    writtenRetx = true;
  }

  if (writtenRetx) {
    conn.lossState.totalBytesRetransmitted += frameLen;
    VLOG(10) << nodeToString(conn.nodeType) << " sent retransmission"
             << " packetNum=" << packetNum << " " << conn;
    QUIC_STATS(conn.statsCallback, onPacketRetransmission);
    return false;
  }

  // Otherwise it must be a clone write.
  conn.lossState.totalStreamBytesCloned += frameLen;
  return false;
}

bool handleStreamBufMetaWritten(
    QuicConnectionStateBase& conn,
    QuicStreamState& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace) {
  auto writtenNewData = false;
  // Handle new data first
  if (stream.writeBufMeta.offset > 0 &&
      frameOffset == stream.writeBufMeta.offset) {
    handleNewStreamBufMetaWritten(stream, frameLen, frameFin);
    writtenNewData = true;
  }

  if (writtenNewData) {
    // Count packet. It's based on the assumption that schedluing scheme will
    // only writes one STREAM frame for a stream in a packet. If that doesn't
    // hold, we need to avoid double-counting.
    ++stream.numPacketsTxWithNewData;
    VLOG(10) << nodeToString(conn.nodeType) << " sent"
             << " packetNum=" << packetNum << " space=" << packetNumberSpace
             << " " << conn;
    return true;
  }

  auto lossBufMetaIter = std::lower_bound(
      stream.lossBufMetas.begin(),
      stream.lossBufMetas.end(),
      frameOffset,
      [](const auto& bufMeta, auto offset) { return bufMeta.offset < offset; });
  // We do not clone BufMeta right now. So the data has to be in lossBufMetas.
  CHECK(lossBufMetaIter != stream.lossBufMetas.end());
  CHECK_EQ(lossBufMetaIter->offset, frameOffset);
  handleRetransmissionBufMetaWritten(
      stream, frameOffset, frameLen, frameFin, lossBufMetaIter);
  conn.lossState.totalBytesRetransmitted += frameLen;
  VLOG(10) << nodeToString(conn.nodeType) << " sent retransmission"
           << " packetNum=" << packetNum << " " << conn;
  QUIC_STATS(conn.statsCallback, onPacketRetransmission);
  return false;
}

void updateConnection(
    QuicConnectionStateBase& conn,
    folly::Optional<PacketEvent> packetEvent,
    RegularQuicWritePacket packet,
    TimePoint sentTime,
    uint32_t encodedSize,
    uint32_t encodedBodySize,
    bool isDSRPacket) {
  auto packetNum = packet.header.getPacketSequenceNum();
  // AckFrame, PaddingFrame and Datagrams are not retx-able.
  bool retransmittable = false;
  bool isHandshake = false;
  bool isPing = false;
  uint32_t connWindowUpdateSent = 0;
  uint32_t ackFrameCounter = 0;
  uint32_t streamBytesSent = 0;
  uint32_t newStreamBytesSent = 0;
  OutstandingPacketWrapper::Metadata::DetailsPerStream detailsPerStream;
  auto packetNumberSpace = packet.header.getPacketNumberSpace();
  VLOG(10) << nodeToString(conn.nodeType) << " sent packetNum=" << packetNum
           << " in space=" << packetNumberSpace << " size=" << encodedSize
           << " bodySize: " << encodedBodySize << " isDSR=" << isDSRPacket
           << " " << conn;
  if (conn.qLogger) {
    conn.qLogger->addPacket(packet, encodedSize);
  }
  for (const auto& frame : packet.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::WriteStreamFrame: {
        const WriteStreamFrame& writeStreamFrame = *frame.asWriteStreamFrame();
        retransmittable = true;
        auto stream = CHECK_NOTNULL(
            conn.streamManager->getStream(writeStreamFrame.streamId));
        bool newStreamDataWritten = false;
        if (writeStreamFrame.fromBufMeta) {
          newStreamDataWritten = handleStreamBufMetaWritten(
              conn,
              *stream,
              writeStreamFrame.offset,
              writeStreamFrame.len,
              writeStreamFrame.fin,
              packetNum,
              packetNumberSpace);
        } else {
          newStreamDataWritten = handleStreamWritten(
              conn,
              *stream,
              writeStreamFrame.offset,
              writeStreamFrame.len,
              writeStreamFrame.fin,
              packetNum,
              packetNumberSpace);
        }
        if (newStreamDataWritten) {
          updateFlowControlOnWriteToSocket(*stream, writeStreamFrame.len);
          maybeWriteBlockAfterSocketWrite(*stream);
          maybeWriteDataBlockedAfterSocketWrite(conn);
          conn.streamManager->addTx(writeStreamFrame.streamId);
          newStreamBytesSent += writeStreamFrame.len;
        }
        conn.streamManager->updateWritableStreams(*stream);
        streamBytesSent += writeStreamFrame.len;
        detailsPerStream.addFrame(writeStreamFrame, newStreamDataWritten);
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
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
            false /* fin */,
            packetNum,
            packetNumberSpace);
        break;
      }
      case QuicWriteFrame::Type::WriteAckFrame: {
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
      case QuicWriteFrame::Type::RstStreamFrame: {
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
      case QuicWriteFrame::Type::MaxDataFrame: {
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
        onConnWindowUpdateSent(conn, maxDataFrame.maximumData, sentTime);
        break;
      }
      case QuicWriteFrame::Type::DataBlockedFrame: {
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent conn data blocked frame=" << packetNum << " "
                 << conn;
        retransmittable = true;
        conn.pendingEvents.sendDataBlocked = false;
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& maxStreamDataFrame =
            *frame.asMaxStreamDataFrame();
        auto stream = CHECK_NOTNULL(
            conn.streamManager->getStream(maxStreamDataFrame.streamId));
        retransmittable = true;
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent packet with window update packetNum=" << packetNum
                 << " stream=" << maxStreamDataFrame.streamId << " " << conn;
        onStreamWindowUpdateSent(
            *stream, maxStreamDataFrame.maximumData, sentTime);
        break;
      }
      case QuicWriteFrame::Type::StreamDataBlockedFrame: {
        const StreamDataBlockedFrame& streamBlockedFrame =
            *frame.asStreamDataBlockedFrame();
        VLOG(10) << nodeToString(conn.nodeType)
                 << " sent blocked stream frame packetNum=" << packetNum << " "
                 << conn;
        retransmittable = true;
        conn.streamManager->removeBlocked(streamBlockedFrame.streamId);
        break;
      }
      case QuicWriteFrame::Type::PingFrame:
        conn.pendingEvents.sendPing = false;
        isPing = true;
        break;
      case QuicWriteFrame::Type::QuicSimpleFrame: {
        const QuicSimpleFrame& simpleFrame = *frame.asQuicSimpleFrame();
        retransmittable = true;
        // We don't want this triggered for cloned frames.
        if (!packetEvent.has_value()) {
          updateSimpleFrameOnPacketSent(conn, simpleFrame);
        }
        break;
      }
      case QuicWriteFrame::Type::PaddingFrame: {
        // do not mark padding as retransmittable. There are several reasons
        // for this:
        // 1. We might need to pad ACK packets to make it so that we can
        //    sample them correctly for header encryption. ACK packets may not
        //    count towards congestion window, so the padding frames in those
        //    ack packets should not count towards the window either
        // 2. Of course we do not want to retransmit the ACK frames.
        break;
      }
      case QuicWriteFrame::Type::DatagramFrame: {
        // do not mark Datagram frames as retransmittable
        break;
      }
      case QuicWriteFrame::Type::ImmediateAckFrame: {
        // turn off the immediate ack pending event.
        conn.pendingEvents.requestImmediateAck = false;
        retransmittable = true;
        break;
      }
      default:
        retransmittable = true;
    }
  }

  // This increments the next packet number and (potentially) the next non-DSR
  // packet sequence number. Capture the non DSR sequence number before
  // increment.
  auto nonDsrPacketSequenceNumber =
      getAckState(conn, packetNumberSpace).nonDsrPacketSequenceNumber;
  increaseNextPacketNum(conn, packetNumberSpace, isDSRPacket);
  conn.lossState.largestSent =
      std::max(conn.lossState.largestSent.value_or(packetNum), packetNum);
  // updateConnection may be called multiple times during write. If before or
  // during any updateConnection, setLossDetectionAlarm is already set, we
  // shouldn't clear it:
  if (!conn.pendingEvents.setLossDetectionAlarm) {
    conn.pendingEvents.setLossDetectionAlarm = retransmittable;
  }
  conn.lossState.maybeLastPacketSentTime = sentTime;
  conn.lossState.totalBytesSent += encodedSize;
  conn.lossState.totalBodyBytesSent += encodedBodySize;
  conn.lossState.totalPacketsSent++;
  conn.lossState.totalStreamBytesSent += streamBytesSent;
  conn.lossState.totalNewStreamBytesSent += newStreamBytesSent;

  if (!retransmittable && !isPing) {
    DCHECK(!packetEvent);
    return;
  }
  conn.lossState.totalAckElicitingPacketsSent++;

  auto packetIt =
      std::find_if(
          conn.outstandings.packets.rbegin(),
          conn.outstandings.packets.rend(),
          [packetNum](const auto& packetWithTime) {
            return packetWithTime.packet.header.getPacketSequenceNum() <
                packetNum;
          })
          .base();

  std::function<void(const quic::OutstandingPacketWrapper&)> packetDestroyFn =
      [&conn](const quic::OutstandingPacketWrapper& pkt) {
        for (auto& packetProcessor : conn.packetProcessors) {
          packetProcessor->onPacketDestroyed(pkt);
        }
      };

  auto& pkt = *conn.outstandings.packets.emplace(
      packetIt,
      std::move(packet),
      sentTime,
      encodedSize,
      encodedBodySize,
      isHandshake,
      // these numbers should all _include_ the current packet
      // conn.lossState.inflightBytes isn't updated until below
      // conn.outstandings.numOutstanding() + 1 since we're emplacing here
      conn.lossState.totalBytesSent,
      conn.lossState.totalBodyBytesSent,
      conn.lossState.inflightBytes + encodedSize,
      conn.outstandings.numOutstanding() + 1,
      conn.lossState,
      conn.writeCount,
      std::move(detailsPerStream),
      conn.appLimitedTracker.getTotalAppLimitedTime(),
      packetDestroyFn);

  pkt.metadata.cmsgs = conn.socketCmsgsState.additionalCmsgs;

  pkt.isAppLimited = conn.congestionController
      ? conn.congestionController->isAppLimited()
      : false;
  if (conn.lossState.lastAckedTime.has_value() &&
      conn.lossState.lastAckedPacketSentTime.has_value()) {
    pkt.lastAckedPacketInfo.emplace(
        *conn.lossState.lastAckedPacketSentTime,
        *conn.lossState.lastAckedTime,
        *conn.lossState.adjustedLastAckedTime,
        conn.lossState.totalBytesSentAtLastAck,
        conn.lossState.totalBytesAckedAtLastAck);
  }
  if (packetEvent) {
    DCHECK(conn.outstandings.packetEvents.count(*packetEvent));
    pkt.associatedEvent = std::move(packetEvent);
    conn.lossState.totalBytesCloned += encodedSize;
  }
  pkt.isDSRPacket = isDSRPacket;
  if (isDSRPacket) {
    ++conn.outstandings.dsrCount;
    QUIC_STATS(conn.statsCallback, onDSRPacketSent, encodedSize);
  } else {
    // If it's not a DSR packet, set the sequence number to the previous one,
    // as the state currently is the _next_ one after this packet.
    pkt.nonDsrPacketSequenceNumber = nonDsrPacketSequenceNumber;
  }

  if (conn.congestionController) {
    conn.congestionController->onPacketSent(pkt);
  }
  if (conn.pacer) {
    conn.pacer->onPacketSent();
  }
  for (auto& packetProcessor : conn.packetProcessors) {
    packetProcessor->onPacketSent(pkt);
  }

  if (conn.pathValidationLimiter &&
      (conn.pendingEvents.pathChallenge || conn.outstandingPathValidation)) {
    conn.pathValidationLimiter->onPacketSent(pkt.metadata.encodedSize);
  }
  conn.lossState.lastRetransmittablePacketSentTime = pkt.metadata.time;
  if (pkt.associatedEvent) {
    ++conn.outstandings.clonedPacketCount[packetNumberSpace];
    ++conn.lossState.timeoutBasedRtxCount;
  } else {
    ++conn.outstandings.packetCount[packetNumberSpace];
  }
}

uint64_t probePacketWritableBytes(QuicConnectionStateBase& conn) {
  uint64_t probeWritableBytes = maybeUnvalidatedClientWritableBytes(conn);
  if (!probeWritableBytes) {
    conn.numProbesWritableBytesLimited++;
  }
  return probeWritableBytes;
}

uint64_t congestionControlWritableBytes(QuicConnectionStateBase& conn) {
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
    writableBytes = maybeUnvalidatedClientWritableBytes(conn);
  }

  if (conn.congestionController) {
    writableBytes = std::min<uint64_t>(
        writableBytes, conn.congestionController->getWritableBytes());

    if (conn.throttlingSignalProvider &&
        conn.throttlingSignalProvider->getCurrentThrottlingSignal()
            .has_value()) {
      const auto& throttlingSignal =
          conn.throttlingSignalProvider->getCurrentThrottlingSignal();
      if (throttlingSignal.value().maybeBytesToSend.has_value()) {
        // Cap the writable bytes by the amount of tokens available in the
        // throttler's bucket if one found to be throttling the connection.
        writableBytes = std::min(
            throttlingSignal.value().maybeBytesToSend.value(), writableBytes);
      }
    }
  }

  if (writableBytes == std::numeric_limits<uint64_t>::max()) {
    return writableBytes;
  }

  // For real-CC/PathChallenge cases, round the result up to the nearest
  // multiple of udpSendPacketLen.
  return (writableBytes + conn.udpSendPacketLen - 1) / conn.udpSendPacketLen *
      conn.udpSendPacketLen;
}

uint64_t unlimitedWritableBytes(QuicConnectionStateBase&) {
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

WriteQuicDataResult writeCryptoAndAckDataToSocket(
    QuicAsyncUDPSocketWrapper& sock,
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
  WriteQuicDataResult result;
  auto& packetsWritten = result.packetsWritten;
  auto& bytesWritten = result.bytesWritten;
  auto& probesWritten = result.probesWritten;
  auto& cryptoStream =
      *getCryptoStream(*connection.cryptoState, encryptionLevel);
  auto& numProbePackets =
      connection.pendingEvents
          .numProbePackets[LongHeader::typeToPacketNumberSpace(packetType)];
  if (numProbePackets &&
      (cryptoStream.retransmissionBuffer.size() || scheduler.hasData())) {
    auto probeResult = writeProbingDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        encryptionLevel,
        LongHeader::typeToPacketNumberSpace(packetType),
        scheduler,
        numProbePackets, // This possibly bypasses the packetLimit.
        cleartextCipher,
        headerCipher,
        version,
        token);
    probesWritten += probeResult.probesWritten;
    bytesWritten += probeResult.bytesWritten;
  }
  packetLimit = probesWritten > packetLimit ? 0 : (packetLimit - probesWritten);
  // Only get one chance to write probes.
  numProbePackets = 0;
  // Crypto data is written without aead protection.
  auto writeResult = writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      std::move(builder),
      LongHeader::typeToPacketNumberSpace(packetType),
      scheduler,
      congestionControlWritableBytes,
      packetLimit - packetsWritten,
      cleartextCipher,
      headerCipher,
      version,
      Clock::now(),
      token);

  packetsWritten += writeResult.packetsWritten;
  bytesWritten += writeResult.bytesWritten;

  VLOG_IF(10, packetsWritten || probesWritten)
      << nodeToString(connection.nodeType)
      << " written crypto and acks data type=" << packetType
      << " packetsWritten=" << packetsWritten
      << " probesWritten=" << probesWritten << connection;
  CHECK_GE(packetLimit, packetsWritten);
  return result;
}

WriteQuicDataResult writeQuicDataToSocket(
    QuicAsyncUDPSocketWrapper& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    TimePoint writeLoopBeginTime) {
  return writeQuicDataToSocketImpl(
      sock,
      connection,
      srcConnId,
      dstConnId,
      aead,
      headerCipher,
      version,
      packetLimit,
      /*exceptCryptoStream=*/false,
      writeLoopBeginTime);
}

WriteQuicDataResult writeQuicDataExceptCryptoStreamToSocket(
    QuicAsyncUDPSocketWrapper& socket,
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
      /*exceptCryptoStream=*/true,
      Clock::now());
}

uint64_t writeZeroRttDataToSocket(
    QuicAsyncUDPSocketWrapper& socket,
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
                     version,
                     Clock::now())
                     .packetsWritten;
  VLOG_IF(10, written > 0) << nodeToString(connection.nodeType)
                           << " written zero rtt data, packets=" << written
                           << " " << connection;
  DCHECK_GE(packetLimit, written);
  return written;
}

void writeCloseCommon(
    QuicAsyncUDPSocketWrapper& sock,
    QuicConnectionStateBase& connection,
    PacketHeader&& header,
    folly::Optional<QuicError> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher) {
  // close is special, we're going to bypass all the packet sent logic for all
  // packets we send with a connection close frame.
  PacketNumberSpace pnSpace = header.getPacketNumberSpace();
  HeaderForm headerForm = header.getHeaderForm();
  PacketNum packetNum = header.getPacketSequenceNum();
  // TODO: This too needs to be switchable between regular and inplace builder.
  RegularQuicPacketBuilder packetBuilder(
      kDefaultUDPSendPacketLen,
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
    switch (closeDetails->code.type()) {
      case QuicErrorCode::Type::ApplicationErrorCode:
        written = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(*closeDetails->code.asApplicationErrorCode()),
                closeDetails->message,
                quic::FrameType::CONNECTION_CLOSE_APP_ERR),
            packetBuilder);
        break;
      case QuicErrorCode::Type::TransportErrorCode:
        written = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(*closeDetails->code.asTransportErrorCode()),
                closeDetails->message,
                quic::FrameType::CONNECTION_CLOSE),
            packetBuilder);
        break;
      case QuicErrorCode::Type::LocalErrorCode:
        written = writeFrame(
            ConnectionCloseFrame(
                QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
                std::string("Internal error"),
                quic::FrameType::CONNECTION_CLOSE),
            packetBuilder);
        break;
    }
  }
  if (pnSpace == PacketNumberSpace::Initial &&
      connection.nodeType == QuicNodeType::Client) {
    while (packetBuilder.remainingSpaceInPkt() > 0) {
      writeFrame(PaddingFrame(), packetBuilder);
    }
  }
  if (written == 0) {
    LOG(ERROR) << "Close frame too large " << connection;
    return;
  }
  auto packet = std::move(packetBuilder).buildPacket();
  packet.header->coalesce();
  packet.body->reserve(0, aead.getCipherOverhead());
  CHECK_GE(packet.body->tailroom(), aead.getCipherOverhead());
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
  VLOG(10) << nodeToString(connection.nodeType)
           << " sent close packetNum=" << packetNum << " in space=" << pnSpace
           << " " << connection;
  // Increment the sequence number.
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
    QuicAsyncUDPSocketWrapper& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types headerType,
    folly::Optional<QuicError> closeDetails,
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
    QuicAsyncUDPSocketWrapper& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& connId,
    folly::Optional<QuicError> closeDetails,
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

/**
 * Writes packets to the socket. The is the function that is called by all
 * the other write*ToSocket() functions.
 *
 * The number of packets written is limited by:
 *   - the maximum batch size supported by the underlying writer
 *     (`maxBatchSize`)
 *   - the `packetLimit` input parameter
 *   - the value returned by the `writableBytesFunc` which usually is either the
 *     congestion control writable bytes or unlimited writable bytes (if the
 *     output of the given scheduler should not be subject to congestion
 *     control)
 *   - the maximum time to spend in a write loop as specified by
 *     `transportSettings.writeLimitRttFraction`
 *   - the amount of data available in the provided scheduler.
 *
 * Writing the packets involves:
 *   1. The scheduler which decides the data to write in each packet
 *   2. The IOBufQuicBatch which holds the data output by the scheduler
 *   3. The BatchWriter which writes the data from the IOBufQuicBatch to
 *      the socket
 *
 * The IOBufQuicBatch can hold packets either as a chain of IOBufs or as a
 * single contiguous buffer (continuous vs. chained memory datapaths). This also
 * affects the type of BatchWriter used to read the IOBufQuicBatch and write it
 * to the socket.
 *
 * A rough outline of this function is as follows:
 * 1. Make a BatchWriter for the requested batching mode and datapath type.
 * 2. Make an IOBufQuicBatch to hold the data. This owns the BatchWriter created
 *    above which it will use to write its data to the socket later.
 * 3. Based upon the selected datapathType, the dataplaneFunc is chosen.
 * 4. The dataplaneFunc is responsible for writing the scheduler's data into the
 *    IOBufQuicBatch in the desired format, and calling the IOBufQuicBatch's
 *    write() function which wraps around the BatchWriter it owns.
 * 5. Each dataplaneFunc call writes one packet to the IOBufQuicBatch. It is
 *    called repeatedly until one of the limits described above is hit.
 * 6. After each packet is written, the connection state is updated to reflect a
 *    packet being sent.
 * 7. Once the limit is hit, the IOBufQuicBatch is flushed to give it another
 *    chance to write any remaining data to the socket that hasn't already been
 *    written in the loop.
 *
 * Note that:
 * - This function does not guarantee that the data is written to the underlying
 *   UDP socket buffer.
 * - It only guarantees that packets will be scheduled and written to a
 *   IOBufQuicBatch and that the IOBufQuicBatch will get a chance to write to
 *   the socket.
 * - Step 6 above updates the connection state when the packet is written to the
 *   buffer, but not necessarily when it is written to the socket. This decision
 *   is made by the IOBufQuicBatch and its BatchWriter.
 * - This function attempts to flush the IOBufQuicBatch before returning
 *   to try to ensure that all scheduled data is written into the socket.
 * - If that flush still fails, the packets are considered written to the
 *   network, since currently there is no way to rewind scheduler and connection
 *   state after the packets have been written to a batch.
 */
WriteQuicDataResult writeConnectionDataToSocket(
    QuicAsyncUDPSocketWrapper& sock,
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
    TimePoint writeLoopBeginTime,
    const std::string& token) {
  if (connection.loopDetectorCallback) {
    connection.writeDebugState.schedulerName = scheduler.name().str();
    connection.writeDebugState.noWriteReason = NoWriteReason::WRITE_OK;
  }

  if (!scheduler.hasData()) {
    if (connection.loopDetectorCallback) {
      connection.writeDebugState.noWriteReason = NoWriteReason::EMPTY_SCHEDULER;
    }
    return {0, 0, 0};
  }

  VLOG(10) << nodeToString(connection.nodeType)
           << " writing data using scheduler=" << scheduler.name() << " "
           << connection;

  if (!connection.gsoSupported.hasValue()) {
    connection.gsoSupported = sock.getGSO() >= 0;
    if (!*connection.gsoSupported) {
      if (!useSinglePacketInplaceBatchWriter(
              connection.transportSettings.maxBatchSize,
              connection.transportSettings.dataPathType) &&
          (connection.transportSettings.dataPathType ==
           DataPathType::ContinuousMemory)) {
        // Change data path type to DataPathType::ChainedMemory.
        // Continuous memory data path is only supported with working GSO or
        // SinglePacketInplaceBatchWriter.
        LOG(ERROR) << "Switching data path to ChainedMemory as "
                   << "GSO is not supported on the socket";
        connection.transportSettings.dataPathType = DataPathType::ChainedMemory;
      }
    }
  }

  auto batchWriter = BatchWriterFactory::makeBatchWriter(
      connection.transportSettings.batchingMode,
      connection.transportSettings.maxBatchSize,
      connection.transportSettings.useThreadLocalBatching,
      connection.transportSettings.threadLocalDelay,
      connection.transportSettings.dataPathType,
      connection,
      *connection.gsoSupported);

  auto happyEyeballsState = connection.nodeType == QuicNodeType::Server
      ? nullptr
      : &static_cast<QuicClientConnectionState&>(connection).happyEyeballsState;
  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter),
      connection.transportSettings.useThreadLocalBatching,
      sock,
      connection.peerAddress,
      connection.statsCallback,
      happyEyeballsState);

  auto batchSize = connection.transportSettings.batchingMode ==
          QuicBatchingMode::BATCHING_MODE_NONE
      ? connection.transportSettings.writeConnectionDataPacketsLimit
      : connection.transportSettings.maxBatchSize;

  uint64_t bytesWritten = 0;

  while (scheduler.hasData() && ioBufBatch.getPktSent() < packetLimit &&
         ((ioBufBatch.getPktSent() < batchSize) ||
          writeLoopTimeLimit(writeLoopBeginTime, connection))) {
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

    const auto& dataPlaneFunc =
        connection.transportSettings.dataPathType == DataPathType::ChainedMemory
        ? iobufChainBasedBuildScheduleEncrypt
        : continuousMemoryBuildScheduleEncrypt;
    auto ret = dataPlaneFunc(
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
      // If we're returning because we couldn't schedule more packets,
      // make sure we flush the buffer in this function.
      ioBufBatch.flush();
      return {ioBufBatch.getPktSent(), 0, bytesWritten};
    }
    // If we build a packet, we updateConnection(), even if write might have
    // been failed. Because if it builds, a lot of states need to be updated no
    // matter the write result. We are basically treating this case as if we
    // pretend write was also successful but packet is lost somewhere in the
    // network.
    bytesWritten += ret.encodedSize;

    auto& result = ret.result;
    updateConnection(
        connection,
        std::move(result->packetEvent),
        std::move(result->packet->packet),
        Clock::now(),
        folly::to<uint32_t>(ret.encodedSize),
        folly::to<uint32_t>(ret.encodedBodySize),
        false /* isDSRPacket */);

    // if ioBufBatch.write returns false
    // it is because a flush() call failed
    if (!ret.writeSuccess) {
      if (connection.loopDetectorCallback) {
        connection.writeDebugState.noWriteReason =
            NoWriteReason::SOCKET_FAILURE;
      }
      return {ioBufBatch.getPktSent(), 0, bytesWritten};
    }

    if ((connection.transportSettings.batchingMode ==
         QuicBatchingMode::BATCHING_MODE_NONE) &&
        useSinglePacketInplaceBatchWriter(
            connection.transportSettings.maxBatchSize,
            connection.transportSettings.dataPathType)) {
      // With SinglePacketInplaceBatchWriter we always write one packet, and so
      // ioBufBatch needs a flush.
      ioBufBatch.flush();
    }
  }

  // Ensure that the buffer is flushed before returning
  ioBufBatch.flush();

  if (connection.transportSettings.dataPathType ==
      DataPathType::ContinuousMemory) {
    CHECK(connection.bufAccessor->ownsBuffer());
    auto buf = connection.bufAccessor->obtain();
    CHECK(buf->length() == 0 && buf->headroom() == 0);
    connection.bufAccessor->release(std::move(buf));
  }
  return {ioBufBatch.getPktSent(), 0, bytesWritten};
}

WriteQuicDataResult writeProbingDataToSocket(
    QuicAsyncUDPSocketWrapper& sock,
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
  auto writeLoopBeginTime = Clock::now();

  // If we have the ability to draw an ACK for AppData, let's send a probe that
  // is just an IMMEDIATE_ACK. Increase the number of probes to do so.
  uint8_t dataProbesToSend = probesToSend;
  if (probesToSend && canSendAckControlFrames(connection) &&
      encryptionLevel == EncryptionLevel::AppData) {
    probesToSend = std::max<uint8_t>(probesToSend, kPacketToSendForPTO);
    dataProbesToSend = probesToSend - 1;
  }
  auto cloningResult = writeConnectionDataToSocket(
      sock,
      connection,
      srcConnId,
      dstConnId,
      builder,
      pnSpace,
      cloningScheduler,
      connection.transportSettings.enableWritableBytesLimit
          ? probePacketWritableBytes
          : unlimitedWritableBytes,
      dataProbesToSend,
      aead,
      headerCipher,
      version,
      writeLoopBeginTime,
      token);
  auto probesWritten = cloningResult.packetsWritten;
  auto bytesWritten = cloningResult.bytesWritten;
  if (probesWritten < probesToSend) {
    // If we can use an IMMEDIATE_ACK, that's better than a PING.
    auto probeSchedulerBuilder = FrameScheduler::Builder(
        connection, encryptionLevel, pnSpace, "ProbeScheduler");
    // Might as well include some ACKs.
    probeSchedulerBuilder.ackFrames();
    if (canSendAckControlFrames(connection) &&
        encryptionLevel == EncryptionLevel::AppData) {
      requestPeerImmediateAck(connection);
      probeSchedulerBuilder.immediateAckFrames();
    } else {
      connection.pendingEvents.sendPing = true;
      probeSchedulerBuilder.pingFrames();
    }
    auto probeScheduler = std::move(probeSchedulerBuilder).build();
    auto probingResult = writeConnectionDataToSocket(
        sock,
        connection,
        srcConnId,
        dstConnId,
        builder,
        pnSpace,
        probeScheduler,
        connection.transportSettings.enableWritableBytesLimit
            ? probePacketWritableBytes
            : unlimitedWritableBytes,
        probesToSend - probesWritten,
        aead,
        headerCipher,
        version,
        writeLoopBeginTime);
    probesWritten += probingResult.packetsWritten;
    bytesWritten += probingResult.bytesWritten;
  }
  VLOG_IF(10, probesWritten > 0)
      << nodeToString(connection.nodeType)
      << " writing probes using scheduler=CloningScheduler " << connection;
  return {0, probesWritten, bytesWritten};
}

WriteDataReason shouldWriteData(/*const*/ QuicConnectionStateBase& conn) {
  auto& numProbePackets = conn.pendingEvents.numProbePackets;
  bool shouldWriteInitialProbes =
      numProbePackets[PacketNumberSpace::Initial] && conn.initialWriteCipher;
  bool shouldWriteHandshakeProbes =
      numProbePackets[PacketNumberSpace::Handshake] &&
      conn.handshakeWriteCipher;
  bool shouldWriteAppDataProbes =
      numProbePackets[PacketNumberSpace::AppData] && conn.oneRttWriteCipher;
  if (shouldWriteInitialProbes || shouldWriteHandshakeProbes ||
      shouldWriteAppDataProbes) {
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
  if (!conn.oneRttWriteCipher &&
      !(conn.nodeType == QuicNodeType::Client &&
        static_cast<const QuicClientConnectionState&>(conn)
            .zeroRttWriteCipher)) {
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
  // If we have lost data or flow control + stream data.
  if (conn.streamManager->hasLoss() ||
      (getSendConnFlowControlBytesWire(conn) != 0 &&
       conn.streamManager->hasWritable())) {
    return WriteDataReason::STREAM;
  }
  if (!conn.pendingEvents.frames.empty()) {
    return WriteDataReason::SIMPLE;
  }
  if ((conn.pendingEvents.pathChallenge.has_value())) {
    return WriteDataReason::PATHCHALLENGE;
  }
  if (conn.pendingEvents.sendPing) {
    return WriteDataReason::PING;
  }
  if (!conn.datagramState.writeBuffer.empty()) {
    return WriteDataReason::DATAGRAM;
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
  implicitAck.implicit = true;
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
          case QuicWriteFrame::Type::WriteCryptoFrame: {
            const WriteCryptoFrame& frame = *packetFrame.asWriteCryptoFrame();
            auto cryptoStream =
                getCryptoStream(*conn.cryptoState, encryptionLevel);
            processCryptoStreamAck(*cryptoStream, frame.offset, frame.len);
            break;
          }
          case QuicWriteFrame::Type::WriteAckFrame: {
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
      [](auto&, auto&, auto) {
        LOG(FATAL) << "Got loss from implicit crypto ACK.";
      },
      implicitAckTime);
  // Clear our the loss buffer explicitly. The implicit ACK itself will not
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
  conn.ackStates.initialAckState.reset();
  conn.handshakeWriteCipher.reset();
  conn.handshakeWriteHeaderCipher.reset();
  conn.readCodec->setHandshakeReadCipher(nullptr);
  conn.readCodec->setHandshakeHeaderCipher(nullptr);
  implicitAckCryptoStream(conn, EncryptionLevel::Handshake);
  conn.ackStates.handshakeAckState.reset();
}

bool hasInitialOrHandshakeCiphers(QuicConnectionStateBase& conn) {
  return conn.initialWriteCipher || conn.handshakeWriteCipher ||
      conn.readCodec->getInitialCipher() ||
      conn.readCodec->getHandshakeReadCipher();
}

bool setCustomTransportParameter(
    const CustomTransportParameter& customParam,
    std::vector<TransportParameter>& customTransportParameters) {
  // Check that the parameter id is in the "private parameter" range, as
  // described by the spec.
  if (static_cast<uint16_t>(customParam.getParameterId()) <
      kCustomTransportParameterThreshold) {
    LOG(ERROR) << "invalid parameter id";
    return false;
  }

  // check to see that we haven't already added in a parameter with the
  // specified parameter id
  auto it = std::find_if(
      customTransportParameters.begin(),
      customTransportParameters.end(),
      [&customParam](const TransportParameter& param) {
        return param.parameter == customParam.getParameterId();
      });

  // if a match has been found, we return failure
  if (it != customTransportParameters.end()) {
    LOG(ERROR) << "transport parameter already present";
    return false;
  }

  customTransportParameters.push_back(customParam.encode());
  return true;
}

bool toWriteInitialAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.initialWriteCipher && conn.ackStates.initialAckState &&
      hasAcksToSchedule(*conn.ackStates.initialAckState) &&
      conn.ackStates.initialAckState->needsToSendAckImmediately);
}

bool toWriteHandshakeAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.handshakeWriteCipher && conn.ackStates.handshakeAckState &&
      hasAcksToSchedule(*conn.ackStates.handshakeAckState) &&
      conn.ackStates.handshakeAckState->needsToSendAckImmediately);
}

bool toWriteAppDataAcks(const quic::QuicConnectionStateBase& conn) {
  return (
      conn.oneRttWriteCipher &&
      hasAcksToSchedule(conn.ackStates.appDataAckState) &&
      conn.ackStates.appDataAckState.needsToSendAckImmediately);
}
} // namespace quic
