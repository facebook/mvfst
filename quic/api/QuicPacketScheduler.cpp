/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/QuicPacketScheduler.h>

namespace quic {

bool hasAcksToSchedule(const AckState& ackState) {
  folly::Optional<PacketNum> largestAckSend = largestAckToSend(ackState);
  if (!largestAckSend) {
    return false;
  }
  if (!ackState.largestAckScheduled) {
    // Never scheduled an ack, we need to send
    return true;
  }
  return *largestAckSend > *(ackState.largestAckScheduled);
}

folly::Optional<PacketNum> largestAckToSend(const AckState& ackState) {
  if (ackState.acks.empty()) {
    return folly::none;
  }
  return ackState.acks.back().end;
}

// Schedulers

FrameScheduler::Builder::Builder(
    QuicConnectionStateBase& conn,
    EncryptionLevel encryptionLevel,
    PacketNumberSpace packetNumberSpace,
    std::string name)
    : conn_(conn),
      encryptionLevel_(encryptionLevel),
      packetNumberSpace_(packetNumberSpace),
      name_(std::move(name)) {}

FrameScheduler::Builder& FrameScheduler::Builder::streamRetransmissions() {
  retransmissionScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::streamFrames() {
  streamFrameScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::ackFrames() {
  ackScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::resetFrames() {
  rstScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::windowUpdateFrames() {
  windowUpdateScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::blockedFrames() {
  blockedScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::cryptoFrames() {
  cryptoStreamScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::simpleFrames() {
  simpleFrameScheduler_ = true;
  return *this;
}

FrameScheduler FrameScheduler::Builder::build() && {
  FrameScheduler scheduler(std::move(name_));
  if (retransmissionScheduler_) {
    scheduler.retransmissionScheduler_.emplace(RetransmissionScheduler(conn_));
  }
  if (streamFrameScheduler_) {
    scheduler.streamFrameScheduler_.emplace(StreamFrameScheduler(conn_));
  }
  if (ackScheduler_) {
    scheduler.ackScheduler_.emplace(
        AckScheduler(conn_, getAckState(conn_, packetNumberSpace_)));
  }
  if (rstScheduler_) {
    scheduler.rstScheduler_.emplace(RstStreamScheduler(conn_));
  }
  if (windowUpdateScheduler_) {
    scheduler.windowUpdateScheduler_.emplace(WindowUpdateScheduler(conn_));
  }
  if (blockedScheduler_) {
    scheduler.blockedScheduler_.emplace(BlockedScheduler(conn_));
  }
  if (cryptoStreamScheduler_) {
    scheduler.cryptoStreamScheduler_.emplace(CryptoStreamScheduler(
        conn_, *getCryptoStream(*conn_.cryptoState, encryptionLevel_)));
  }
  if (simpleFrameScheduler_) {
    scheduler.simpleFrameScheduler_.emplace(SimpleFrameScheduler(conn_));
  }
  return scheduler;
}

FrameScheduler::FrameScheduler(std::string name) : name_(std::move(name)) {}

SchedulingResult FrameScheduler::scheduleFramesForPacket(
    PacketBuilderInterface&& builder,
    uint32_t writableBytes) {
  builder.encodePacketHeader();
  // We need to keep track of writable bytes after writing header.
  writableBytes = writableBytes > builder.getHeaderBytes()
      ? writableBytes - builder.getHeaderBytes()
      : 0;
  // We cannot return early if the writablyBytes dropps to 0 here, since pure
  // acks can skip writableBytes entirely.
  PacketBuilderWrapper wrapper(builder, writableBytes);
  auto ackMode = hasImmediateData() ? AckMode::Immediate : AckMode::Pending;
  bool cryptoDataWritten = false;
  bool rstWritten = false;
  if (cryptoStreamScheduler_ && cryptoStreamScheduler_->hasData()) {
    cryptoDataWritten = cryptoStreamScheduler_->writeCryptoData(wrapper);
  }
  if (rstScheduler_ && rstScheduler_->hasPendingRsts()) {
    rstWritten = rstScheduler_->writeRsts(wrapper);
  }
  if (ackScheduler_ && ackScheduler_->hasPendingAcks()) {
    if (cryptoDataWritten || rstWritten) {
      // If packet has non ack data, it is subject to congestion control. We
      // need to use the wrapper/
      ackScheduler_->writeNextAcks(wrapper, ackMode);
    } else {
      // If we start with writing acks, we will let the ack scheduler write
      // up to the full packet space. If the ack bytes exceeds the writable
      // bytes, this will be a pure ack packet and it will skip congestion
      // controller. Otherwise, we will give other schedulers an opportunity to
      // write up to writable bytes.
      ackScheduler_->writeNextAcks(builder, ackMode);
    }
  }
  if (windowUpdateScheduler_ &&
      windowUpdateScheduler_->hasPendingWindowUpdates()) {
    windowUpdateScheduler_->writeWindowUpdates(wrapper);
  }
  if (blockedScheduler_ && blockedScheduler_->hasPendingBlockedFrames()) {
    blockedScheduler_->writeBlockedFrames(wrapper);
  }
  // Simple frames should be scheduled before stream frames and retx frames
  // because those frames might fill up all available bytes for writing.
  // If we are trying to send a PathChallenge frame it may be blocked by those,
  // causing a connection to proceed slowly because of path validation rate
  // limiting.
  if (simpleFrameScheduler_ &&
      simpleFrameScheduler_->hasPendingSimpleFrames()) {
    simpleFrameScheduler_->writeSimpleFrames(wrapper);
  }
  if (retransmissionScheduler_ && retransmissionScheduler_->hasPendingData()) {
    retransmissionScheduler_->writeRetransmissionStreams(wrapper);
  }
  if (streamFrameScheduler_ && streamFrameScheduler_->hasPendingData()) {
    streamFrameScheduler_->writeStreams(wrapper);
  }

  if (builder.hasFramesPending()) {
    const LongHeader* longHeader = builder.getPacketHeader().asLong();
    bool initialPacket =
        longHeader && longHeader->getHeaderType() == LongHeader::Types::Initial;
    if (initialPacket) {
      // This is the initial packet, we need to fill er up.
      while (wrapper.remainingSpaceInPkt() > 0) {
        writeFrame(PaddingFrame(), builder);
      }
    }
  }

  return SchedulingResult(folly::none, std::move(builder).buildPacket());
}

bool FrameScheduler::hasData() const {
  return (ackScheduler_ && ackScheduler_->hasPendingAcks()) ||
      hasImmediateData();
}

bool FrameScheduler::hasImmediateData() const {
  return (cryptoStreamScheduler_ && cryptoStreamScheduler_->hasData()) ||
      (retransmissionScheduler_ &&
       retransmissionScheduler_->hasPendingData()) ||
      (streamFrameScheduler_ && streamFrameScheduler_->hasPendingData()) ||
      (rstScheduler_ && rstScheduler_->hasPendingRsts()) ||
      (windowUpdateScheduler_ &&
       windowUpdateScheduler_->hasPendingWindowUpdates()) ||
      (blockedScheduler_ && blockedScheduler_->hasPendingBlockedFrames()) ||
      (simpleFrameScheduler_ &&
       simpleFrameScheduler_->hasPendingSimpleFrames());
}

std::string FrameScheduler::name() const {
  return name_;
}

RetransmissionScheduler::RetransmissionScheduler(
    const QuicConnectionStateBase& conn)
    : conn_(conn) {}

void RetransmissionScheduler::writeRetransmissionStreams(
    PacketBuilderInterface& builder) {
  for (auto streamId : conn_.streamManager->lossStreams()) {
    auto stream = conn_.streamManager->findStream(streamId);
    CHECK(stream);
    for (auto buffer = stream->lossBuffer.cbegin();
         buffer != stream->lossBuffer.cend();
         ++buffer) {
      auto bufferLen = buffer->data.chainLength();
      auto dataLen = writeStreamFrameHeader(
          builder,
          stream->id,
          buffer->offset,
          bufferLen, // writeBufferLen -- only the len of the single buffer.
          bufferLen, // flowControlLen -- not relevant, already flow controlled.
          buffer->eof,
          folly::none /* skipLenHint */);
      if (dataLen) {
        writeStreamFrameData(builder, buffer->data, *dataLen);
        VLOG(4) << "Wrote retransmitted stream=" << stream->id
                << " offset=" << buffer->offset << " bytes=" << *dataLen
                << " fin=" << (buffer->eof && *dataLen == bufferLen) << " "
                << conn_;
      } else {
        return;
      }
    }
  }
}

bool RetransmissionScheduler::hasPendingData() const {
  return !conn_.streamManager->lossStreams().empty();
}

StreamFrameScheduler::StreamFrameScheduler(QuicConnectionStateBase& conn)
    : conn_(conn) {}

StreamId StreamFrameScheduler::writeStreamsHelper(
    PacketBuilderInterface& builder,
    const std::set<StreamId>& writableStreams,
    StreamId nextScheduledStream,
    uint64_t& connWritableBytes,
    bool streamPerPacket) {
  MiddleStartingIterationWrapper wrapper(writableStreams, nextScheduledStream);
  auto writableStreamItr = wrapper.cbegin();
  // This will write the stream frames in a round robin fashion ordered by
  // stream id. The iterator will wrap around the collection at the end, and we
  // keep track of the value at the next iteration. This allows us to start
  // writing at the next stream when building the next packet.
  // TODO experiment with writing streams with an actual prioritization scheme.
  while (writableStreamItr != wrapper.cend() && connWritableBytes > 0) {
    if (writeNextStreamFrame(builder, *writableStreamItr, connWritableBytes)) {
      writableStreamItr++;
      if (streamPerPacket) {
        break;
      }
    } else {
      break;
    }
  }
  return *writableStreamItr;
}

void StreamFrameScheduler::writeStreams(PacketBuilderInterface& builder) {
  DCHECK(conn_.streamManager->hasWritable());
  uint64_t connWritableBytes = getSendConnFlowControlBytesWire(conn_);
  if (connWritableBytes == 0) {
    return;
  }
  // Write the control streams first as a naive binary priority mechanism.
  const auto& writableControlStreams =
      conn_.streamManager->writableControlStreams();
  if (!writableControlStreams.empty()) {
    conn_.schedulingState.nextScheduledControlStream = writeStreamsHelper(
        builder,
        writableControlStreams,
        conn_.schedulingState.nextScheduledControlStream,
        connWritableBytes,
        conn_.transportSettings.streamFramePerPacket);
  }
  if (connWritableBytes == 0) {
    return;
  }
  const auto& writableStreams = conn_.streamManager->writableStreams();
  if (!writableStreams.empty()) {
    conn_.schedulingState.nextScheduledStream = writeStreamsHelper(
        builder,
        writableStreams,
        conn_.schedulingState.nextScheduledStream,
        connWritableBytes,
        conn_.transportSettings.streamFramePerPacket);
  }
} // namespace quic

bool StreamFrameScheduler::hasPendingData() const {
  return conn_.streamManager->hasWritable() &&
      getSendConnFlowControlBytesWire(conn_) > 0;
}

bool StreamFrameScheduler::writeNextStreamFrame(
    PacketBuilderInterface& builder,
    StreamId streamId,
    uint64_t& connWritableBytes) {
  if (builder.remainingSpaceInPkt() == 0) {
    return false;
  }
  auto stream = conn_.streamManager->findStream(streamId);
  CHECK(stream);

  // hasWritableData is the condition which has to be satisfied for the
  // stream to be in writableList
  DCHECK(stream->hasWritableData());

  uint64_t flowControlLen =
      std::min(getSendStreamFlowControlBytesWire(*stream), connWritableBytes);
  uint64_t bufferLen = stream->writeBuffer.chainLength();
  bool canWriteFin =
      stream->finalWriteOffset.has_value() && bufferLen <= flowControlLen;
  auto dataLen = writeStreamFrameHeader(
      builder,
      stream->id,
      stream->currentWriteOffset,
      bufferLen,
      flowControlLen,
      canWriteFin,
      folly::none /* skipLenHint */);
  if (!dataLen) {
    return false;
  }
  writeStreamFrameData(builder, stream->writeBuffer, *dataLen);
  VLOG(4) << "Wrote stream frame stream=" << stream->id
          << " offset=" << stream->currentWriteOffset
          << " bytesWritten=" << *dataLen
          << " finWritten=" << (canWriteFin && *dataLen == bufferLen) << " "
          << conn_;
  connWritableBytes -= dataLen.value();
  return true;
}

AckScheduler::AckScheduler(
    const QuicConnectionStateBase& conn,
    const AckState& ackState)
    : conn_(conn), ackState_(ackState) {}

bool AckScheduler::hasPendingAcks() const {
  return hasAcksToSchedule(ackState_);
}

RstStreamScheduler::RstStreamScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool RstStreamScheduler::hasPendingRsts() const {
  return !conn_.pendingEvents.resets.empty();
}

bool RstStreamScheduler::writeRsts(PacketBuilderInterface& builder) {
  bool rstWritten = false;
  for (const auto& resetStream : conn_.pendingEvents.resets) {
    // TODO: here, maybe coordinate scheduling of RST_STREAMS and streams.
    auto bytesWritten = writeFrame(resetStream.second, builder);
    if (!bytesWritten) {
      break;
    }
    rstWritten = true;
  }
  return rstWritten;
}

SimpleFrameScheduler::SimpleFrameScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool SimpleFrameScheduler::hasPendingSimpleFrames() const {
  return conn_.pendingEvents.pathChallenge ||
      !conn_.pendingEvents.frames.empty();
}

bool SimpleFrameScheduler::writeSimpleFrames(PacketBuilderInterface& builder) {
  auto& pathChallenge = conn_.pendingEvents.pathChallenge;
  if (pathChallenge &&
      !writeSimpleFrame(QuicSimpleFrame(*pathChallenge), builder)) {
    return false;
  }

  bool framesWritten = false;
  for (auto& frame : conn_.pendingEvents.frames) {
    auto bytesWritten = writeSimpleFrame(QuicSimpleFrame(frame), builder);
    if (!bytesWritten) {
      break;
    }
    framesWritten = true;
  }
  return framesWritten;
}

WindowUpdateScheduler::WindowUpdateScheduler(
    const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool WindowUpdateScheduler::hasPendingWindowUpdates() const {
  return conn_.streamManager->hasWindowUpdates() ||
      conn_.pendingEvents.connWindowUpdate;
}

void WindowUpdateScheduler::writeWindowUpdates(
    PacketBuilderInterface& builder) {
  if (conn_.pendingEvents.connWindowUpdate) {
    auto maxDataFrame = generateMaxDataFrame(conn_);
    auto maximumData = maxDataFrame.maximumData;
    auto bytes = writeFrame(std::move(maxDataFrame), builder);
    if (bytes) {
      VLOG(4) << "Wrote max_data=" << maximumData << " " << conn_;
    }
  }
  for (const auto& windowUpdateStream : conn_.streamManager->windowUpdates()) {
    auto stream = conn_.streamManager->findStream(windowUpdateStream);
    if (!stream) {
      continue;
    }
    auto maxStreamDataFrame = generateMaxStreamDataFrame(*stream);
    auto maximumData = maxStreamDataFrame.maximumData;
    auto bytes = writeFrame(std::move(maxStreamDataFrame), builder);
    if (!bytes) {
      break;
    }
    VLOG(4) << "Wrote max_stream_data stream=" << stream->id
            << " maximumData=" << maximumData << " " << conn_;
  }
}

BlockedScheduler::BlockedScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool BlockedScheduler::hasPendingBlockedFrames() const {
  return !conn_.streamManager->blockedStreams().empty();
}

void BlockedScheduler::writeBlockedFrames(PacketBuilderInterface& builder) {
  for (const auto& blockedStream : conn_.streamManager->blockedStreams()) {
    auto bytesWritten = writeFrame(blockedStream.second, builder);
    if (!bytesWritten) {
      break;
    }
  }
}

CryptoStreamScheduler::CryptoStreamScheduler(
    const QuicConnectionStateBase& conn,
    const QuicCryptoStream& cryptoStream)
    : conn_(conn), cryptoStream_(cryptoStream) {}

bool CryptoStreamScheduler::writeCryptoData(PacketBuilderInterface& builder) {
  bool cryptoDataWritten = false;
  uint64_t writableData =
      folly::to<uint64_t>(cryptoStream_.writeBuffer.chainLength());
  // We use the crypto scheduler to reschedule the retransmissions of the
  // crypto streams so that we know that retransmissions of the crypto data
  // will always take precedence over the crypto data.
  for (const auto& buffer : cryptoStream_.lossBuffer) {
    auto res = writeCryptoFrame(buffer.offset, buffer.data, builder);
    if (!res) {
      return cryptoDataWritten;
    }
    VLOG(4) << "Wrote retransmitted crypto"
            << " offset=" << buffer.offset << " bytes=" << res->len << " "
            << conn_;
    cryptoDataWritten = true;
  }

  if (writableData != 0) {
    auto res = writeCryptoFrame(
        cryptoStream_.currentWriteOffset, cryptoStream_.writeBuffer, builder);
    if (res) {
      VLOG(4) << "Wrote crypto frame"
              << " offset=" << cryptoStream_.currentWriteOffset
              << " bytesWritten=" << res->len << " " << conn_;
      cryptoDataWritten = true;
    }
  }
  return cryptoDataWritten;
}

bool CryptoStreamScheduler::hasData() const {
  return !cryptoStream_.writeBuffer.empty() ||
      !cryptoStream_.lossBuffer.empty();
}

CloningScheduler::CloningScheduler(
    FrameScheduler& scheduler,
    QuicConnectionStateBase& conn,
    const std::string& name,
    uint64_t cipherOverhead)
    : frameScheduler_(scheduler),
      conn_(conn),
      name_(std::move(name)),
      cipherOverhead_(cipherOverhead) {}

bool CloningScheduler::hasData() const {
  return frameScheduler_.hasData() ||
      (!conn_.outstandingPackets.empty() &&
       conn_.outstandingPackets.size() !=
           conn_.outstandingHandshakePacketsCount);
}

SchedulingResult CloningScheduler::scheduleFramesForPacket(
    PacketBuilderInterface&& builder,
    uint32_t writableBytes) {
  // The writableBytes in this function shouldn't be limited by cwnd, since
  // we only use CloningScheduler for the cases that we want to bypass cwnd for
  // now.
  if (frameScheduler_.hasData()) {
    // Note that there is a possibility that we end up writing nothing here. But
    // if frameScheduler_ hasData() to write, we shouldn't invoke the cloning
    // path if the write fails.
    return frameScheduler_.scheduleFramesForPacket(
        std::move(builder), writableBytes);
  }
  // TODO: We can avoid the copy & rebuild of the header by creating an
  // independent header builder.
  auto header = builder.getPacketHeader();
  std::move(builder).releaseOutputBuffer();
  // Look for an outstanding packet that's no larger than the writableBytes
  // This is a loop, but it builds at most one packet.
  for (auto iter = conn_.outstandingPackets.rbegin();
       iter != conn_.outstandingPackets.rend();
       ++iter) {
    auto opPnSpace = iter->packet.header.getPacketNumberSpace();
    if (opPnSpace != PacketNumberSpace::AppData) {
      continue;
    }
    // Reusing the same builder throughout loop bodies will lead to frames
    // belong to different original packets being written into the same clone
    // packet. So re-create a builder every time.
    auto builderPnSpace = header.getPacketNumberSpace();
    CHECK_EQ(builderPnSpace, PacketNumberSpace::AppData);
    std::unique_ptr<PacketBuilderInterface> internalBuilder;
    if (conn_.transportSettings.dataPathType == DataPathType::ChainedMemory) {
      internalBuilder = std::make_unique<RegularQuicPacketBuilder>(
          conn_.udpSendPacketLen - cipherOverhead_,
          header,
          getAckState(conn_, builderPnSpace).largestAckedByPeer);
    } else {
      CHECK(conn_.bufAccessor && conn_.bufAccessor->ownsBuffer());
      internalBuilder = std::make_unique<InplaceQuicPacketBuilder>(
          *conn_.bufAccessor,
          conn_.udpSendPacketLen - cipherOverhead_,
          header,
          getAckState(conn_, builderPnSpace).largestAckedByPeer);
    }
    internalBuilder->setCipherOverhead(cipherOverhead_);
    internalBuilder->encodePacketHeader();
    PacketRebuilder rebuilder(*internalBuilder, conn_);
    // We shouldn't clone Handshake packet.
    if (iter->isHandshake) {
      continue;
    }
    // If the packet is already a clone that has been processed, we don't clone
    // it again.
    if (iter->associatedEvent &&
        conn_.outstandingPacketEvents.count(*iter->associatedEvent) == 0) {
      continue;
    }

    // The writableBytes here is an optimization. If the writableBytes is too
    // small for this packet. rebuildFromPacket should fail anyway.
    if (iter->encodedSize > writableBytes + cipherOverhead_) {
      continue;
    }

    // TODO: It's possible we write out a packet that's larger than the packet
    // size limit. For example, when the packet sequence number has advanced to
    // a point where we need more bytes to encoded it than that of the original
    // packet. In that case, if the original packet is already at the packet
    // size limit, we will generate a packet larger than the limit. We can
    // either ignore the problem, hoping the packet will be able to travel the
    // network just fine; Or we can throw away the built packet and send a ping.

    // Rebuilder will write the rest of frames
    auto rebuildResult = rebuilder.rebuildFromPacket(*iter);
    if (rebuildResult) {
      return SchedulingResult(
          std::move(rebuildResult), std::move(*internalBuilder).buildPacket());
    }
  }
  return SchedulingResult(folly::none, folly::none);
}

std::string CloningScheduler::name() const {
  return name_;
}
} // namespace quic
