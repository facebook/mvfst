/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/QuicPacketScheduler.h>

namespace {

quic::StreamFrameMetaData makeStreamFrameMetaDataFromStreamBuffer(
    quic::StreamId id,
    const quic::StreamBuffer& buffer);

quic::StreamFrameMetaData makeStreamFrameMetaDataFromStreamBuffer(
    quic::StreamId id,
    const quic::StreamBuffer& buffer) {
  quic::StreamFrameMetaData streamMeta;
  // It's very tricky to get the stream data without the length right,
  // so don't support it for now.
  streamMeta.hasMoreFrames = true;
  streamMeta.id = id;
  streamMeta.offset = buffer.offset;
  streamMeta.fin = buffer.eof;
  streamMeta.data = buffer.data.front() ? buffer.data.front()->clone()
                                        : folly::IOBuf::create(0);
  return streamMeta;
}
} // namespace

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
    const QuicConnectionStateBase& conn,
    EncryptionLevel encryptionLevel,
    PacketNumberSpace packetNumberSpace,
    const std::string& name)
    : conn_(conn),
      encryptionLevel_(encryptionLevel),
      packetNumberSpace_(packetNumberSpace),
      name_(name) {}

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
  auto scheduler = FrameScheduler(name_);
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

FrameScheduler::FrameScheduler(const std::string& name) : name_(name) {}

std::pair<
    folly::Optional<PacketEvent>,
    folly::Optional<RegularQuicPacketBuilder::Packet>>
FrameScheduler::scheduleFramesForPacket(
    RegularQuicPacketBuilder&& builder,
    uint32_t writableBytes) {
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
  if (retransmissionScheduler_ && retransmissionScheduler_->hasPendingData()) {
    retransmissionScheduler_->writeRetransmissionStreams(wrapper);
  }
  if (streamFrameScheduler_ && streamFrameScheduler_->hasPendingData()) {
    streamFrameScheduler_->writeStreams(wrapper);
  }
  if (simpleFrameScheduler_ &&
      simpleFrameScheduler_->hasPendingSimpleFrames()) {
    simpleFrameScheduler_->writeSimpleFrames(wrapper);
  }
  return std::make_pair(folly::none, std::move(builder).buildPacket());
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
      auto streamMeta =
          makeStreamFrameMetaDataFromStreamBuffer(stream->id, *buffer);
      auto res = writeStreamFrame(streamMeta, builder);
      if (!res) {
        // Finish assembling a packet
        break;
      }
      VLOG(4) << "Wrote retransmitted stream=" << streamMeta.id
              << " offset=" << streamMeta.offset
              << " bytes=" << res->bytesWritten << " fin=" << res->finWritten
              << " " << conn_;
    }
  }
}

bool RetransmissionScheduler::hasPendingData() const {
  return !conn_.streamManager->lossStreams().empty();
}

StreamFrameScheduler::StreamFrameScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

void StreamFrameScheduler::writeStreams(PacketBuilderInterface& builder) {
  uint64_t connWritableBytes = getSendConnFlowControlBytesWire(conn_);
  MiddleStartingIterationWrapper wrapper(
      conn_.streamManager->writableStreams(),
      conn_.schedulingState.lastScheduledStream);
  auto writableStreamItr = wrapper.cbegin();
  while (writableStreamItr != wrapper.cend() && connWritableBytes > 0) {
    auto res =
        writeNextStreamFrame(builder, writableStreamItr, connWritableBytes);
    if (!res) {
      break;
    }
  }
}

bool StreamFrameScheduler::hasPendingData() const {
  return conn_.streamManager->hasWritable() &&
      getSendConnFlowControlBytesWire(conn_) > 0;
}

bool StreamFrameScheduler::writeNextStreamFrame(
    PacketBuilderInterface& builder,
    StreamFrameScheduler::WritableStreamItr& writableStreamItr,
    uint64_t& connWritableBytes) {
  auto stream = conn_.streamManager->findStream(*writableStreamItr);
  CHECK(stream);

  // hasWritableData is the condition which has to be satisfied for the
  // stream to be in writableList
  DCHECK(stream->hasWritableData());

  auto streamMeta = makeStreamFrameMetaData(*stream, true, connWritableBytes);
  auto res = writeStreamFrame(streamMeta, builder);
  if (!res) {
    // Finish assembling a packet
    return false;
  }
  VLOG(4) << "Wrote stream frame stream=" << streamMeta.id
          << " offset=" << streamMeta.offset
          << " bytesWritten=" << res->bytesWritten
          << " finWritten=" << res->finWritten << " " << conn_;
  connWritableBytes -= res->bytesWritten;
  // bytesWritten < min(flowControlBytes, writeBuffer) means that we haven't
  // written all writable bytes in this stream due to short of room in the
  // packet.
  if (res->bytesWritten ==
      std::min<uint64_t>(
          getSendStreamFlowControlBytesWire(*stream),
          stream->writeBuffer.chainLength())) {
    ++writableStreamItr;
  }
  return true;
}

StreamFrameMetaData StreamFrameScheduler::makeStreamFrameMetaData(
    const QuicStreamState& streamData,
    bool /*hasMoreData*/,
    uint64_t connWritableBytes) {
  uint64_t writableBytes = std::min(
      getSendStreamFlowControlBytesWire(streamData), connWritableBytes);
  StreamFrameMetaData streamMeta;
  streamMeta.hasMoreFrames = true;
  streamMeta.id = streamData.id;
  streamMeta.offset = streamData.currentWriteOffset;
  if (streamData.writeBuffer.front()) {
    folly::io::Cursor cursor(streamData.writeBuffer.front());
    cursor.cloneAtMost(streamMeta.data, writableBytes);
  }
  streamMeta.fin = streamData.finalWriteOffset.hasValue() &&
      streamData.writeBuffer.chainLength() <= writableBytes;
  return streamMeta;
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
    auto res =
        writeCryptoFrame(buffer.offset, buffer.data.front()->clone(), builder);
    if (!res) {
      return cryptoDataWritten;
    }
    VLOG(4) << "Wrote retransmitted crypto"
            << " offset=" << buffer.offset << " bytes=" << res->len << " "
            << conn_;
    cryptoDataWritten = true;
  }

  if (writableData != 0) {
    Buf data;
    folly::io::Cursor cursor(cryptoStream_.writeBuffer.front());
    cursor.cloneAtMost(data, writableData);
    auto res = writeCryptoFrame(
        cryptoStream_.currentWriteOffset, std::move(data), builder);
    if (res) {
      VLOG(4) << "Wrote crypto frame"
              << " offset=" << cryptoStream_.currentWriteOffset
              << " bytesWritten=" << res->len << " " << conn_;
      cryptoDataWritten = true;
    }
  }
  if (cryptoDataWritten && conn_.nodeType == QuicNodeType::Client) {
    bool initialPacket = folly::variant_match(
        builder.getPacketHeader(),
        [](const LongHeader& header) {
          return header.getHeaderType() == LongHeader::Types::Initial;
        },
        [](const auto&) { return false; });
    if (initialPacket) {
      // This is the initial packet, we need to fill er up.
      while (builder.remainingSpaceInPkt() > 0) {
        writeFrame(PaddingFrame(), builder);
      }
    }
  }
  return cryptoDataWritten;
}

bool CryptoStreamScheduler::hasData() const {
  return !cryptoStream_.writeBuffer.empty() ||
      !cryptoStream_.lossBuffer.empty();
}

std::pair<
    folly::Optional<PacketEvent>,
    folly::Optional<RegularQuicPacketBuilder::Packet>>
CryptoStreamScheduler::scheduleFramesForPacket(
    RegularQuicPacketBuilder&& builder,
    uint32_t writableBytes) {
  // We need to keep track of writable bytes after writing header.
  writableBytes = writableBytes > builder.getHeaderBytes()
      ? writableBytes - builder.getHeaderBytes()
      : 0;
  if (!writableBytes) {
    return std::make_pair(folly::none, folly::none);
  }
  PacketBuilderWrapper wrapper(builder, writableBytes);
  writeCryptoData(wrapper);
  return std::make_pair(folly::none, std::move(builder).buildPacket());
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
       (conn_.outstandingPackets.size() !=
        conn_.outstandingHandshakePacketsCount +
            conn_.outstandingPureAckPacketsCount));
}

std::pair<
    folly::Optional<PacketEvent>,
    folly::Optional<RegularQuicPacketBuilder::Packet>>
CloningScheduler::scheduleFramesForPacket(
    RegularQuicPacketBuilder&& builder,
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
  // Look for an outstanding packet that's no larger than the writableBytes
  for (auto iter = conn_.outstandingPackets.rbegin();
       iter != conn_.outstandingPackets.rend();
       ++iter) {
    auto opPnSpace = folly::variant_match(
        iter->packet.header,
        [](const auto& h) { return h.getPacketNumberSpace(); });
    if (opPnSpace != PacketNumberSpace::AppData) {
      continue;
    }
    // Reusing the RegularQuicPacketBuilder throughout loop bodies will lead to
    // frames belong to different original packets being written into the same
    // clone packet. So re-create a RegularQuicPacketBuilder every time.
    // TODO: We can avoid the copy & rebuild of the header by creating an
    // independent header builder.
    auto builderPnSpace = folly::variant_match(
        builder.getPacketHeader(),
        [](const auto& h) { return h.getPacketNumberSpace(); });
    CHECK_EQ(builderPnSpace, PacketNumberSpace::AppData);
    RegularQuicPacketBuilder regularBuilder(
        conn_.udpSendPacketLen,
        builder.getPacketHeader(),
        getAckState(conn_, builderPnSpace).largestAckedByPeer,
        conn_.version.value_or(*conn_.originalVersion));
    PacketRebuilder rebuilder(regularBuilder, conn_);
    // We shouldn't clone Handshake packet. For PureAcks, cloning them bring
    // perf down as shown by load test.
    if (iter->isHandshake || iter->pureAck) {
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
    // TODO: This isn't the ideal way to solve the wrong writableBytes problem.
    if (iter->encodedSize > writableBytes + cipherOverhead_) {
      continue;
    }

    // Rebuilder will write the rest of frames
    auto rebuildResult = rebuilder.rebuildFromPacket(*iter);
    if (rebuildResult) {
      return std::make_pair(
          std::move(rebuildResult), std::move(regularBuilder).buildPacket());
    }
  }
  return std::make_pair(folly::none, folly::none);
}

std::string CloningScheduler::name() const {
  return name_;
}
} // namespace quic
