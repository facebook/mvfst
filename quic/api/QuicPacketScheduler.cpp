/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicConstants.h>
#include <quic/api/QuicPacketScheduler.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <cstdint>

namespace {
using namespace quic;

/**
 * A helper iterator adaptor class that starts iteration of streams from a
 * specific stream id.
 */
class MiddleStartingIterationWrapper {
 public:
  using MapType = std::set<StreamId>;

  class MiddleStartingIterator
      : public boost::iterator_facade<
            MiddleStartingIterator,
            const MiddleStartingIterationWrapper::MapType::value_type,
            boost::forward_traversal_tag> {
    friend class boost::iterator_core_access;

   public:
    using MapType = MiddleStartingIterationWrapper::MapType;

    MiddleStartingIterator() = delete;

    MiddleStartingIterator(
        const MapType* streams,
        const MapType::key_type& start)
        : streams_(streams) {
      itr_ = streams_->lower_bound(start);
      checkForWrapAround();
      // We don't want to mark it as wrapped around initially, instead just
      // act as if start was the first element.
      wrappedAround_ = false;
    }

    MiddleStartingIterator(const MapType* streams, MapType::const_iterator itr)
        : streams_(streams), itr_(itr) {
      checkForWrapAround();
      // We don't want to mark it as wrapped around initially, instead just
      // act as if start was the first element.
      wrappedAround_ = false;
    }

    FOLLY_NODISCARD const MapType::value_type& dereference() const {
      return *itr_;
    }

    FOLLY_NODISCARD MapType::const_iterator rawIterator() const {
      return itr_;
    }

    FOLLY_NODISCARD bool equal(const MiddleStartingIterator& other) const {
      return wrappedAround_ == other.wrappedAround_ && itr_ == other.itr_;
    }

    void increment() {
      ++itr_;
      checkForWrapAround();
    }

    void checkForWrapAround() {
      if (itr_ == streams_->cend()) {
        wrappedAround_ = true;
        itr_ = streams_->cbegin();
      }
    }

   private:
    friend class MiddleStartingIterationWrapper;
    bool wrappedAround_{false};
    const MapType* streams_{nullptr};
    MapType::const_iterator itr_;
  };

  MiddleStartingIterationWrapper(
      const MapType& streams,
      const MapType::key_type& start)
      : streams_(streams), start_(&streams_, start) {}

  MiddleStartingIterationWrapper(
      const MapType& streams,
      const MapType::const_iterator& start)
      : streams_(streams), start_(&streams_, start) {}

  FOLLY_NODISCARD MiddleStartingIterator cbegin() const {
    return start_;
  }

  FOLLY_NODISCARD MiddleStartingIterator cend() const {
    MiddleStartingIterator itr(start_);
    itr.wrappedAround_ = true;
    return itr;
  }

 private:
  const MapType& streams_;
  const MiddleStartingIterator start_;
};

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
    QuicConnectionStateBase& conn,
    EncryptionLevel encryptionLevel,
    PacketNumberSpace packetNumberSpace,
    folly::StringPiece name)
    : conn_(conn),
      encryptionLevel_(encryptionLevel),
      packetNumberSpace_(packetNumberSpace),
      name_(std::move(name)) {}

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

FrameScheduler::Builder& FrameScheduler::Builder::pingFrames() {
  pingFrameScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::datagramFrames() {
  datagramFrameScheduler_ = true;
  return *this;
}

FrameScheduler::Builder& FrameScheduler::Builder::immediateAckFrames() {
  immediateAckFrameScheduler_ = true;
  return *this;
}

FrameScheduler FrameScheduler::Builder::build() && {
  FrameScheduler scheduler(name_, conn_);
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
  if (pingFrameScheduler_) {
    scheduler.pingFrameScheduler_.emplace(PingFrameScheduler(conn_));
  }
  if (datagramFrameScheduler_) {
    scheduler.datagramFrameScheduler_.emplace(DatagramFrameScheduler(conn_));
  }
  if (immediateAckFrameScheduler_) {
    scheduler.immediateAckFrameScheduler_.emplace(
        ImmediateAckFrameScheduler(conn_));
  }
  return scheduler;
}

FrameScheduler::FrameScheduler(
    folly::StringPiece name,
    QuicConnectionStateBase& conn)
    : name_(name), conn_(conn) {}

SchedulingResult FrameScheduler::scheduleFramesForPacket(
    PacketBuilderInterface&& builder,
    uint32_t writableBytes) {
  builder.encodePacketHeader();
  // We need to keep track of writable bytes after writing header.
  writableBytes = writableBytes > builder.getHeaderBytes()
      ? writableBytes - builder.getHeaderBytes()
      : 0;
  // We cannot return early if the writablyBytes drops to 0 here, since pure
  // acks can skip writableBytes entirely.
  PacketBuilderWrapper wrapper(builder, writableBytes);
  bool cryptoDataWritten = false;
  bool rstWritten = false;
  if (cryptoStreamScheduler_ && cryptoStreamScheduler_->hasData()) {
    cryptoDataWritten = cryptoStreamScheduler_->writeCryptoData(wrapper);
  }
  if (rstScheduler_ && rstScheduler_->hasPendingRsts()) {
    rstWritten = rstScheduler_->writeRsts(wrapper);
  }
  // Long time ago we decided RST has higher priority than Acks.
  if (hasPendingAcks()) {
    if (cryptoDataWritten || rstWritten) {
      // If packet has non ack data, it is subject to congestion control. We
      // need to use the wrapper/
      ackScheduler_->writeNextAcks(wrapper);
    } else {
      // If we start with writing acks, we will let the ack scheduler write
      // up to the full packet space. If the ack bytes exceeds the writable
      // bytes, this will be a pure ack packet and it will skip congestion
      // controller. Otherwise, we will give other schedulers an opportunity to
      // write up to writable bytes.
      ackScheduler_->writeNextAcks(builder);
    }
  }
  // Immediate ACK frames are subject to congestion control but should be sent
  // before other frames to maximize their chance of being included in the
  // packet since they are time sensitive
  if (immediateAckFrameScheduler_ &&
      immediateAckFrameScheduler_->hasPendingImmediateAckFrame()) {
    immediateAckFrameScheduler_->writeImmediateAckFrame(wrapper);
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
  if (pingFrameScheduler_ && pingFrameScheduler_->hasPingFrame()) {
    pingFrameScheduler_->writePing(wrapper);
  }
  if (streamFrameScheduler_ && streamFrameScheduler_->hasPendingData()) {
    streamFrameScheduler_->writeStreams(wrapper);
  }
  if (datagramFrameScheduler_ &&
      datagramFrameScheduler_->hasPendingDatagramFrames()) {
    datagramFrameScheduler_->writeDatagramFrames(wrapper);
  }

  if (builder.hasFramesPending()) {
    const LongHeader* longHeader = builder.getPacketHeader().asLong();
    bool initialPacket =
        longHeader && longHeader->getHeaderType() == LongHeader::Types::Initial;
    if (initialPacket) {
      // This is the initial packet, we need to fill er up.
      while (builder.remainingSpaceInPkt() > 0) {
        writeFrame(PaddingFrame(), builder);
      }
    }
    const ShortHeader* shortHeader = builder.getPacketHeader().asShort();
    if (shortHeader) {
      size_t paddingModulo = conn_.transportSettings.paddingModulo;
      if (paddingModulo > 0) {
        size_t paddingIncrement = wrapper.remainingSpaceInPkt() % paddingModulo;
        for (size_t i = 0; i < paddingIncrement; i++) {
          writeFrame(PaddingFrame(), builder);
        }
        QUIC_STATS(conn_.statsCallback, onShortHeaderPadding, paddingIncrement);
      }
    }
  }

  return SchedulingResult(folly::none, std::move(builder).buildPacket());
}

void FrameScheduler::writeNextAcks(PacketBuilderInterface& builder) {
  ackScheduler_->writeNextAcks(builder);
}

bool FrameScheduler::hasData() const {
  return hasPendingAcks() || hasImmediateData();
}

bool FrameScheduler::hasPendingAcks() const {
  return ackScheduler_ && ackScheduler_->hasPendingAcks();
}

bool FrameScheduler::hasImmediateData() const {
  return (cryptoStreamScheduler_ && cryptoStreamScheduler_->hasData()) ||
      (streamFrameScheduler_ && streamFrameScheduler_->hasPendingData()) ||
      (rstScheduler_ && rstScheduler_->hasPendingRsts()) ||
      (windowUpdateScheduler_ &&
       windowUpdateScheduler_->hasPendingWindowUpdates()) ||
      (blockedScheduler_ && blockedScheduler_->hasPendingBlockedFrames()) ||
      (simpleFrameScheduler_ &&
       simpleFrameScheduler_->hasPendingSimpleFrames()) ||
      (pingFrameScheduler_ && pingFrameScheduler_->hasPingFrame()) ||
      (datagramFrameScheduler_ &&
       datagramFrameScheduler_->hasPendingDatagramFrames()) ||
      (immediateAckFrameScheduler_ &&
       immediateAckFrameScheduler_->hasPendingImmediateAckFrame());
}

folly::StringPiece FrameScheduler::name() const {
  return name_;
}

bool StreamFrameScheduler::writeStreamLossBuffers(
    PacketBuilderInterface& builder,
    QuicStreamState& stream) {
  bool wroteStreamFrame = false;
  for (auto buffer = stream.lossBuffer.cbegin();
       buffer != stream.lossBuffer.cend();
       ++buffer) {
    auto bufferLen = buffer->data.chainLength();
    auto dataLen = writeStreamFrameHeader(
        builder,
        stream.id,
        buffer->offset,
        bufferLen, // writeBufferLen -- only the len of the single buffer.
        bufferLen, // flowControlLen -- not relevant, already flow controlled.
        buffer->eof,
        folly::none /* skipLenHint */,
        stream.groupId);
    if (dataLen) {
      wroteStreamFrame = true;
      writeStreamFrameData(builder, buffer->data, *dataLen);
      VLOG(4) << "Wrote loss data for stream=" << stream.id
              << " offset=" << buffer->offset << " bytes=" << *dataLen
              << " fin=" << (buffer->eof && *dataLen == bufferLen) << " "
              << conn_;
    } else {
      // Either we filled the packet or ran out of data for this stream (EOF?)
      break;
    }
  }
  return wroteStreamFrame;
}

StreamFrameScheduler::StreamFrameScheduler(QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool StreamFrameScheduler::writeSingleStream(
    PacketBuilderInterface& builder,
    QuicStreamState& stream,
    uint64_t& connWritableBytes) {
  if (!stream.lossBuffer.empty()) {
    if (!writeStreamLossBuffers(builder, stream)) {
      return false;
    }
  }
  if (stream.hasWritableData() && connWritableBytes > 0) {
    if (!writeStreamFrame(builder, stream, connWritableBytes)) {
      return false;
    }
  }
  return true;
}

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
  while (writableStreamItr != wrapper.cend()) {
    auto stream = conn_.streamManager->findStream(*writableStreamItr);
    CHECK(stream);
    if (!writeSingleStream(builder, *stream, connWritableBytes)) {
      break;
    }
    writableStreamItr++;
    if (streamPerPacket) {
      break;
    }
  }
  return *writableStreamItr;
}

void StreamFrameScheduler::writeStreamsHelper(
    PacketBuilderInterface& builder,
    PriorityQueue& writableStreams,
    uint64_t& connWritableBytes,
    bool streamPerPacket) {
  // Fill a packet with non-control stream data, in priority order
  for (size_t index = 0; index < writableStreams.levels.size() &&
       builder.remainingSpaceInPkt() > 0;
       index++) {
    PriorityQueue::Level& level = writableStreams.levels[index];
    if (level.empty()) {
      // No data here, keep going
      continue;
    }

    level.iterator->begin();
    do {
      auto streamId = level.iterator->current();
      auto stream = CHECK_NOTNULL(conn_.streamManager->findStream(streamId));
      if (!stream->hasSchedulableData() && stream->hasSchedulableDsr()) {
        // We hit a DSR stream
        return;
      }
      CHECK(stream) << "streamId=" << streamId
                    << "inc=" << uint64_t(level.incremental);
      if (!writeSingleStream(builder, *stream, connWritableBytes)) {
        break;
      }
      auto remainingSpaceAfter = builder.remainingSpaceInPkt();
      // If we wrote a stream frame and there's still space in the packet,
      // that implies we ran out of data or flow control on the stream and
      // we should bypass the nextsPerStream in the priority queue.
      bool forceNext = remainingSpaceAfter > 0;
      level.iterator->next(forceNext);
      if (streamPerPacket) {
        return;
      }
    } while (!level.iterator->end());
  }
}

void StreamFrameScheduler::writeStreams(PacketBuilderInterface& builder) {
  DCHECK(conn_.streamManager->hasWritable());
  uint64_t connWritableBytes = getSendConnFlowControlBytesWire(conn_);
  // Write the control streams first as a naive binary priority mechanism.
  const auto& controlWriteQueue = conn_.streamManager->controlWriteQueue();
  if (!controlWriteQueue.empty()) {
    conn_.schedulingState.nextScheduledControlStream = writeStreamsHelper(
        builder,
        controlWriteQueue,
        conn_.schedulingState.nextScheduledControlStream,
        connWritableBytes,
        conn_.transportSettings.streamFramePerPacket);
  }
  auto& writeQueue = conn_.streamManager->writeQueue();
  if (!writeQueue.empty()) {
    writeStreamsHelper(
        builder,
        writeQueue,
        connWritableBytes,
        conn_.transportSettings.streamFramePerPacket);
    // If the next non-control stream is DSR, record that fact in the scheduler
    // so that we don't try to write a non DSR stream again. Note that this
    // means that in the presence of many large control streams and DSR
    // streams, we won't completely prioritize control streams but they
    // will not be starved.
    auto streamId = writeQueue.getNextScheduledStream();
    auto stream = conn_.streamManager->findStream(streamId);
    if (stream && !stream->hasSchedulableData()) {
      nextStreamDsr_ = true;
    }
  }
}

bool StreamFrameScheduler::hasPendingData() const {
  return !nextStreamDsr_ &&
      (conn_.streamManager->hasNonDSRLoss() ||
       (conn_.streamManager->hasNonDSRWritable() &&
        getSendConnFlowControlBytesWire(conn_) > 0));
}

bool StreamFrameScheduler::writeStreamFrame(
    PacketBuilderInterface& builder,
    QuicStreamState& stream,
    uint64_t& connWritableBytes) {
  if (builder.remainingSpaceInPkt() == 0) {
    return false;
  }

  // hasWritableData is the condition which has to be satisfied for the
  // stream to be in writableList
  CHECK(stream.hasWritableData());

  uint64_t flowControlLen =
      std::min(getSendStreamFlowControlBytesWire(stream), connWritableBytes);
  uint64_t bufferLen = stream.writeBuffer.chainLength();
  // We should never write a FIN from the non-DSR scheduler for a DSR stream.
  bool canWriteFin = stream.finalWriteOffset.has_value() &&
      bufferLen <= flowControlLen && stream.writeBufMeta.offset == 0;
  auto writeOffset = stream.currentWriteOffset;
  auto dataLen = writeStreamFrameHeader(
      builder,
      stream.id,
      writeOffset,
      bufferLen,
      flowControlLen,
      canWriteFin,
      folly::none /* skipLenHint */,
      stream.groupId);
  if (!dataLen) {
    return false;
  }
  writeStreamFrameData(builder, stream.writeBuffer, *dataLen);
  VLOG(4) << "Wrote stream frame stream=" << stream.id
          << " offset=" << stream.currentWriteOffset
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

folly::Optional<PacketNum> AckScheduler::writeNextAcks(
    PacketBuilderInterface& builder) {
  // Use default ack delay for long headers. Usually long headers are sent
  // before crypto negotiation, so the peer might not know about the ack delay
  // exponent yet, so we use the default.
  uint8_t ackDelayExponentToUse =
      builder.getPacketHeader().getHeaderForm() == HeaderForm::Long
      ? kDefaultAckDelayExponent
      : conn_.transportSettings.ackDelayExponent;
  auto largestAckedPacketNum = *largestAckToSend(ackState_);
  auto ackingTime = Clock::now();
  DCHECK(ackState_.largestRecvdPacketTime.hasValue())
      << "Missing received time for the largest acked packet";
  // assuming that we're going to ack the largest received with highest pri
  auto receivedTime = *ackState_.largestRecvdPacketTime;
  std::chrono::microseconds ackDelay =
      (ackingTime > receivedTime
           ? std::chrono::duration_cast<std::chrono::microseconds>(
                 ackingTime - receivedTime)
           : 0us);

  WriteAckFrameMetaData meta = {
      ackState_, /* ackState*/
      ackDelay, /* ackDelay */
      static_cast<uint8_t>(ackDelayExponentToUse), /* ackDelayExponent */
      conn_.connectionTime, /* connect timestamp */
  };

  folly::Optional<WriteAckFrameResult> ackWriteResult;

  bool isAckReceiveTimestampsSupported =
      conn_.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer &&
      conn_.maybePeerAckReceiveTimestampsConfig;

  uint64_t peerRequestedTimestampsCount =
      conn_.maybePeerAckReceiveTimestampsConfig.has_value()
      ? conn_.maybePeerAckReceiveTimestampsConfig.value()
            .maxReceiveTimestampsPerAck
      : 0;

  // If ack_receive_timestamps are not enabled on *either* end-points OR
  // the peer requests 0 timestamps, we fall-back to using FrameType::ACK
  if (!isAckReceiveTimestampsSupported || !peerRequestedTimestampsCount) {
    ackWriteResult = writeAckFrame(meta, builder, FrameType::ACK);
  } else {
    ackWriteResult = writeAckFrameWithReceivedTimestamps(
        meta,
        builder,
        conn_.transportSettings.maybeAckReceiveTimestampsConfigSentToPeer
            .value(),
        peerRequestedTimestampsCount);
  }
  if (!ackWriteResult) {
    return folly::none;
  }
  return largestAckedPacketNum;
}

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

PingFrameScheduler::PingFrameScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool PingFrameScheduler::hasPingFrame() const {
  return conn_.pendingEvents.sendPing;
}

bool PingFrameScheduler::writePing(PacketBuilderInterface& builder) {
  return 0 != writeFrame(PingFrame(), builder);
}

DatagramFrameScheduler::DatagramFrameScheduler(QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool DatagramFrameScheduler::hasPendingDatagramFrames() const {
  return !conn_.datagramState.writeBuffer.empty();
}

bool DatagramFrameScheduler::writeDatagramFrames(
    PacketBuilderInterface& builder) {
  bool sent = false;
  for (size_t i = 0; i <= conn_.datagramState.writeBuffer.size(); ++i) {
    auto& payload = conn_.datagramState.writeBuffer.front();
    auto len = payload.chainLength();
    uint64_t spaceLeft = builder.remainingSpaceInPkt();
    QuicInteger frameTypeQuicInt(static_cast<uint8_t>(FrameType::DATAGRAM_LEN));
    QuicInteger datagramLenInt(len);
    auto datagramFrameLength =
        frameTypeQuicInt.getSize() + len + datagramLenInt.getSize();
    if (folly::to<uint64_t>(datagramFrameLength) <= spaceLeft) {
      auto datagramFrame = DatagramFrame(len, payload.move());
      auto res = writeFrame(datagramFrame, builder);
      // Must always succeed since we have already checked that there is enough
      // space to write the frame
      CHECK_GT(res, 0);
      QUIC_STATS(conn_.statsCallback, onDatagramWrite, len);
      conn_.datagramState.writeBuffer.pop_front();
      sent = true;
    }
    if (conn_.transportSettings.datagramConfig.framePerPacket) {
      break;
    }
  }
  return sent;
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
  return !conn_.streamManager->blockedStreams().empty() ||
      conn_.pendingEvents.sendDataBlocked;
}

void BlockedScheduler::writeBlockedFrames(PacketBuilderInterface& builder) {
  if (conn_.pendingEvents.sendDataBlocked) {
    // Connection is write blocked due to connection level flow control.
    DataBlockedFrame blockedFrame(
        conn_.flowControlState.peerAdvertisedMaxOffset);
    auto result = writeFrame(blockedFrame, builder);
    if (!result) {
      // If there is not enough room to write data blocked frame in the
      // current packet, we won't be able to write stream blocked frames either
      // so just return.
      return;
    }
  }
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

ImmediateAckFrameScheduler::ImmediateAckFrameScheduler(
    const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool ImmediateAckFrameScheduler::hasPendingImmediateAckFrame() const {
  return conn_.pendingEvents.requestImmediateAck;
}

bool ImmediateAckFrameScheduler::writeImmediateAckFrame(
    PacketBuilderInterface& builder) {
  return 0 != writeFrame(ImmediateAckFrame(), builder);
}

CloningScheduler::CloningScheduler(
    FrameScheduler& scheduler,
    QuicConnectionStateBase& conn,
    const folly::StringPiece name,
    uint64_t cipherOverhead)
    : frameScheduler_(scheduler),
      conn_(conn),
      name_(name),
      cipherOverhead_(cipherOverhead) {}

bool CloningScheduler::hasData() const {
  return frameScheduler_.hasData() ||
      conn_.outstandings.numOutstanding() > conn_.outstandings.dsrCount;
}

SchedulingResult CloningScheduler::scheduleFramesForPacket(
    PacketBuilderInterface&& builder,
    uint32_t writableBytes) {
  // The writableBytes in this function shouldn't be limited by cwnd, since
  // we only use CloningScheduler for the cases that we want to bypass cwnd for
  // now.
  bool hasData = frameScheduler_.hasData();
  if (conn_.version.has_value() &&
      conn_.version.value() != QuicVersion::QUIC_V1) {
    hasData = frameScheduler_.hasImmediateData();
  }
  if (hasData) {
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
  for (auto& outstandingPacket : conn_.outstandings.packets) {
    if (outstandingPacket.declaredLost || outstandingPacket.isDSRPacket) {
      continue;
    }
    auto opPnSpace = outstandingPacket.packet.header.getPacketNumberSpace();
    // Reusing the RegularQuicPacketBuilder throughout loop bodies will lead to
    // frames belong to different original packets being written into the same
    // clone packet. So re-create a RegularQuicPacketBuilder every time.
    // TODO: We can avoid the copy & rebuild of the header by creating an
    // independent header builder.
    auto builderPnSpace = builder.getPacketHeader().getPacketNumberSpace();
    if (opPnSpace != builderPnSpace) {
      continue;
    }
    size_t prevSize = 0;
    if (conn_.transportSettings.dataPathType ==
        DataPathType::ContinuousMemory) {
      ScopedBufAccessor scopedBufAccessor(conn_.bufAccessor);
      prevSize = scopedBufAccessor.buf()->length();
    }
    // Reusing the same builder throughout loop bodies will lead to frames
    // belong to different original packets being written into the same clone
    // packet. So re-create a builder every time.
    std::unique_ptr<PacketBuilderInterface> internalBuilder;
    if (conn_.transportSettings.dataPathType == DataPathType::ChainedMemory) {
      internalBuilder = std::make_unique<RegularQuicPacketBuilder>(
          conn_.udpSendPacketLen,
          header,
          getAckState(conn_, builderPnSpace).largestAckedByPeer.value_or(0));
    } else {
      CHECK(conn_.bufAccessor && conn_.bufAccessor->ownsBuffer());
      internalBuilder = std::make_unique<InplaceQuicPacketBuilder>(
          *conn_.bufAccessor,
          conn_.udpSendPacketLen,
          header,
          getAckState(conn_, builderPnSpace).largestAckedByPeer.value_or(0));
    }
    // If the packet is already a clone that has been processed, we don't clone
    // it again.
    if (outstandingPacket.associatedEvent &&
        conn_.outstandings.packetEvents.count(
            *outstandingPacket.associatedEvent) == 0) {
      continue;
    }
    // I think this only fail if udpSendPacketLen somehow shrinks in the middle
    // of a connection.
    if (outstandingPacket.metadata.encodedSize >
        writableBytes + cipherOverhead_) {
      continue;
    }

    internalBuilder->accountForCipherOverhead(cipherOverhead_);
    internalBuilder->encodePacketHeader();
    PacketRebuilder rebuilder(*internalBuilder, conn_);

    // TODO: It's possible we write out a packet that's larger than the packet
    // size limit. For example, when the packet sequence number has advanced to
    // a point where we need more bytes to encoded it than that of the original
    // packet. In that case, if the original packet is already at the packet
    // size limit, we will generate a packet larger than the limit. We can
    // either ignore the problem, hoping the packet will be able to travel the
    // network just fine; Or we can throw away the built packet and send a ping.

    // Rebuilder will write the rest of frames
    auto rebuildResult = rebuilder.rebuildFromPacket(outstandingPacket);
    if (rebuildResult) {
      return SchedulingResult(
          std::move(rebuildResult), std::move(*internalBuilder).buildPacket());
    } else if (
        conn_.transportSettings.dataPathType ==
        DataPathType::ContinuousMemory) {
      // When we use Inplace packet building and reuse the write buffer, even if
      // the packet rebuild has failed, there might be some bytes already
      // written into the buffer and the buffer tail pointer has already moved.
      // We need to roll back the tail pointer to the position before the packet
      // building to exclude those bytes. Otherwise these bytes will be sitting
      // in between legit packets inside the buffer and will either cause errors
      // further down the write path, or be sent out and then dropped at peer
      // when peer fail to parse them.
      internalBuilder.reset();
      CHECK(conn_.bufAccessor && conn_.bufAccessor->ownsBuffer());
      ScopedBufAccessor scopedBufAccessor(conn_.bufAccessor);
      auto& buf = scopedBufAccessor.buf();
      buf->trimEnd(buf->length() - prevSize);
    }
  }
  return SchedulingResult(folly::none, folly::none);
}

folly::StringPiece CloningScheduler::name() const {
  return name_;
}

} // namespace quic
