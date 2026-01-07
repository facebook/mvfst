/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicConstants.h>
#include <quic/api/QuicPacketScheduler.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/MvfstLogging.h>
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

    [[nodiscard]] const MapType::value_type& dereference() const {
      return *itr_;
    }

    [[nodiscard]] MapType::const_iterator rawIterator() const {
      return itr_;
    }

    [[nodiscard]] bool equal(const MiddleStartingIterator& other) const {
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

  [[nodiscard]] MiddleStartingIterator cbegin() const {
    return start_;
  }

  [[nodiscard]] MiddleStartingIterator cend() const {
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

FrameScheduler::Builder& FrameScheduler::Builder::pathValidationFrames(
    PathIdType pathId) {
  schedulePathValidationFramesForPathId_ = pathId;
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
  if (schedulePathValidationFramesForPathId_.has_value()) {
    scheduler.pathValidationFrameScheduler_.emplace(
        PathValidationFrameScheduler(
            conn_, schedulePathValidationFramesForPathId_.value()));
  }
  return scheduler;
}

FrameScheduler::FrameScheduler(
    folly::StringPiece name,
    QuicConnectionStateBase& conn)
    : name_(name), conn_(conn) {}

quic::Expected<SchedulingResult, QuicError>
FrameScheduler::scheduleFramesForPacket(
    PacketBuilderInterface&& builder,
    uint32_t writableBytes) {
  size_t shortHeaderPadding = 0;
  const ShortHeader* shortHeader = builder.getPacketHeader().asShort();
  const LongHeader* longHeader = builder.getPacketHeader().asLong();
  bool initialPacket =
      longHeader && longHeader->getHeaderType() == LongHeader::Types::Initial;
  auto encodeRes = builder.encodePacketHeader();
  if (!encodeRes.has_value()) {
    return quic::make_unexpected(encodeRes.error());
  }
  // Add fixed padding at start of short header packets if configured
  if (shortHeader && conn_.transportSettings.fixedShortHeaderPadding > 0) {
    for (size_t i = 0; i < conn_.transportSettings.fixedShortHeaderPadding;
         i++) {
      auto writeRes = writeFrame(PaddingFrame(), builder);
      if (!writeRes.has_value()) {
        return quic::make_unexpected(writeRes.error());
      }
    }
    shortHeaderPadding = conn_.transportSettings.fixedShortHeaderPadding;
  }
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
    auto cryptoDataRes = cryptoStreamScheduler_->writeCryptoData(wrapper);
    if (!cryptoDataRes.has_value()) {
      return quic::make_unexpected(cryptoDataRes.error());
    }
    cryptoDataWritten = cryptoDataRes.value();
  }
  if (rstScheduler_ && rstScheduler_->hasPendingRsts()) {
    auto rstWrittenRes = rstScheduler_->writeRsts(wrapper);
    if (!rstWrittenRes.has_value()) {
      return quic::make_unexpected(rstWrittenRes.error());
    }
    rstWritten = rstWrittenRes.value();
  }
  // Long time ago we decided RST has higher priority than Acks.
  if (hasPendingAcks()) {
    if (cryptoDataWritten || rstWritten) {
      // If packet has non ack data, it is subject to congestion control. We
      // need to use the wrapper/
      auto writeAcksRes = ackScheduler_->writeNextAcks(wrapper);
      if (!writeAcksRes.has_value()) {
        return quic::make_unexpected(writeAcksRes.error());
      }
    } else {
      // If we start with writing acks, we will let the ack scheduler write
      // up to the full packet space. If the ack bytes exceeds the writable
      // bytes, this will be a pure ack packet and it will skip congestion
      // controller. Otherwise, we will give other schedulers an opportunity to
      // write up to writable bytes.
      auto writeAcksRes = ackScheduler_->writeNextAcks(builder);
      if (!writeAcksRes.has_value()) {
        return quic::make_unexpected(writeAcksRes.error());
      }
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
    auto result = windowUpdateScheduler_->writeWindowUpdates(wrapper);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  }
  if (blockedScheduler_ && blockedScheduler_->hasPendingBlockedFrames()) {
    auto result = blockedScheduler_->writeBlockedFrames(wrapper);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
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
    auto result = streamFrameScheduler_->writeStreams(wrapper);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  }
  // When scheduleDatagramsWithStreams is enabled, datagrams are handled by
  // streamFrameScheduler above.
  if (datagramFrameScheduler_ &&
      !conn_.transportSettings.datagramConfig.scheduleDatagramsWithStreams &&
      datagramFrameScheduler_->hasPendingDatagramFrames()) {
    auto datagramRes = datagramFrameScheduler_->writeDatagramFrames(wrapper);
    if (!datagramRes.has_value()) {
      return quic::make_unexpected(datagramRes.error());
    }
  }

  bool hasPathProbingFrame = false;
  if (pathValidationFrameScheduler_) {
    if (pathValidationFrameScheduler_->hasPendingPathValidationFrames()) {
      pathValidationFrameScheduler_->writePathValidationFrames(wrapper);
      hasPathProbingFrame = true;
    }
  }

  if (builder.hasFramesPending()) {
    if (initialPacket || hasPathProbingFrame) {
      // This is the initial packet or a it has a path probing frame, we need to
      // fill er up.
      while (builder.remainingSpaceInPkt() > 0) {
        auto writeRes = writeFrame(PaddingFrame(), builder);
        if (!writeRes.has_value()) {
          return quic::make_unexpected(writeRes.error());
        }
      }
    }
    if (shortHeader) {
      size_t paddingModulo = conn_.transportSettings.paddingModulo;
      if (paddingModulo > 0) {
        size_t paddingIncrement = wrapper.remainingSpaceInPkt() % paddingModulo;
        for (size_t i = 0; i < paddingIncrement; i++) {
          auto writeRes = writeFrame(PaddingFrame(), builder);
          if (!writeRes.has_value()) {
            return quic::make_unexpected(writeRes.error());
          }
        }
        shortHeaderPadding += paddingIncrement;
      }
    }
  }

  return SchedulingResult(
      std::nullopt, std::move(builder).buildPacket(), shortHeaderPadding);
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
       immediateAckFrameScheduler_->hasPendingImmediateAckFrame()) ||
      (pathValidationFrameScheduler_ &&
       pathValidationFrameScheduler_->hasPendingPathValidationFrames());
}

folly::StringPiece FrameScheduler::name() const {
  return name_;
}

quic::Expected<bool, QuicError> StreamFrameScheduler::writeStreamLossBuffers(
    PacketBuilderInterface& builder,
    QuicStreamState& stream) {
  bool wroteStreamFrame = false;
  for (auto buffer = stream.lossBuffer.cbegin();
       buffer != stream.lossBuffer.cend();
       ++buffer) {
    auto bufferLen = buffer->data.chainLength();
    auto res = writeStreamFrameHeader(
        builder,
        stream.id,
        buffer->offset,
        bufferLen, // writeBufferLen -- only the len of the single buffer.
        bufferLen, // flowControlLen -- not relevant, already flow controlled.
        buffer->eof,
        std::nullopt /* skipLenHint */);
    if (!res.has_value()) {
      return quic::make_unexpected(res.error());
    }
    auto dataLen = *res;
    if (dataLen) {
      wroteStreamFrame = true;
      writeStreamFrameData(builder, buffer->data, *dataLen);
      MVVLOG(4) << "Wrote loss data for stream=" << stream.id
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

quic::Expected<StreamFrameScheduler::StreamWriteResult, QuicError>
StreamFrameScheduler::writeSingleStream(
    PacketBuilderInterface& builder,
    QuicStreamState& stream,
    uint64_t& connWritableBytes) {
  StreamWriteResult result = StreamWriteResult::NOT_LIMITED;
  if (!stream.lossBuffer.empty()) {
    auto writeResult = writeStreamLossBuffers(builder, stream);
    if (!writeResult.has_value()) {
      return quic::make_unexpected(writeResult.error());
    }
    if (!writeResult.value()) {
      return StreamWriteResult::PACKET_FULL;
    }
  }
  if (stream.hasWritableData(true)) {
    if (connWritableBytes > 0 || stream.hasWritableData(false)) {
      auto writeResult = writeStreamFrame(builder, stream, connWritableBytes);
      if (!writeResult.has_value()) {
        return quic::make_unexpected(writeResult.error());
      }
      if (!writeResult.value()) {
        return StreamWriteResult::PACKET_FULL;
      }
      result = (connWritableBytes == 0) ? StreamWriteResult::CONN_FC_LIMITED
                                        : StreamWriteResult::NOT_LIMITED;
    } else {
      result = StreamWriteResult::CONN_FC_LIMITED;
    }
  }
  return result;
}

quic::Expected<StreamId, QuicError> StreamFrameScheduler::writeStreamsHelper(
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
    MVCHECK(stream);
    auto writeResult = writeSingleStream(builder, *stream, connWritableBytes);
    if (!writeResult.has_value()) {
      return quic::make_unexpected(writeResult.error());
    }
    if (writeResult.value() == StreamWriteResult::PACKET_FULL) {
      break;
    }
    writableStreamItr++;
    if (streamPerPacket) {
      break;
    }
  }
  return *writableStreamItr;
}

// Helper to write a datagram from a flow
// Returns {buf, flowEmpty, datagramLen} - buf is nullptr if nothing written
static quic::Expected<DatagramFlowManager::DatagramPopResult, QuicError>
writeDatagramFrame(
    QuicConnectionStateBase& conn,
    uint32_t flowId,
    PacketBuilderInterface& builder) {
  // Try to pop the datagram if it fits (overhead calculated internally)
  auto popResult = conn.datagramState.flowManager.popDatagramIfFits(
      flowId, builder.remainingSpaceInPkt());

  if (!popResult.buf) {
    // Doesn't fit - return popResult as-is
    return popResult;
  }

  // Write the datagram frame
  auto datagramFrame =
      DatagramFrame(popResult.datagramLen, std::move(popResult.buf));
  auto res = writeFrame(datagramFrame, builder);
  if (!res.has_value()) {
    return quic::make_unexpected(res.error());
  }
  MVCHECK_GT(res.value(), 0);
  QUIC_STATS(conn.statsCallback, onDatagramWrite, popResult.datagramLen);
  // Return popResult directly; buf has been moved into the DatagramFrame above
  return popResult;
}

quic::Expected<void, QuicError> StreamFrameScheduler::writeStreamsHelper(
    PacketBuilderInterface& builder,
    PriorityQueue& writableStreams,
    uint64_t& connWritableBytes,
    bool streamPerPacket) {
  // Fill a packet with non-control stream data, in priority order
  //
  // The streams can have loss data or fresh data.  Once we run out of
  // conn flow control, we can only write loss data.  In order to
  // advance the write queue, we have to remove the elements.  Store
  // them in QuicStreamManager and re-insert when more f/c arrives
  while (!writableStreams.empty() && builder.remainingSpaceInPkt() > 0) {
    auto id = writableStreams.peekNextScheduledID();

    // Handle datagrams scheduled via PriorityQueue
    if (id.isDatagramFlowID()) {
      auto flowId = id.asDatagramFlowID();
      auto writeResult = writeDatagramFrame(conn_, flowId, builder);
      if (!writeResult.has_value()) {
        return quic::make_unexpected(writeResult.error());
      }
      auto& result = writeResult.value();
      if (result.datagramLen == 0) {
        // Front Datagram doesn't fit
        break;
      }
      // Successfully wrote datagram
      if (result.flowEmpty) {
        writableStreams.erase(id);
      } else {
        // Consume bytes written for fairness
        writableStreams.consume(result.datagramLen);
      }
      if (conn_.transportSettings.datagramConfig.framePerPacket) {
        break;
      }
    } else {
      // Handle streams
      MVCHECK(id.isStreamID());
      auto streamId = id.asStreamID();
      auto stream = MVCHECK_NOTNULL(conn_.streamManager->findStream(streamId));
      MVCHECK(stream, "streamId=" << streamId);
      // TODO: this is counting STREAM frame overhead against the stream itself
      auto lastWriteBytes = builder.remainingSpaceInPkt();
      auto writeResult = writeSingleStream(builder, *stream, connWritableBytes);
      if (!writeResult.has_value()) {
        return quic::make_unexpected(writeResult.error());
      }
      if (writeResult.value() == StreamWriteResult::PACKET_FULL) {
        break;
      }
      auto remainingSpaceAfter = builder.remainingSpaceInPkt();
      lastWriteBytes -= remainingSpaceAfter;
      // If we wrote a stream frame and there's still space in the packet,
      // that implies we ran out of data or flow control on the stream and
      // we should erase the stream from writableStreams, the caller can
      // rollback the transaction if the packet write fails
      if (remainingSpaceAfter > 0) {
        if (writeResult.value() == StreamWriteResult::CONN_FC_LIMITED) {
          conn_.streamManager->addConnFCBlockedStream(streamId);
        }
        writableStreams.erase(id);
      } else { // the loop will break
        writableStreams.consume(lastWriteBytes);
      }
      if (streamPerPacket) {
        return {};
      }
    }
  }
  return {};
}

quic::Expected<void, QuicError> StreamFrameScheduler::writeStreams(
    PacketBuilderInterface& builder) {
  MVDCHECK(conn_.streamManager->hasWritable());
  uint64_t connWritableBytes = getSendConnFlowControlBytesWire(conn_);
  // Write the control streams first as a naive binary priority mechanism.
  const auto& controlWriteQueue = conn_.streamManager->controlWriteQueue();
  if (!controlWriteQueue.empty()) {
    auto result = writeStreamsHelper(
        builder,
        controlWriteQueue,
        conn_.schedulingState.nextScheduledControlStream,
        connWritableBytes,
        conn_.transportSettings.streamFramePerPacket);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
    conn_.schedulingState.nextScheduledControlStream = result.value();
  }
  auto& writeQueue = conn_.streamManager->writeQueue();
  if (!writeQueue.empty()) {
    auto result = writeStreamsHelper(
        builder,
        writeQueue,
        connWritableBytes,
        conn_.transportSettings.streamFramePerPacket);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
  }
  return {};
}

bool StreamFrameScheduler::hasPendingData() const {
  return conn_.streamManager->hasLoss() ||
      (conn_.streamManager->hasWritable() &&
       getSendConnFlowControlBytesWire(conn_) > 0);
}

quic::Expected<bool, QuicError> StreamFrameScheduler::writeStreamFrame(
    PacketBuilderInterface& builder,
    QuicStreamState& stream,
    uint64_t& connWritableBytes) {
  if (builder.remainingSpaceInPkt() == 0) {
    return false;
  }

  // hasWritableData is the condition which has to be satisfied for the
  // stream to be in writableList
  MVCHECK(stream.hasWritableData());

  uint64_t flowControlLen =
      std::min(getSendStreamFlowControlBytesWire(stream), connWritableBytes);
  uint64_t bufferLen = stream.pendingWrites.chainLength();
  bool canWriteFin =
      stream.finalWriteOffset.has_value() && bufferLen <= flowControlLen;
  auto writeOffset = stream.currentWriteOffset;
  auto res = writeStreamFrameHeader(
      builder,
      stream.id,
      writeOffset,
      bufferLen,
      flowControlLen,
      canWriteFin,
      std::nullopt /* skipLenHint */);
  if (!res.has_value()) {
    return quic::make_unexpected(res.error());
  }
  auto dataLen = *res;
  if (!dataLen) {
    return false;
  }
  writeStreamFrameData(builder, stream.pendingWrites, *dataLen);
  MVVLOG(4) << "Wrote stream frame stream=" << stream.id
            << " offset=" << stream.currentWriteOffset
            << " bytesWritten=" << *dataLen
            << " finWritten=" << (canWriteFin && *dataLen == bufferLen) << " "
            << conn_;
  connWritableBytes -= dataLen.value();
  return true;
}

RstStreamScheduler::RstStreamScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool RstStreamScheduler::hasPendingRsts() const {
  return !conn_.pendingEvents.resets.empty();
}

quic::Expected<bool, QuicError> RstStreamScheduler::writeRsts(
    PacketBuilderInterface& builder) {
  bool rstWritten = false;
  for (const auto& resetStream : conn_.pendingEvents.resets) {
    auto streamId = resetStream.first;
    QuicStreamState* streamState =
        conn_.streamManager->getStream(streamId).value_or(nullptr);
    MVCHECK(
        streamState,
        "Stream " << streamId << " not found when going through resets");
    if (streamState->pendingWrites.empty()) {
      //    We only write a RESET_STREAM or RESET_STREAM_AT frame for a stream
      //    once we've written out all data that needs to be delivered reliably.
      //    While this is not something that's mandated by the spec, we're doing
      //    it in this implementation because it dramatically simplifies flow
      //    control accounting.
      auto bytesWrittenResult = writeFrame(resetStream.second, builder);
      if (!bytesWrittenResult.has_value()) {
        return quic::make_unexpected(bytesWrittenResult.error());
      }
      if (!bytesWrittenResult.value()) {
        break;
      }
      rstWritten = true;
    }
  }
  return rstWritten;
}

SimpleFrameScheduler::SimpleFrameScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool SimpleFrameScheduler::hasPendingSimpleFrames() const {
  return !conn_.pendingEvents.frames.empty();
}

bool SimpleFrameScheduler::writeSimpleFrames(PacketBuilderInterface& builder) {
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

PathValidationFrameScheduler::PathValidationFrameScheduler(
    const QuicConnectionStateBase& conn,
    PathIdType pathId)
    : conn_(conn), pathId_(pathId) {}

bool PathValidationFrameScheduler::hasPendingPathValidationFrames() const {
  return conn_.pendingEvents.pathChallenges.find(pathId_) !=
      conn_.pendingEvents.pathChallenges.end() ||
      conn_.pendingEvents.pathResponses.find(pathId_) !=
      conn_.pendingEvents.pathResponses.end();
}

bool PathValidationFrameScheduler::writePathValidationFrames(
    PacketBuilderInterface& builder) {
  bool framesWritten = false;

  // Write PathResponse frames for the specified path
  auto pathResponse = conn_.pendingEvents.pathResponses.find(pathId_);
  if (pathResponse != conn_.pendingEvents.pathResponses.end()) {
    if (!writeSimpleFrame(QuicSimpleFrame(pathResponse->second), builder)) {
      return false;
    }
    framesWritten = true;
  }

  // Write PathChallenge frames for the specified path
  auto pathChallenge = conn_.pendingEvents.pathChallenges.find(pathId_);
  if (pathChallenge != conn_.pendingEvents.pathChallenges.end()) {
    if (!writeSimpleFrame(QuicSimpleFrame(pathChallenge->second), builder)) {
      return false;
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
  auto writeFrameResult = writeFrame(PingFrame(), builder);
  // We shouldn't ever error on a PING.
  MVCHECK(writeFrameResult.has_value());
  return writeFrameResult.value() != 0;
}

DatagramFrameScheduler::DatagramFrameScheduler(QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool DatagramFrameScheduler::hasPendingDatagramFrames() const {
  return conn_.datagramState.flowManager.hasDatagramsToSend();
}

quic::Expected<bool, QuicError> DatagramFrameScheduler::writeDatagramFrames(
    PacketBuilderInterface& builder) {
  bool sent = false;

  // Write datagrams from default flow when not using PriorityQueue scheduling
  size_t maxIters = conn_.datagramState.flowManager.getDatagramCount();
  for (size_t i = 0; i < maxIters; ++i) {
    auto writeResult =
        writeDatagramFrame(conn_, kDefaultDatagramFlowId, builder);
    if (!writeResult.has_value()) {
      return quic::make_unexpected(writeResult.error());
    }
    if (writeResult->datagramLen == 0) {
      break;
    }
    sent = true;

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

quic::Expected<void, QuicError> WindowUpdateScheduler::writeWindowUpdates(
    PacketBuilderInterface& builder) {
  if (conn_.pendingEvents.connWindowUpdate) {
    auto maxDataFrame = generateMaxDataFrame(conn_);
    auto maximumData = maxDataFrame.maximumData;
    auto bytesResult = writeFrame(std::move(maxDataFrame), builder);
    if (!bytesResult.has_value()) {
      return quic::make_unexpected(bytesResult.error());
    }
    if (bytesResult.value()) {
      MVVLOG(4) << "Wrote max_data=" << maximumData << " " << conn_;
    }
  }
  for (const auto& windowUpdateStream : conn_.streamManager->windowUpdates()) {
    auto stream = conn_.streamManager->findStream(windowUpdateStream);
    if (!stream) {
      continue;
    }
    auto maxStreamDataFrame = generateMaxStreamDataFrame(*stream);
    auto maximumData = maxStreamDataFrame.maximumData;
    auto bytesResult = writeFrame(std::move(maxStreamDataFrame), builder);
    if (!bytesResult.has_value()) {
      return quic::make_unexpected(bytesResult.error());
    }
    if (!bytesResult.value()) {
      break;
    }
    MVVLOG(4) << "Wrote max_stream_data stream=" << stream->id
              << " maximumData=" << maximumData << " " << conn_;
  }
  return {};
}

BlockedScheduler::BlockedScheduler(const QuicConnectionStateBase& conn)
    : conn_(conn) {}

bool BlockedScheduler::hasPendingBlockedFrames() const {
  return !conn_.streamManager->blockedStreams().empty() ||
      conn_.pendingEvents.sendDataBlocked;
}

quic::Expected<void, QuicError> BlockedScheduler::writeBlockedFrames(
    PacketBuilderInterface& builder) {
  if (conn_.pendingEvents.sendDataBlocked) {
    // Connection is write blocked due to connection level flow control.
    DataBlockedFrame blockedFrame(
        conn_.flowControlState.peerAdvertisedMaxOffset);
    auto result = writeFrame(blockedFrame, builder);
    if (!result.has_value()) {
      return quic::make_unexpected(result.error());
    }
    if (!result.value()) {
      // If there is not enough room to write data blocked frame in the
      // current packet, we won't be able to write stream blocked frames either
      // so just return.
      return {};
    }
  }
  for (const auto& blockedStream : conn_.streamManager->blockedStreams()) {
    // Reconstruct frame from streamId (key) and offset (value)
    StreamDataBlockedFrame frame(blockedStream.first, blockedStream.second);
    auto bytesWrittenResult = writeFrame(frame, builder);
    if (!bytesWrittenResult.has_value()) {
      return quic::make_unexpected(bytesWrittenResult.error());
    }
    if (!bytesWrittenResult.value()) {
      break;
    }
  }
  return {};
}

CryptoStreamScheduler::CryptoStreamScheduler(
    const QuicConnectionStateBase& conn,
    const QuicCryptoStream& cryptoStream)
    : conn_(conn), cryptoStream_(cryptoStream) {}

quic::Expected<bool, QuicError> CryptoStreamScheduler::writeCryptoData(
    PacketBuilderInterface& builder) {
  bool cryptoDataWritten = false;
  uint64_t writableData = cryptoStream_.pendingWrites.chainLength();
  // We use the crypto scheduler to reschedule the retransmissions of the
  // crypto streams so that we know that retransmissions of the crypto data
  // will always take precedence over the crypto data.
  for (const auto& buffer : cryptoStream_.lossBuffer) {
    auto res = writeCryptoFrame(buffer.offset, buffer.data, builder);
    if (!res.has_value()) {
      return quic::make_unexpected(res.error());
    }
    if (!res.value()) {
      return cryptoDataWritten;
    }
    MVVLOG(4) << "Wrote retransmitted crypto" << " offset=" << buffer.offset
              << " bytes=" << res.value()->len << " " << conn_;
    cryptoDataWritten = true;
  }

  if (writableData != 0) {
    auto res = writeCryptoFrame(
        cryptoStream_.currentWriteOffset, cryptoStream_.pendingWrites, builder);
    if (!res.has_value()) {
      return quic::make_unexpected(res.error());
    }
    if (res.value()) {
      MVVLOG(4) << "Wrote crypto frame"
                << " offset=" << cryptoStream_.currentWriteOffset
                << " bytesWritten=" << res.value()->len << " " << conn_;
      cryptoDataWritten = true;
    }
  }
  return cryptoDataWritten;
}

bool CryptoStreamScheduler::hasData() const {
  return !cryptoStream_.pendingWrites.empty() ||
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
  auto result = writeFrame(ImmediateAckFrame(), builder);
  // We shouldn't ever error on an IMMEDIATE_ACK.
  MVCHECK(result.has_value());
  return result.value() != 0;
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
  return frameScheduler_.hasData() || conn_.outstandings.numOutstanding() > 0;
}

quic::Expected<SchedulingResult, QuicError>
CloningScheduler::scheduleFramesForPacket(
    PacketBuilderInterface&& builder,
    uint32_t writableBytes) {
  // Store header type information before any moves
  auto builderPnSpace = builder.getPacketHeader().getPacketNumberSpace();
  auto header = builder.getPacketHeader();
  // The writableBytes in this function shouldn't be limited by cwnd, since
  // we only use CloningScheduler for the cases that we want to bypass cwnd for
  // now.
  if (frameScheduler_.hasImmediateData()) {
    // If we have new ack-eliciting data to write, write that first.
    return frameScheduler_.scheduleFramesForPacket(
        std::move(builder), writableBytes);
  }
  // TODO: We can avoid the copy & rebuild of the header by creating an
  // independent header builder.
  std::move(builder).releaseOutputBuffer();
  // Look for an outstanding packet that's no larger than the writableBytes
  for (auto& outstandingPacket : conn_.outstandings.packets) {
    if (outstandingPacket.declaredLost) {
      continue;
    }
    auto opPnSpace = outstandingPacket.packet.header.getPacketNumberSpace();
    // Reusing the RegularQuicPacketBuilder throughout loop bodies will lead to
    // frames belong to different original packets being written into the same
    // clone packet. So re-create a RegularQuicPacketBuilder every time.
    // TODO: We can avoid the copy & rebuild of the header by creating an
    // independent header builder.
    if (opPnSpace != builderPnSpace) {
      continue;
    }
    size_t prevSize = 0;
    if (conn_.transportSettings.dataPathType ==
        DataPathType::ContinuousMemory) {
      prevSize = conn_.bufAccessor->length();
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
      MVCHECK(conn_.bufAccessor && conn_.bufAccessor->ownsBuffer());
      internalBuilder = std::make_unique<InplaceQuicPacketBuilder>(
          *conn_.bufAccessor,
          conn_.udpSendPacketLen,
          header,
          getAckState(conn_, builderPnSpace).largestAckedByPeer.value_or(0));
    }
    // The packet is already a clone or has a clone outstanding
    if (outstandingPacket.maybeClonedPacketIdentifier) {
      const auto& frames = outstandingPacket.packet.frames;
      if (conn_.transportSettings.cloneAllPacketsWithCryptoFrame) {
        // Has CRYPTO frame
        if (std::find_if(frames.begin(), frames.end(), [](const auto& frame) {
              return frame.type() == QuicWriteFrame::Type::WriteCryptoFrame;
            }) != frames.end()) {
          if (conn_.transportSettings.cloneCryptoPacketsAtMostOnce) {
            continue;
          }
          auto mostRecentOutstandingPacketIdentifier =
              conn_.outstandings.packets.back().maybeClonedPacketIdentifier;
          if (mostRecentOutstandingPacketIdentifier ==
              outstandingPacket.maybeClonedPacketIdentifier) {
            continue;
          }
        }
      }
      // This packet has already been processed (acked/lost), no need to
      // clone it.
      if (conn_.outstandings.clonedPacketIdentifiers.count(
              *outstandingPacket.maybeClonedPacketIdentifier) == 0) {
        continue;
      }

      // Check if we've already cloned this packet in this write loop. We don't
      // need to clone it again.
      bool alreadyClonedThisWrite = [&]() -> bool {
        if (conn_.transportSettings.allowDuplicateProbesInSameWrite) {
          // Allow the duplicate clone anyway if we explicitly want it.
          return false;
        }
        for (auto it = conn_.outstandings.packets.rbegin();
             it != conn_.outstandings.packets.rend();
             ++it) {
          // Break early if we've gone past the current write loop
          if (it->metadata.writeCount < conn_.writeCount) {
            return false;
          }
          if (it->metadata.writeCount == conn_.writeCount &&
              it->maybeClonedPacketIdentifier &&
              it->maybeClonedPacketIdentifier ==
                  outstandingPacket.maybeClonedPacketIdentifier) {
            return true;
          }
        }
        return false;
      }();

      if (alreadyClonedThisWrite) {
        continue;
      }
    }
    // I think this only fail if udpSendPacketLen somehow shrinks in the
    // middle of a connection.
    if (outstandingPacket.metadata.encodedSize >
        writableBytes + cipherOverhead_) {
      continue;
    }

    internalBuilder->accountForCipherOverhead(cipherOverhead_);
    auto encodeRes = internalBuilder->encodePacketHeader();
    if (!encodeRes.has_value()) {
      return quic::make_unexpected(encodeRes.error());
    }
    PacketRebuilder rebuilder(*internalBuilder, conn_);

    // TODO: It's possible we write out a packet that's larger than the
    // packet size limit. For example, when the packet sequence number
    // has advanced to a point where we need more bytes to encoded it
    // than that of the original packet. In that case, if the original
    // packet is already at the packet size limit, we will generate a
    // packet larger than the limit. We can either ignore the problem,
    // hoping the packet will be able to travel the network just fine;
    // Or we can throw away the built packet and send a ping.

    // Rebuilder will write the rest of frames
    auto rebuildResultExpected = rebuilder.rebuildFromPacket(outstandingPacket);
    if (!rebuildResultExpected.has_value()) {
      return quic::make_unexpected(rebuildResultExpected.error());
    }
    if (rebuildResultExpected.value()) {
      return SchedulingResult(
          std::move(rebuildResultExpected.value()),
          std::move(*internalBuilder).buildPacket(),
          0);
    } else if (
        conn_.transportSettings.dataPathType ==
        DataPathType::ContinuousMemory) {
      // When we use Inplace packet building and reuse the write buffer,
      // even if the packet rebuild has failed, there might be some
      // bytes already written into the buffer and the buffer tail
      // pointer has already moved. We need to roll back the tail
      // pointer to the position before the packet building to exclude
      // those bytes. Otherwise these bytes will be sitting in between
      // legit packets inside the buffer and will either cause errors
      // further down the write path, or be sent out and then dropped at
      // peer when peer fail to parse them.
      internalBuilder.reset();
      MVCHECK(conn_.bufAccessor && conn_.bufAccessor->ownsBuffer());
      conn_.bufAccessor->trimEnd(conn_.bufAccessor->length() - prevSize);
    }
  }
  return SchedulingResult(std::nullopt, std::nullopt, 0);
}

folly::StringPiece CloningScheduler::name() const {
  return name_;
}

} // namespace quic
