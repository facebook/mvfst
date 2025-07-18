/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/dsr/frontend/Scheduler.h>
#include <quic/dsr/frontend/WriteCodec.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

DSRStreamFrameScheduler::DSRStreamFrameScheduler(
    QuicServerConnectionState& conn)
    : conn_(conn) {}

bool DSRStreamFrameScheduler::hasPendingData() const {
  return !nextStreamNonDsr_ &&
      (conn_.streamManager->hasDSRLoss() ||
       (conn_.streamManager->hasDSRWritable() &&
        getSendConnFlowControlBytesWire(conn_) > 0));
}

DSRStreamFrameScheduler::SchedulingResult
DSRStreamFrameScheduler::enrichAndAddSendInstruction(
    uint32_t encodedSize,
    DSRStreamFrameScheduler::SchedulingResult result,
    DSRPacketBuilderBase& packetBuilder,
    SendInstruction::Builder& instructionBuilder,
    const deprecated::PriorityQueue& writeQueue,
    const deprecated::PriorityQueue::LevelItr& levelIter,
    QuicStreamState& stream) {
  enrichInstruction(instructionBuilder, stream);
  packetBuilder.addSendInstruction(
      instructionBuilder.build(), encodedSize, stream.streamPacketIdx++);
  result.writeSuccess = true;
  result.sender = stream.dsrSender.get();
  levelIter->iterator->next();
  auto nextStreamId = writeQueue.getNextScheduledStream();
  auto nextStream =
      CHECK_NOTNULL(conn_.streamManager->findStream(nextStreamId));
  if (nextStream->hasSchedulableData()) {
    nextStreamNonDsr_ = true;
  }
  return result;
}

DSRStreamFrameScheduler::SchedulingResult
DSRStreamFrameScheduler::enrichAndAddSendInstruction(
    uint32_t encodedSize,
    DSRStreamFrameScheduler::SchedulingResult result,
    DSRPacketBuilderBase& packetBuilder,
    SendInstruction::Builder& instructionBuilder,
    const PriorityQueue& writeQueue,
    QuicStreamState& stream) {
  enrichInstruction(instructionBuilder, stream);
  packetBuilder.addSendInstruction(
      instructionBuilder.build(), encodedSize, stream.streamPacketIdx++);
  result.writeSuccess = true;
  result.sender = stream.dsrSender.get();
  auto id = writeQueue.peekNextScheduledID();
  CHECK(id.isStreamID());
  auto nextStreamId = id.asStreamID();
  auto nextStream =
      CHECK_NOTNULL(conn_.streamManager->findStream(nextStreamId));
  if (nextStream->hasSchedulableData()) {
    nextStreamNonDsr_ = true;
  }
  return result;
}

/**
 * Note the difference between this and the regular StreamFrameScheduler.
 * There is no current way of knowing if two streams can be DSR-ed from the
 * same backend. Thus one SendInstruction can only have one stream. So this API
 * only write a single stream.
 */
quic::Expected<DSRStreamFrameScheduler::SchedulingResult, QuicError>
DSRStreamFrameScheduler::writeStream(DSRPacketBuilderBase& builder) {
  auto oldWriteQueue = conn_.streamManager->oldWriteQueue();
  if (oldWriteQueue) {
    return writeStreamImpl(builder, *oldWriteQueue);
  } else {
    return writeStreamImpl(builder, conn_.streamManager->writeQueue());
  }
}

quic::Expected<DSRStreamFrameScheduler::SchedulingResult, QuicError>
DSRStreamFrameScheduler::writeStreamImpl(
    DSRPacketBuilderBase& builder,
    PriorityQueue& writeQueue) {
  SchedulingResult result;
  if (writeQueue.empty()) {
    return result;
  }
  auto txn = writeQueue.beginTransaction();
  auto guard =
      folly::makeGuard([&] { writeQueue.rollbackTransaction(std::move(txn)); });
  auto id = writeQueue.getNextScheduledID(std::nullopt);
  CHECK(id.isStreamID());
  auto streamId = id.asStreamID();
  auto stream = conn_.streamManager->findStream(streamId);
  CHECK(stream);
  if (!stream->dsrSender || !stream->hasSchedulableDsr()) {
    nextStreamNonDsr_ = true;
    return result;
  }
  bool hasFreshBufMeta = stream->writeBufMeta.length > 0;
  bool hasLossBufMeta = !stream->lossBufMetas.empty();
  CHECK(stream->hasSchedulableDsr());
  if (hasLossBufMeta) {
    SendInstruction::Builder instructionBuilder(conn_, streamId);
    auto encodedSizeExpected = writeDSRStreamFrame(
        builder,
        instructionBuilder,
        streamId,
        stream->lossBufMetas.front().offset,
        stream->lossBufMetas.front().length,
        stream->lossBufMetas.front()
            .length, // flowControlLen shouldn't be used to limit loss write
        stream->lossBufMetas.front().eof,
        stream->currentWriteOffset + stream->pendingWrites.chainLength());
    if (encodedSizeExpected.hasError()) {
      return quic::make_unexpected(encodedSizeExpected.error());
    }

    auto encodedSize = encodedSizeExpected.value();
    if (encodedSize > 0) {
      if (builder.remainingSpace() < encodedSize) {
        return result;
      }
      guard.dismiss();
      writeQueue.commitTransaction(std::move(txn));
      return enrichAndAddSendInstruction(
          encodedSize,
          std::move(result),
          builder,
          instructionBuilder,
          writeQueue,
          *stream);
    }
  }
  if (!hasFreshBufMeta || builder.remainingSpace() == 0) {
    return result;
  }
  // If we have fresh BufMeta to write, the offset cannot be 0. This is based on
  // the current limit that some real data has to be written into the stream
  // before BufMetas.
  CHECK_NE(stream->writeBufMeta.offset, 0);
  uint64_t connWritableBytes = getSendConnFlowControlBytesWire(conn_);
  if (connWritableBytes == 0) {
    return result;
  }
  // When stream still has pendingWrites, getSendStreamFlowControlBytesWire
  // counts from currentWriteOffset which isn't right for BufMetas.
  auto streamFlowControlLen = std::min(
      getSendStreamFlowControlBytesWire(*stream),
      stream->flowControlState.peerAdvertisedMaxOffset -
          stream->writeBufMeta.offset);
  auto flowControlLen = std::min(streamFlowControlLen, connWritableBytes);
  bool canWriteFin = stream->finalWriteOffset.has_value() &&
      stream->writeBufMeta.length <= flowControlLen;
  SendInstruction::Builder instructionBuilder(conn_, streamId);
  auto encodedSizeExpected = writeDSRStreamFrame(
      builder,
      instructionBuilder,
      streamId,
      stream->writeBufMeta.offset,
      stream->writeBufMeta.length,
      flowControlLen,
      canWriteFin,
      stream->currentWriteOffset + stream->pendingWrites.chainLength());
  if (encodedSizeExpected.hasError()) {
    return quic::make_unexpected(encodedSizeExpected.error());
  }

  auto encodedSize = encodedSizeExpected.value();
  if (encodedSize > 0) {
    if (builder.remainingSpace() < encodedSize) {
      return result;
    }
    guard.dismiss();
    writeQueue.commitTransaction(std::move(txn));
    return enrichAndAddSendInstruction(
        encodedSize,
        std::move(result),
        builder,
        instructionBuilder,
        writeQueue,
        *stream);
  }
  return result;
}

quic::Expected<DSRStreamFrameScheduler::SchedulingResult, QuicError>
DSRStreamFrameScheduler::writeStreamImpl(
    DSRPacketBuilderBase& builder,
    const deprecated::PriorityQueue& writeQueue) {
  SchedulingResult result;
  const auto& levelIter = std::find_if(
      writeQueue.levels.cbegin(),
      writeQueue.levels.cend(),
      [&](const auto& level) { return !level.empty(); });
  if (levelIter == writeQueue.levels.cend()) {
    return result;
  }
  levelIter->iterator->begin();
  auto streamId = levelIter->iterator->current();
  auto stream = conn_.streamManager->findStream(streamId);
  CHECK(stream);
  if (!stream->dsrSender || !stream->hasSchedulableDsr()) {
    nextStreamNonDsr_ = true;
    return result;
  }
  bool hasFreshBufMeta = stream->writeBufMeta.length > 0;
  bool hasLossBufMeta = !stream->lossBufMetas.empty();
  CHECK(stream->hasSchedulableDsr());
  if (hasLossBufMeta) {
    SendInstruction::Builder instructionBuilder(conn_, streamId);
    auto encodedSizeExpected = writeDSRStreamFrame(
        builder,
        instructionBuilder,
        streamId,
        stream->lossBufMetas.front().offset,
        stream->lossBufMetas.front().length,
        stream->lossBufMetas.front()
            .length, // flowControlLen shouldn't be used to limit loss write
        stream->lossBufMetas.front().eof,
        stream->currentWriteOffset + stream->pendingWrites.chainLength());

    if (encodedSizeExpected.hasError()) {
      return quic::make_unexpected(encodedSizeExpected.error());
    }

    auto encodedSize = encodedSizeExpected.value();
    if (encodedSize > 0) {
      if (builder.remainingSpace() < encodedSize) {
        return result;
      }
      return enrichAndAddSendInstruction(
          encodedSize,
          std::move(result),
          builder,
          instructionBuilder,
          writeQueue,
          levelIter,
          *stream);
    }
  }
  if (!hasFreshBufMeta || builder.remainingSpace() == 0) {
    return result;
  }
  // If we have fresh BufMeta to write, the offset cannot be 0. This is based on
  // the current limit that some real data has to be written into the stream
  // before BufMetas.
  CHECK_NE(stream->writeBufMeta.offset, 0);
  uint64_t connWritableBytes = getSendConnFlowControlBytesWire(conn_);
  if (connWritableBytes == 0) {
    return result;
  }
  // When stream still has pendingWrites, getSendStreamFlowControlBytesWire
  // counts from currentWriteOffset which isn't right for BufMetas.
  auto streamFlowControlLen = std::min(
      getSendStreamFlowControlBytesWire(*stream),
      stream->flowControlState.peerAdvertisedMaxOffset -
          stream->writeBufMeta.offset);
  auto flowControlLen = std::min(streamFlowControlLen, connWritableBytes);
  bool canWriteFin = stream->finalWriteOffset.has_value() &&
      stream->writeBufMeta.length <= flowControlLen;
  SendInstruction::Builder instructionBuilder(conn_, streamId);
  auto encodedSizeExpected = writeDSRStreamFrame(
      builder,
      instructionBuilder,
      streamId,
      stream->writeBufMeta.offset,
      stream->writeBufMeta.length,
      flowControlLen,
      canWriteFin,
      stream->currentWriteOffset + stream->pendingWrites.chainLength());

  if (encodedSizeExpected.hasError()) {
    return quic::make_unexpected(encodedSizeExpected.error());
  }

  auto encodedSize = encodedSizeExpected.value();
  if (encodedSize > 0) {
    if (builder.remainingSpace() < encodedSize) {
      return result;
    }
    return enrichAndAddSendInstruction(
        encodedSize,
        std::move(result),
        builder,
        instructionBuilder,
        writeQueue,
        levelIter,
        *stream);
  }
  return result;
}

void DSRStreamFrameScheduler::enrichInstruction(
    SendInstruction::Builder& builder,
    const QuicStreamState& stream) {
  builder.setPacketNum(getNextPacketNum(conn_, PacketNumberSpace::AppData))
      .setLargestAckedPacketNum(getAckState(conn_, PacketNumberSpace::AppData)
                                    .largestAckedByPeer.value_or(0));

  auto largestDeliverableOffset = getLargestDeliverableOffset(stream);
  if (largestDeliverableOffset) {
    builder.setLargestAckedStreamOffset(*largestDeliverableOffset);
  }
  // TODO set to actual write delay.
  builder.setWriteOffset(0us);
}

} // namespace quic
