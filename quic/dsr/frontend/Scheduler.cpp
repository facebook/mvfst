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
  return conn_.streamManager->hasDSRWritable() &&
      getSendConnFlowControlBytesWire(conn_) > 0;
}

/**
 * Note the difference between this and the regular StreamFrameScheduler.
 * There is no current way of knowing if two streams can be DSR-ed from the
 * same backend. Thus one SendInstruction can only have one stream. So this API
 * only write a single stream.
 */
DSRStreamFrameScheduler::SchedulingResult DSRStreamFrameScheduler::writeStream(
    DSRPacketBuilderBase& builder) {
  SchedulingResult result;
  auto& writableDSRStreams = conn_.streamManager->writableDSRStreams();
  const auto& levelIter = std::find_if(
      writableDSRStreams.levels.cbegin(),
      writableDSRStreams.levels.cend(),
      [&](const auto& level) { return !level.streams.empty(); });
  if (levelIter == writableDSRStreams.levels.cend()) {
    return result;
  }
  auto streamId = levelIter->streams.cbegin();
  auto stream = conn_.streamManager->findStream(*streamId);
  CHECK(stream);
  CHECK(stream->dsrSender);
  result.sender = stream->dsrSender.get();
  bool hasFreshBufMeta = stream->writeBufMeta.length > 0;
  bool hasLossBufMeta = !stream->lossBufMetas.empty();
  CHECK(hasFreshBufMeta || hasLossBufMeta);
  if (hasLossBufMeta) {
    SendInstruction::Builder instructionBuilder(conn_, *streamId);
    auto encodedSize = writeDSRStreamFrame(
        builder,
        instructionBuilder,
        *streamId,
        stream->lossBufMetas.front().offset,
        stream->lossBufMetas.front().length,
        stream->lossBufMetas.front()
            .length, // flowControlLen shouldn't be used to limit loss write
        stream->lossBufMetas.front().eof,
        stream->currentWriteOffset + stream->writeBuffer.chainLength());
    if (encodedSize > 0) {
      if (builder.remainingSpace() < encodedSize) {
        return result;
      }
      enrichInstruction(instructionBuilder, *stream);
      builder.addSendInstruction(instructionBuilder.build(), encodedSize);
      result.writeSuccess = true;
      return result;
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
  // When stream still has writeBuffer, getSendStreamFlowControlBytesWire counts
  // from currentWriteOffset which isn't right for BufMetas.
  auto streamFlowControlLen = std::min(
      getSendStreamFlowControlBytesWire(*stream),
      stream->flowControlState.peerAdvertisedMaxOffset -
          stream->writeBufMeta.offset);
  auto flowControlLen = std::min(streamFlowControlLen, connWritableBytes);
  bool canWriteFin = stream->finalWriteOffset.has_value() &&
      stream->writeBufMeta.length <= flowControlLen;
  SendInstruction::Builder instructionBuilder(conn_, *streamId);
  auto encodedSize = writeDSRStreamFrame(
      builder,
      instructionBuilder,
      *streamId,
      stream->writeBufMeta.offset,
      stream->writeBufMeta.length,
      flowControlLen,
      canWriteFin,
      stream->currentWriteOffset + stream->writeBuffer.chainLength());
  if (encodedSize > 0) {
    if (builder.remainingSpace() < encodedSize) {
      return result;
    }
    enrichInstruction(instructionBuilder, *stream);
    builder.addSendInstruction(instructionBuilder.build(), encodedSize);
    result.writeSuccess = true;
    return result;
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
}

} // namespace quic
