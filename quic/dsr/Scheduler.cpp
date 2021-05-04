/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/dsr/Scheduler.h>
#include <quic/dsr/WriteCodec.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/QuicStateFunctions.h>

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
bool DSRStreamFrameScheduler::writeStream(DSRPacketBuilderBase& builder) {
  auto& writableDSRStreams = conn_.streamManager->writableDSRStreams();
  const auto& levelIter = std::find_if(
      writableDSRStreams.levels.cbegin(),
      writableDSRStreams.levels.cend(),
      [&](const auto& level) { return !level.streams.empty(); });
  if (levelIter == writableDSRStreams.levels.cend()) {
    return false;
  }
  auto streamId = levelIter->streams.cbegin();
  auto stream = conn_.streamManager->findStream(*streamId);
  CHECK(stream);
  bool hasFreshBufMeta = stream->writeBufMeta.length > 0;
  bool hasLossBufMeta = !stream->lossBufMetas.empty();
  CHECK(hasFreshBufMeta || hasLossBufMeta);
  bool written = false;
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
        return false;
      }
      enrichInstruction(instructionBuilder);
      builder.addSendInstruction(instructionBuilder.build(), encodedSize);
      written = true;
    }
  }
  if (!hasFreshBufMeta || builder.remainingSpace() == 0) {
    return written;
  }
  uint64_t connWritableBytes = getSendConnFlowControlBytesWire(conn_);
  if (connWritableBytes == 0) {
    return written;
  }
  auto flowControlLen =
      std::min(getSendStreamFlowControlBytesWire(*stream), connWritableBytes);
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
      return written;
    }
    enrichInstruction(instructionBuilder);
    builder.addSendInstruction(instructionBuilder.build(), encodedSize);
    return true;
  }
  return written;
}

void DSRStreamFrameScheduler::enrichInstruction(
    SendInstruction::Builder& builder) {
  builder.setPacketNum(getNextPacketNum(conn_, PacketNumberSpace::AppData))
      .setLargestAckedPacketNum(getAckState(conn_, PacketNumberSpace::AppData)
                                    .largestAckedByPeer.value_or(0));
}

} // namespace quic
