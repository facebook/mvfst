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

namespace quic {

DSRStreamFrameScheduler::DSRStreamFrameScheduler(QuicConnectionStateBase& conn)
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
  uint64_t connWritableBytes = getSendConnFlowControlBytesWire(conn_);
  if (connWritableBytes == 0) {
    return false;
  }
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
  CHECK_GT(stream->writeBufMeta.length, 0);
  auto flowControlLen =
      std::min(getSendStreamFlowControlBytesWire(*stream), connWritableBytes);
  bool canWriteFin = stream->finalWriteOffset.has_value() &&
      stream->writeBufMeta.length <= flowControlLen;
  auto sendInstruction = writeDSRStreamFrame(
      builder,
      *streamId,
      stream->writeBufMeta.offset,
      stream->writeBufMeta.length,
      flowControlLen,
      canWriteFin);
  if (sendInstruction.has_value()) {
    builder.addSendInstruction(
        std::move(sendInstruction->sendInstruction),
        sendInstruction->encodedSize);
    return true;
  }
  return false;
}
} // namespace quic
