/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicPacketRebuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>

namespace quic {

PacketRebuilder::PacketRebuilder(
    PacketBuilderInterface& regularBuilder,
    QuicConnectionStateBase& conn)
    : builder_(regularBuilder), conn_(conn) {}

uint64_t PacketRebuilder::getHeaderBytes() const {
  return builder_.getHeaderBytes();
}

PacketEvent PacketRebuilder::cloneOutstandingPacket(OutstandingPacket& packet) {
  // Either the packet has never been cloned before, or it's associatedEvent is
  // still in the outstandings.packetEvents set.
  DCHECK(
      !packet.associatedEvent ||
      conn_.outstandings.packetEvents.count(*packet.associatedEvent));
  if (!packet.associatedEvent) {
    auto packetNum = packet.packet.header.getPacketSequenceNum();
    auto packetNumberSpace = packet.packet.header.getPacketNumberSpace();
    PacketEvent event(packetNumberSpace, packetNum);
    DCHECK(!conn_.outstandings.packetEvents.count(event));
    packet.associatedEvent = event;
    conn_.outstandings.packetEvents.insert(event);
    ++conn_.outstandings
          .clonedPacketCount[packet.packet.header.getPacketNumberSpace()];
  }
  return *packet.associatedEvent;
}

folly::Optional<PacketEvent> PacketRebuilder::rebuildFromPacket(
    OutstandingPacket& packet) {
  // TODO: if PMTU changes between the transmission of the original packet and
  // now, then we cannot clone everything in the packet.

  bool writeSuccess = false;
  bool windowUpdateWritten = false;
  bool shouldWriteWindowUpdate = false;
  bool notPureAck = false;
  bool shouldRebuildWriteAckFrame = false;
  auto encryptionLevel =
      protectionTypeToEncryptionLevel(packet.packet.header.getProtectionType());
  // First check if there's an ACK in this packet. We do this because we need
  // to know before we rebuild a stream frame whether there is an ACK in this
  // packet. If there is an ACK, we have to always encode the stream frame's
  // length. This forces the associatedEvent code to reconsider the packet for
  // ACK processing. We should always be able to write an ACK since the min
  // ACK frame size is 4, while 1500 MTU stream frame lengths are going to be
  // 2 bytes maximum.
  bool hasAckFrame = false;
  for (const auto& frame : packet.packet.frames) {
    if (frame.asWriteAckFrame()) {
      hasAckFrame = true;
      break;
    }
  }
  for (auto iter = packet.packet.frames.cbegin();
       iter != packet.packet.frames.cend();
       iter++) {
    bool lastFrame = iter == packet.packet.frames.cend() - 1;
    const QuicWriteFrame& frame = *iter;
    switch (frame.type()) {
      case QuicWriteFrame::Type::WriteAckFrame: {
        // We need to rebuild this WriteAckFrame with fresh AckStats
        // which may make the packet larger. We keep track of this
        // for now and rebuild the frame after the loop.
        shouldRebuildWriteAckFrame = true;
        break;
      }
      case QuicWriteFrame::Type::WriteStreamFrame: {
        const WriteStreamFrame& streamFrame = *frame.asWriteStreamFrame();
        auto stream = conn_.streamManager->getStream(streamFrame.streamId);
        if (stream && retransmittable(*stream)) {
          auto streamData = cloneRetransmissionBuffer(streamFrame, stream);
          auto bufferLen = streamData ? streamData->chainLength() : 0;
          auto dataLen = writeStreamFrameHeader(
              builder_,
              streamFrame.streamId,
              streamFrame.offset,
              bufferLen,
              bufferLen,
              streamFrame.fin,
              // It's safe to skip the length if it was the last frame in the
              // original packet and there's no ACK frame. Since we put the ACK
              // frame last we need to end the stream frame in that case.
              lastFrame && bufferLen && !hasAckFrame,
              streamFrame.streamGroupId);
          bool ret = dataLen.has_value() && *dataLen == streamFrame.len;
          if (ret) {
            // Writing 0 byte for stream data is legit if the stream frame has
            // FIN. That's checked in writeStreamFrameHeader.
            CHECK(streamData || streamFrame.fin);
            if (streamData) {
              writeStreamFrameData(builder_, *streamData, *dataLen);
            }
            notPureAck = true;
            writeSuccess = true;
            break;
          }
          writeSuccess = false;
          break;
        }
        // If a stream is already Closed, we should not clone and resend this
        // stream data. But should we abort the cloning of this packet and
        // move on to the next packet? I'm gonna err on the aggressive side
        // for now and call it success.
        writeSuccess = true;
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
        const WriteCryptoFrame& cryptoFrame = *frame.asWriteCryptoFrame();
        auto stream = getCryptoStream(*conn_.cryptoState, encryptionLevel);
        auto buf = cloneCryptoRetransmissionBuffer(cryptoFrame, *stream);

        // No crypto data found to be cloned, just skip
        if (!buf) {
          writeSuccess = true;
          break;
        }
        auto cryptoWriteResult =
            writeCryptoFrame(cryptoFrame.offset, *buf, builder_);
        bool ret = cryptoWriteResult.has_value() &&
            cryptoWriteResult->offset == cryptoFrame.offset &&
            cryptoWriteResult->len == cryptoFrame.len;
        notPureAck |= ret;
        writeSuccess = ret;
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        shouldWriteWindowUpdate = true;
        auto ret = 0 != writeFrame(generateMaxDataFrame(conn_), builder_);
        windowUpdateWritten |= ret;
        notPureAck |= ret;
        writeSuccess = true;
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& maxStreamDataFrame =
            *frame.asMaxStreamDataFrame();
        auto stream =
            conn_.streamManager->getStream(maxStreamDataFrame.streamId);
        if (!stream || !stream->shouldSendFlowControl()) {
          writeSuccess = true;
          break;
        }
        shouldWriteWindowUpdate = true;
        auto ret =
            0 != writeFrame(generateMaxStreamDataFrame(*stream), builder_);
        windowUpdateWritten |= ret;
        notPureAck |= ret;
        writeSuccess = true;
        break;
      }
      case QuicWriteFrame::Type::PaddingFrame: {
        const PaddingFrame& paddingFrame = *frame.asPaddingFrame();
        writeSuccess = writeFrame(paddingFrame, builder_) != 0;
        break;
      }
      case QuicWriteFrame::Type::PingFrame: {
        const PingFrame& pingFrame = *frame.asPingFrame();
        writeSuccess = writeFrame(pingFrame, builder_) != 0;
        break;
      }
      case QuicWriteFrame::Type::QuicSimpleFrame: {
        const QuicSimpleFrame& simpleFrame = *frame.asQuicSimpleFrame();
        auto updatedSimpleFrame =
            updateSimpleFrameOnPacketClone(conn_, simpleFrame);
        if (!updatedSimpleFrame) {
          writeSuccess = true;
          break;
        }
        bool ret =
            writeSimpleFrame(std::move(*updatedSimpleFrame), builder_) != 0;
        notPureAck |= ret;
        writeSuccess = ret;
        break;
      }
      case QuicWriteFrame::Type::DatagramFrame:
        // Do not clone Datagram frames. If datagram frame is the only frame in
        // the packet, notPureAck will be false, and the function will return
        // folly::none correctly.
        writeSuccess = true;
        break;
      default: {
        bool ret = writeFrame(QuicWriteFrame(frame), builder_) != 0;
        notPureAck |= ret;
        writeSuccess = ret;
        break;
      }
    }
    if (!writeSuccess) {
      return folly::none;
    }
  }
  // If this packet had a WriteAckFrame, build a new one it with
  // fresh AckState on best-effort basis. If writing
  // that ACK fails, just ignore it and use the rest of the
  // cloned packet.
  if (shouldRebuildWriteAckFrame) {
    auto& packetHeader = builder_.getPacketHeader();
    uint64_t ackDelayExponent =
        (packetHeader.getHeaderForm() == HeaderForm::Long)
        ? kDefaultAckDelayExponent
        : conn_.transportSettings.ackDelayExponent;
    const AckState& ackState_ = getAckState(
        conn_,
        protectionTypeToPacketNumberSpace(packetHeader.getProtectionType()));
    auto ackingTime = Clock::now();
    DCHECK(ackState_.largestRecvdPacketTime.hasValue())
        << "Missing received time for the largest acked packet";
    auto receivedTime = *ackState_.largestRecvdPacketTime;
    std::chrono::microseconds ackDelay =
        (ackingTime > receivedTime
             ? std::chrono::duration_cast<std::chrono::microseconds>(
                   ackingTime - receivedTime)
             : 0us);
    AckFrameMetaData meta(ackState_.acks, ackDelay, ackDelayExponent);
    // Write the AckFrame ignoring the result. This is best-effort.
    writeAckFrame(meta, builder_);
  }
  // We shouldn't clone if:
  // (1) we only end up cloning only acks, ping, or paddings.
  // (2) we should write window update, but didn't, and wrote nothing else.
  if (!notPureAck ||
      (shouldWriteWindowUpdate && !windowUpdateWritten && !writeSuccess)) {
    return folly::none;
  }
  return cloneOutstandingPacket(packet);
}

const BufQueue* PacketRebuilder::cloneCryptoRetransmissionBuffer(
    const WriteCryptoFrame& frame,
    const QuicCryptoStream& stream) {
  /**
   * Crypto's StreamBuffer is removed from retransmissionBuffer in 2 cases.
   * 1: Packet containing the buffer gets acked.
   * 2: Packet containing the buffer is marked loss.
   * They have to be covered by making sure we do not clone an already acked or
   * lost packet.
   */
  DCHECK(frame.len) << "WriteCryptoFrame cloning: frame is empty. " << conn_;
  auto iter = stream.retransmissionBuffer.find(frame.offset);

  // If the crypto stream is canceled somehow, just skip cloning this frame
  if (iter == stream.retransmissionBuffer.end()) {
    return nullptr;
  }
  DCHECK(iter->second->offset == frame.offset)
      << "WriteCryptoFrame cloning: offset mismatch. " << conn_;
  DCHECK(iter->second->data.chainLength() == frame.len)
      << "WriteCryptoFrame cloning: Len mismatch. " << conn_;
  return &(iter->second->data);
}

const BufQueue* PacketRebuilder::cloneRetransmissionBuffer(
    const WriteStreamFrame& frame,
    const QuicStreamState* stream) {
  /**
   * StreamBuffer is removed from retransmissionBuffer in 3 cases.
   * 1: After send or receive RST.
   * 2: Packet containing the buffer gets acked.
   * 3: Packet containing the buffer is marked loss.
   *
   * Checking retransmittable() should cover first case. The latter three cases
   * have to be covered by making sure we do not clone an already acked, lost or
   * skipped packet.
   */
  DCHECK(stream);
  DCHECK(retransmittable(*stream));
  auto iter = stream->retransmissionBuffer.find(frame.offset);
  if (iter != stream->retransmissionBuffer.end()) {
    DCHECK(!frame.len || !iter->second->data.empty())
        << "WriteStreamFrame cloning: frame is not empty but StreamBuffer has"
        << " empty data. " << conn_;
    return frame.len ? &(iter->second->data) : nullptr;
  }
  return nullptr;
}

} // namespace quic
