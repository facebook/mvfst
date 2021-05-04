/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/QuicPacketRebuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/flowcontrol/QuicFlowController.h>
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
  auto encryptionLevel =
      protectionTypeToEncryptionLevel(packet.packet.header.getProtectionType());
  for (auto iter = packet.packet.frames.cbegin();
       iter != packet.packet.frames.cend();
       iter++) {
    bool lastFrame = iter == packet.packet.frames.cend() - 1;
    const QuicWriteFrame& frame = *iter;
    switch (frame.type()) {
      case QuicWriteFrame::Type::WriteAckFrame: {
        const WriteAckFrame& ackFrame = *frame.asWriteAckFrame();
        auto& packetHeader = builder_.getPacketHeader();
        uint64_t ackDelayExponent =
            (packetHeader.getHeaderForm() == HeaderForm::Long)
            ? kDefaultAckDelayExponent
            : conn_.transportSettings.ackDelayExponent;
        AckBlocks ackBlocks;
        for (auto& block : ackFrame.ackBlocks) {
          ackBlocks.insert(block.start, block.end);
        }
        AckFrameMetaData meta(ackBlocks, ackFrame.ackDelay, ackDelayExponent);
        auto ackWriteResult = writeAckFrame(meta, builder_);
        writeSuccess = ackWriteResult.has_value();
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
              lastFrame && bufferLen);
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
