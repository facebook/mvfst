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
    RegularQuicPacketBuilder& regularBuilder,
    QuicConnectionStateBase& conn)
    : builder_(regularBuilder), conn_(conn) {}

uint64_t PacketRebuilder::getHeaderBytes() const {
  return builder_.getHeaderBytes();
}

PacketEvent PacketRebuilder::cloneOutstandingPacket(OutstandingPacket& packet) {
  // Either the packet has never been cloned before, or it's associatedEvent is
  // still in the outstandingPacketEvents set.
  DCHECK(
      !packet.associatedEvent ||
      conn_.outstandingPacketEvents.count(*packet.associatedEvent));
  if (!packet.associatedEvent) {
    auto packetNum = folly::variant_match(
        packet.packet.header, [](auto& h) { return h.getPacketSequenceNum(); });
    DCHECK(!conn_.outstandingPacketEvents.count(packetNum));
    packet.associatedEvent = packetNum;
    conn_.outstandingPacketEvents.insert(packetNum);
    ++conn_.outstandingClonedPacketsCount;
  }
  return *packet.associatedEvent;
}

folly::Optional<PacketEvent> PacketRebuilder::rebuildFromPacket(
    OutstandingPacket& packet) {
  // TODO: if PMTU changes between the transmission of the original packet and
  // now, then we cannot clone everything in the packet.

  // TODO: make sure this cannot be called on handshake packets.
  bool writeSuccess = false;
  bool windowUpdateWritten = false;
  bool shouldWriteWindowUpdate = false;
  bool notPureAck = false;
  for (auto iter = packet.packet.frames.cbegin();
       iter != packet.packet.frames.cend();
       iter++) {
    const QuicWriteFrame& frame = *iter;
    writeSuccess = folly::variant_match(
        frame,
        [&](const WriteAckFrame& ackFrame) {
          uint64_t ackDelayExponent = folly::variant_match(
              builder_.getPacketHeader(),
              [](const LongHeader&) { return kDefaultAckDelayExponent; },
              [&](const auto&) {
                return conn_.transportSettings.ackDelayExponent;
              });
          AckFrameMetaData meta(
              ackFrame.ackBlocks, ackFrame.ackDelay, ackDelayExponent);
          auto ackWriteResult = writeAckFrame(meta, builder_);
          return ackWriteResult.hasValue();
        },
        [&](const WriteStreamFrame& streamFrame) {
          auto stream = conn_.streamManager->getStream(streamFrame.streamId);
          if (stream && retransmittable(*stream)) {
            StreamFrameMetaData meta(
                streamFrame.streamId,
                streamFrame.offset,
                streamFrame.fin,
                cloneRetransmissionBuffer(streamFrame, stream),
                true);
            auto streamWriteResult = writeStreamFrame(meta, builder_);
            bool ret = streamWriteResult.hasValue() &&
                streamWriteResult->bytesWritten == streamFrame.len &&
                streamWriteResult->finWritten == streamFrame.fin;
            notPureAck |= ret;
            return ret;
          }
          // If a stream is already Closed, or HalfClosedLocal, we should not
          // clone and resend this stream data. But should we abort the cloning
          // of this packet and move on to the next packet? I'm gonna err on the
          // aggressive side for now and call it success.
          return true;
        },
        [&](const WriteCryptoFrame& cryptoFrame) {
          // initialStream and handshakeStream can only be in handshake packet,
          // so they are not clonable
          CHECK(!packet.isHandshake);
          folly::variant_match(packet.packet.header, [](const auto& header) {
            // key update not supported
            CHECK(header.getProtectionType() == ProtectionType::KeyPhaseZero);
          });
          auto& stream = conn_.cryptoState->oneRttStream;
          auto buf = cloneCryptoRetransmissionBuffer(cryptoFrame, stream);

          // No crypto data found to be cloned, just skip
          if (!buf) {
            return true;
          }
          auto cryptoWriteResult =
              writeCryptoFrame(cryptoFrame.offset, std::move(buf), builder_);
          bool ret = cryptoWriteResult.hasValue() &&
              cryptoWriteResult->offset == cryptoFrame.offset &&
              cryptoWriteResult->len == cryptoFrame.len;
          notPureAck |= ret;
          return ret;
        },
        [&](const MaxDataFrame&) {
          shouldWriteWindowUpdate = true;
          auto ret = 0 != writeFrame(generateMaxDataFrame(conn_), builder_);
          windowUpdateWritten |= ret;
          notPureAck |= ret;
          return true;
        },
        [&](const MaxStreamDataFrame& maxStreamDataFrame) {
          auto stream =
              conn_.streamManager->getStream(maxStreamDataFrame.streamId);
          if (!stream || !stream->shouldSendFlowControl()) {
            return true;
          }
          shouldWriteWindowUpdate = true;
          auto ret =
              0 != writeFrame(generateMaxStreamDataFrame(*stream), builder_);
          windowUpdateWritten |= ret;
          notPureAck |= ret;
          return true;
        },
        [&](const PaddingFrame& paddingFrame) {
          return writeFrame(paddingFrame, builder_) != 0;
        },
        [&](const QuicSimpleFrame& simpleFrame) {
          auto updatedSimpleFrame =
              updateSimpleFrameOnPacketClone(conn_, simpleFrame);
          if (!updatedSimpleFrame) {
            return true;
          }
          bool ret =
              writeSimpleFrame(std::move(*updatedSimpleFrame), builder_) != 0;
          notPureAck |= ret;
          return ret;
        },
        [&](const auto& otherFrame) {
          bool ret = writeFrame(otherFrame, builder_) != 0;
          notPureAck |= ret;
          return ret;
        });
    if (!writeSuccess) {
      return folly::none;
    }
  }
  // We shouldn't clone if:
  // (1) we only end up cloning acks and paddings.
  // (2) we should write window update, but didn't, and wrote nothing else.
  if (!notPureAck ||
      (shouldWriteWindowUpdate && !windowUpdateWritten && !writeSuccess)) {
    return folly::none;
  }
  return cloneOutstandingPacket(packet);
}

Buf PacketRebuilder::cloneCryptoRetransmissionBuffer(
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
  auto iter = std::lower_bound(
      stream.retransmissionBuffer.begin(),
      stream.retransmissionBuffer.end(),
      frame.offset,
      [](const auto& buffer, const auto& targetOffset) {
        return buffer.offset < targetOffset;
      });

  // If the crypto stream is canceled somehow, just skip cloning this frame
  if (iter == stream.retransmissionBuffer.end()) {
    return nullptr;
  }
  DCHECK(iter->offset == frame.offset)
      << "WriteCryptoFrame cloning: offset mismatch. " << conn_;
  DCHECK(iter->data.chainLength() == frame.len)
      << "WriteCryptoFrame cloning: Len mismatch. " << conn_;
  return iter->data.front()->clone();
}

Buf PacketRebuilder::cloneRetransmissionBuffer(
    const WriteStreamFrame& frame,
    const QuicStreamState* stream) {
  /**
   * StreamBuffer is removed from retransmissionBuffer in 4 cases.
   * 1: After send or receive RST.
   * 2: Packet containing the buffer gets acked.
   * 3: Packet containing the buffer is marked loss.
   * 4: Skip (MIN_DATA or EXPIRED_DATA) frame is received with offset larger
   *    than what's in the retransmission buffer.
   *
   * Checking retransmittable() should cover first case. The latter three cases
   * have to be covered by making sure we do not clone an already acked, lost or
   * skipped packet.
   */
  DCHECK(stream);
  DCHECK(retransmittable(*stream));
  auto iter = std::lower_bound(
      stream->retransmissionBuffer.begin(),
      stream->retransmissionBuffer.end(),
      frame.offset,
      [](const auto& buffer, const auto& targetOffset) {
        return buffer.offset < targetOffset;
      });
  if (iter != stream->retransmissionBuffer.end()) {
    DCHECK(iter->offset == frame.offset)
        << "WriteStreamFrame cloning: offset mismatch. " << conn_;
    DCHECK(iter->data.chainLength() == frame.len)
        << "WriteStreamFrame cloning: Len mismatch. " << conn_;
    DCHECK(iter->eof == frame.fin)
        << "WriteStreamFrame cloning: fin mismatch. " << conn_;
    DCHECK(!frame.len || !iter->data.empty())
        << "WriteStreamFrame cloning: frame is not empty but StreamBuffer has "
        << "empty data. " << conn_;
    return (frame.len ? iter->data.front()->clone() : nullptr);
  } else {
    VLOG(10) << "WriteStreamFrame cloning: frame is not in retx buffer anymore "
             << conn_;
    return nullptr;
  }
}

} // namespace quic
