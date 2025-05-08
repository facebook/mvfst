/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicAckScheduler.h>
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

ClonedPacketIdentifier PacketRebuilder::cloneOutstandingPacket(
    OutstandingPacketWrapper& packet) {
  // Either the packet has never been cloned before, or it's
  // maybeClonedPacketIdentifier is still in the
  // outstandings.clonedPacketIdentifiers set.
  DCHECK(
      !packet.maybeClonedPacketIdentifier ||
      conn_.outstandings.clonedPacketIdentifiers.count(
          *packet.maybeClonedPacketIdentifier));
  if (!packet.maybeClonedPacketIdentifier) {
    auto packetNum = packet.packet.header.getPacketSequenceNum();
    auto packetNumberSpace = packet.packet.header.getPacketNumberSpace();
    ClonedPacketIdentifier event(packetNumberSpace, packetNum);
    DCHECK(!conn_.outstandings.clonedPacketIdentifiers.count(event));
    packet.maybeClonedPacketIdentifier = event;
    conn_.outstandings.clonedPacketIdentifiers.insert(event);
    ++conn_.outstandings
          .clonedPacketCount[packet.packet.header.getPacketNumberSpace()];
  }
  return *packet.maybeClonedPacketIdentifier;
}

folly::Expected<Optional<ClonedPacketIdentifier>, QuicError>
PacketRebuilder::rebuildFromPacket(OutstandingPacketWrapper& packet) {
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
  // length. This forces the maybeClonedPacketIdentifier code to reconsider the
  // packet for ACK processing. We should always be able to write an ACK since
  // the min ACK frame size is 4, while 1500 MTU stream frame lengths are going
  // to be 2 bytes maximum.
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
        continue;
      }
      case QuicWriteFrame::Type::WriteStreamFrame: {
        const WriteStreamFrame& streamFrame = *frame.asWriteStreamFrame();
        auto streamResult =
            conn_.streamManager->getStream(streamFrame.streamId);
        if (streamResult.hasError()) {
          VLOG(4) << "Failed to get stream " << streamFrame.streamId
                  << " for cloning WriteStreamFrame: "
                  << streamResult.error().message;
          // Propagate error
          return folly::makeUnexpected(streamResult.error());
        }
        auto* stream = streamResult.value();
        if (stream && retransmittable(*stream)) {
          auto streamData = cloneRetransmissionBuffer(streamFrame, stream);
          auto bufferLen = streamData ? streamData->chainLength() : 0;
          auto res = writeStreamFrameHeader(
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
          if (res.hasError()) {
            VLOG(4) << "Failed to write stream frame header for cloning: "
                    << res.error().message;
            return folly::makeUnexpected(res.error());
          }

          auto dataLen = *res;
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
        if (cryptoWriteResult.hasError()) {
          return folly::makeUnexpected(cryptoWriteResult.error());
        }

        bool ret = cryptoWriteResult.value()->offset == cryptoFrame.offset &&
            cryptoWriteResult.value()->len == cryptoFrame.len;
        notPureAck |= ret;
        writeSuccess = ret;
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        shouldWriteWindowUpdate = true;
        auto writeResult = writeFrame(generateMaxDataFrame(conn_), builder_);
        if (writeResult.hasError()) {
          return folly::makeUnexpected(writeResult.error());
        }
        bool ret = writeResult.value() != 0;
        windowUpdateWritten |= ret;
        notPureAck |= ret;
        writeSuccess = true;
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        const MaxStreamDataFrame& maxStreamDataFrame =
            *frame.asMaxStreamDataFrame();
        auto streamResult =
            conn_.streamManager->getStream(maxStreamDataFrame.streamId);
        if (streamResult.hasError()) {
          VLOG(4) << "Failed to get stream " << maxStreamDataFrame.streamId
                  << " for cloning MaxStreamDataFrame: "
                  << streamResult.error().message;
          return folly::makeUnexpected(streamResult.error());
        }
        auto* stream = streamResult.value();

        if (!stream || !stream->shouldSendFlowControl()) {
          writeSuccess = true;
          break;
        }
        shouldWriteWindowUpdate = true;
        auto writeResult =
            writeFrame(generateMaxStreamDataFrame(*stream), builder_);
        if (writeResult.hasError()) {
          return folly::makeUnexpected(writeResult.error());
        }
        bool ret = writeResult.value() != 0;
        windowUpdateWritten |= ret;
        notPureAck |= ret;
        writeSuccess = true;
        break;
      }
      case QuicWriteFrame::Type::PaddingFrame: {
        const PaddingFrame& paddingFrame = *frame.asPaddingFrame();
        auto writeResult = writeFrame(paddingFrame, builder_);
        if (writeResult.hasError()) {
          return folly::makeUnexpected(writeResult.error());
        }
        writeSuccess = writeResult.value() != 0;
        break;
      }
      case QuicWriteFrame::Type::PingFrame: {
        const PingFrame& pingFrame = *frame.asPingFrame();
        auto writeResult = writeFrame(pingFrame, builder_);
        if (writeResult.hasError()) {
          return folly::makeUnexpected(writeResult.error());
        }
        writeSuccess = writeResult.value() != 0;
        notPureAck |= writeSuccess;
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
        auto writeResult =
            writeSimpleFrame(std::move(*updatedSimpleFrame), builder_);
        if (writeResult.hasError()) {
          return folly::makeUnexpected(writeResult.error());
        }
        bool ret = writeResult.value() != 0;
        notPureAck |= ret;
        writeSuccess = ret;
        break;
      }
      case QuicWriteFrame::Type::DatagramFrame:
        // Do not clone Datagram frames.
        writeSuccess = true;
        break;
      default: {
        auto writeResult = writeFrame(QuicWriteFrame(frame), builder_);
        if (writeResult.hasError()) {
          return folly::makeUnexpected(writeResult.error());
        }
        bool ret = writeResult.value() != 0;
        notPureAck |= ret;
        writeSuccess = ret;
        break;
      }
    }
    if (!writeSuccess) {
      return std::nullopt;
    }
  }

  // If this packet had a WriteAckFrame, build a new one it with
  // fresh AckState on best-effort basis. If writing
  // that ACK fails, just ignore it and use the rest of the
  // cloned packet.
  if (shouldRebuildWriteAckFrame) {
    auto& packetHeader = builder_.getPacketHeader();
    const AckState& ackState = getAckState(
        conn_,
        protectionTypeToPacketNumberSpace(packetHeader.getProtectionType()));
    AckScheduler ackScheduler(conn_, ackState);
    auto writeResult = ackScheduler.writeNextAcks(builder_);
    if (writeResult.hasError()) {
      return folly::makeUnexpected(writeResult.error());
    }
  }

  // We shouldn't clone if:
  // (1) we only end up cloning only acks, ping, or paddings.
  // (2) we should write window update, but didn't, and wrote nothing else.
  if (!notPureAck ||
      (shouldWriteWindowUpdate && !windowUpdateWritten && !writeSuccess)) {
    return std::nullopt;
  }

  if (encryptionLevel == EncryptionLevel::Initial) {
    // Pad anything else that's left.
    while (builder_.remainingSpaceInPkt() > 0) {
      auto writeResult = writeFrame(PaddingFrame(), builder_);
      if (writeResult.hasError()) {
        return folly::makeUnexpected(writeResult.error());
      }
    }
  }

  return cloneOutstandingPacket(packet);
}

const ChainedByteRangeHead* PacketRebuilder::cloneCryptoRetransmissionBuffer(
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

const ChainedByteRangeHead* PacketRebuilder::cloneRetransmissionBuffer(
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
