/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include "quic/loss/QuicLossFunctions.h"
#include "quic/state/QuicStreamFunctions.h"

namespace quic {

std::chrono::microseconds calculatePTO(const QuicConnectionStateBase& conn) {
  if (conn.lossState.srtt == 0us) {
    return 2 * conn.transportSettings.initialRtt;
  }
  return conn.lossState.srtt + 4 * conn.lossState.rttvar +
      conn.lossState.maxAckDelay;
}

bool isPersistentCongestion(
    const QuicConnectionStateBase& conn,
    TimePoint lostPeriodStart,
    TimePoint lostPeriodEnd) noexcept {
  if (conn.lossState.srtt == 0us) {
    return false;
  }
  auto pto = calculatePTO(conn);
  return (lostPeriodEnd - lostPeriodStart) >=
      pto * kPersistentCongestionThreshold;
}

void onPTOAlarm(QuicConnectionStateBase& conn) {
  VLOG(10) << __func__ << " " << conn;
  QUIC_TRACE(
      pto_alarm,
      conn,
      conn.lossState.largestSent,
      conn.lossState.ptoCount,
      (uint64_t)conn.outstandingPackets.size());
  QUIC_STATS(conn.statsCallback, onPTO);
  conn.lossState.ptoCount++;
  conn.lossState.totalPTOCount++;
  if (conn.qLogger) {
    conn.qLogger->addLossAlarm(
        conn.lossState.largestSent,
        conn.lossState.ptoCount,
        (uint64_t)conn.outstandingPackets.size(),
        kPtoAlarm);
  }
  if (conn.lossState.ptoCount == conn.transportSettings.maxNumPTOs) {
    throw QuicInternalException("Exceeded max PTO", LocalErrorCode::NO_ERROR);
  }
  conn.pendingEvents.numProbePackets = kPacketToSendForPTO;
}

void markPacketLoss(
    QuicConnectionStateBase& conn,
    RegularQuicWritePacket& packet,
    bool processed,
    PacketNum currentPacketNum) {
  for (auto& packetFrame : packet.frames) {
    switch (packetFrame.type()) {
      case QuicWriteFrame::Type::MaxStreamDataFrame_E: {
        MaxStreamDataFrame& frame = *packetFrame.asMaxStreamDataFrame();
        // For all other frames, we process it if it's not from a clone
        // packet, or if the clone and its siblings have never been processed.
        // But for both MaxData and MaxStreamData, clone and its siblings may
        // have different values. So we process it if it matches the
        // latestMaxDataPacket or latestMaxStreamDataPacket. If an older
        // packet also has such frames, it's ok to skip process of such loss
        // since newer value is already sent in later packets.
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (!stream) {
          break;
        }
        // TODO: check for the stream is in Open or HalfClosedLocal state, the
        // peer doesn't need a flow control update in these cases.
        if (stream->latestMaxStreamDataPacket == currentPacketNum) {
          onStreamWindowUpdateLost(*stream);
        }
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame_E: {
        if (conn.latestMaxDataPacket == currentPacketNum) {
          onConnWindowUpdateLost(conn);
        }
        break;
      }
      // For other frame types, we only process them if the packet is not a
      // processed clone.
      case QuicWriteFrame::Type::WriteStreamFrame_E: {
        WriteStreamFrame frame = *packetFrame.asWriteStreamFrame();
        if (processed) {
          break;
        }
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (!stream) {
          break;
        }
        auto bufferItr = stream->retransmissionBuffer.find(frame.offset);
        if (bufferItr == stream->retransmissionBuffer.end()) {
          // It's possible that the stream was reset or data on the stream was
          // skipped while we discovered that its packet was lost so we might
          // not have the offset.
          break;
        }
        // The original rxmt offset might have been bumped up after it was
        // shrunk due to egress partially reliable skip.
        if (!streamFrameMatchesRetransmitBuffer(
                *stream, frame, *bufferItr->second)) {
          break;
        }
        stream->insertIntoLossBuffer(std::move(bufferItr->second));
        stream->retransmissionBuffer.erase(bufferItr);
        conn.streamManager->updateLossStreams(*stream);
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame_E: {
        WriteCryptoFrame& frame = *packetFrame.asWriteCryptoFrame();
        if (processed) {
          break;
        }
        auto protectionType = packet.header.getProtectionType();
        auto encryptionLevel = protectionTypeToEncryptionLevel(protectionType);
        auto cryptoStream = getCryptoStream(*conn.cryptoState, encryptionLevel);

        auto bufferItr = cryptoStream->retransmissionBuffer.find(frame.offset);
        if (bufferItr == cryptoStream->retransmissionBuffer.end()) {
          // It's possible that the stream was reset while we discovered that
          // it's packet was lost so we might not have the offset.
          break;
        }
        DCHECK_EQ(bufferItr->second->offset, frame.offset);
        cryptoStream->insertIntoLossBuffer(std::move(bufferItr->second));
        cryptoStream->retransmissionBuffer.erase(bufferItr);
        break;
      }
      case QuicWriteFrame::Type::RstStreamFrame_E: {
        RstStreamFrame& frame = *packetFrame.asRstStreamFrame();
        if (processed) {
          break;
        }
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (!stream) {
          // If the stream is dead, ignore the retransmissions of the rst
          // stream.
          break;
        }
        // Add the lost RstStreamFrame back to pendingEvents:
        conn.pendingEvents.resets.insert({frame.streamId, frame});
        break;
      }
      case QuicWriteFrame::Type::StreamDataBlockedFrame_E: {
        StreamDataBlockedFrame& frame = *packetFrame.asStreamDataBlockedFrame();
        if (processed) {
          break;
        }
        auto stream = conn.streamManager->getStream(frame.streamId);
        // TODO: check for retransmittable
        if (!stream) {
          break;
        }
        onBlockedLost(*stream);
        break;
      }
      case QuicWriteFrame::Type::QuicSimpleFrame_E: {
        QuicSimpleFrame& frame = *packetFrame.asQuicSimpleFrame();
        if (processed) {
          break;
        }
        updateSimpleFrameOnPacketLoss(conn, frame);
        break;
      }
      default:
        // ignore the rest of the frames.
        break;
    }
  }
}
} // namespace quic
