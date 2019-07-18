/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include "quic/loss/QuicLossFunctions.h"

namespace quic {

std::chrono::microseconds calculatePTO(const QuicConnectionStateBase& conn) {
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
  QUIC_STATS(conn.infoCallback, onPTO);
  conn.lossState.ptoCount++;
  conn.lossState.totalPTOCount++;
  if (conn.qLogger) {
    conn.qLogger->addLossAlarm(
        conn.lossState.largestSent,
        conn.lossState.ptoCount,
        (uint64_t)conn.outstandingPackets.size(),
        kPtoAlarm.str());
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
    folly::variant_match(
        packetFrame,
        [&](MaxStreamDataFrame& frame) {
          // For all other frames, we process it if it's not from a clone
          // packet, or if the clone and its siblings have never been processed.
          // But for both MaxData and MaxStreamData, clone and its siblings may
          // have different values. So we process it if it matches the
          // latestMaxDataPacket or latestMaxStreamDataPacket. If an older
          // packet also has such frames, it's ok to skip process of such loss
          // since newer value is already sent in later packets.
          auto stream = conn.streamManager->getStream(frame.streamId);
          if (!stream) {
            return;
          }
          // TODO: check for the stream is in Open or HalfClosedLocal state, the
          // peer doesn't need a flow control update in these cases.
          if (stream->latestMaxStreamDataPacket == currentPacketNum) {
            onStreamWindowUpdateLost(*stream);
          }
        },
        [&](MaxDataFrame&) {
          if (conn.latestMaxDataPacket == currentPacketNum) {
            onConnWindowUpdateLost(conn);
          }
        },
        // For other frame types, we only process them if the packet is not a
        // processed clone.
        [&](WriteStreamFrame& frame) {
          if (processed) {
            return;
          }
          auto stream = conn.streamManager->getStream(frame.streamId);
          if (!stream) {
            return;
          }
          auto bufferItr = std::lower_bound(
              stream->retransmissionBuffer.begin(),
              stream->retransmissionBuffer.end(),
              frame.offset,
              [](const auto& buffer, const auto& offset) {
                return buffer.offset < offset;
              });
          if (bufferItr == stream->retransmissionBuffer.end()) {
            // It's possible that the stream was reset or data on the stream was
            // skipped while we discovered that its packet was lost so we might
            // not have the offset.
            return;
          }
          // The original rxmt offset might have been bumped up after it was
          // shrunk due to egress partially reliable skip.
          if (!ackFrameMatchesRetransmitBuffer(*stream, frame, *bufferItr)) {
            return;
          }
          stream->lossBuffer.insert(
              std::upper_bound(
                  stream->lossBuffer.begin(),
                  stream->lossBuffer.end(),
                  bufferItr->offset,
                  [](const auto& offset, const auto& buffer) {
                    return offset < buffer.offset;
                  }),
              std::move(*bufferItr));
          stream->retransmissionBuffer.erase(bufferItr);
          conn.streamManager->updateLossStreams(*stream);
        },
        [&](WriteCryptoFrame& frame) {
          if (processed) {
            return;
          }
          auto protectionType = folly::variant_match(
              packet.header,
              [](auto& header) { return header.getProtectionType(); });
          auto encryptionLevel =
              protectionTypeToEncryptionLevel(protectionType);
          auto cryptoStream =
              getCryptoStream(*conn.cryptoState, encryptionLevel);

          auto bufferItr = std::lower_bound(
              cryptoStream->retransmissionBuffer.begin(),
              cryptoStream->retransmissionBuffer.end(),
              frame.offset,
              [](const auto& buffer, const auto& offset) {
                return buffer.offset < offset;
              });
          if (bufferItr == cryptoStream->retransmissionBuffer.end()) {
            // It's possible that the stream was reset while we discovered that
            // it's packet was lost so we might not have the offset.
            return;
          }
          DCHECK_EQ(bufferItr->offset, frame.offset);
          cryptoStream->lossBuffer.insert(
              std::upper_bound(
                  cryptoStream->lossBuffer.begin(),
                  cryptoStream->lossBuffer.end(),
                  bufferItr->offset,
                  [](const auto& offset, const auto& buffer) {
                    return offset < buffer.offset;
                  }),
              std::move(*bufferItr));
          cryptoStream->retransmissionBuffer.erase(bufferItr);
        },
        [&](RstStreamFrame& frame) {
          if (processed) {
            return;
          }
          auto stream = conn.streamManager->getStream(frame.streamId);
          if (!stream) {
            // If the stream is dead, ignore the retransmissions of the rst
            // stream.
            return;
          }
          // Add the lost RstStreamFrame back to pendingEvents:
          conn.pendingEvents.resets.insert({frame.streamId, frame});
        },
        [&](StreamDataBlockedFrame& frame) {
          if (processed) {
            return;
          }
          auto stream = conn.streamManager->getStream(frame.streamId);
          // TODO: check for retransmittable
          if (!stream) {
            return;
          }
          onBlockedLost(*stream);
        },
        [&](QuicSimpleFrame& frame) {
          if (processed) {
            return;
          }
          updateSimpleFrameOnPacketLoss(conn, frame);
        },
        [&](auto&) {
          // ignore the rest of the frames.
        });
  }
}
} // namespace quic
