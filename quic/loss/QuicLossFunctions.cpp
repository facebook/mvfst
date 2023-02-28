/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/small_vector.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

std::chrono::microseconds calculatePTO(const QuicConnectionStateBase& conn) {
  if (conn.lossState.srtt == 0us) {
    return 2 * conn.transportSettings.initialRtt;
  }
  return conn.lossState.srtt + 4 * conn.lossState.rttvar +
      conn.lossState.maxAckDelay;
}

bool isPersistentCongestion(
    folly::Optional<std::chrono::microseconds> pto,
    TimePoint lostPeriodStart,
    TimePoint lostPeriodEnd,
    const CongestionController::AckEvent& ack) noexcept {
  if (!pto.has_value()) {
    return false;
  }

  auto exceedsDuration = (lostPeriodEnd - lostPeriodStart) >=
      pto.value() * kPersistentCongestionThreshold;

  if (!exceedsDuration) {
    return false;
  }

  auto it = std::find_if(
      ack.ackedPackets.cbegin(), ack.ackedPackets.cend(), [&](auto& ackPacket) {
        return ackPacket.outstandingPacketMetadata.time >= lostPeriodStart &&
            ackPacket.outstandingPacketMetadata.time <= lostPeriodEnd;
      });

  return it == ack.ackedPackets.cend();
}

void onPTOAlarm(QuicConnectionStateBase& conn) {
  VLOG(10) << __func__ << " " << conn;
  QUIC_STATS(conn.statsCallback, onPTO);
  conn.lossState.ptoCount++;
  conn.lossState.totalPTOCount++;
  if (conn.qLogger) {
    conn.qLogger->addLossAlarm(
        conn.lossState.largestSent.value_or(0),
        conn.lossState.ptoCount,
        conn.outstandings.numOutstanding(),
        kPtoAlarm);
  }
  if (conn.lossState.ptoCount == conn.transportSettings.maxNumPTOs) {
    throw QuicInternalException(
        "Exceeded max PTO", LocalErrorCode::CONNECTION_ABANDONED);
  }

  // The first PTO after the oneRttWriteCipher is available is an opportunity to
  // retransmit unacknowledged 0-rtt data. It may be done only once.
  if (conn.transportSettings.earlyRetransmit0Rtt &&
      !conn.lossState.attemptedEarlyRetransmit0Rtt && conn.oneRttWriteCipher) {
    conn.lossState.attemptedEarlyRetransmit0Rtt = true;
    markZeroRttPacketsLost(conn, markPacketLoss);
  }

  // We should avoid sending pointless PTOs if we don't have packets in the loss
  // buffer or enough outstanding packets to send.
  auto& packetCount = conn.outstandings.packetCount;
  auto& numProbePackets = conn.pendingEvents.numProbePackets;
  // Zero it out so we don't try to send probes for spaces without a cipher.
  numProbePackets = {};
  if (conn.initialWriteCipher) {
    numProbePackets[PacketNumberSpace::Initial] = kPacketToSendForPTO;
    if (conn.cryptoState->initialStream.lossBuffer.empty() &&
        packetCount[PacketNumberSpace::Initial] < kPacketToSendForPTO) {
      numProbePackets[PacketNumberSpace::Initial] =
          packetCount[PacketNumberSpace::Initial];
    }
  }
  if (conn.handshakeWriteCipher) {
    numProbePackets[PacketNumberSpace::Handshake] = kPacketToSendForPTO;
    if (conn.cryptoState->handshakeStream.lossBuffer.empty() &&
        packetCount[PacketNumberSpace::Handshake] < kPacketToSendForPTO) {
      numProbePackets[PacketNumberSpace::Handshake] =
          packetCount[PacketNumberSpace::Handshake];
    }
  }
  if (conn.oneRttWriteCipher) {
    numProbePackets[PacketNumberSpace::AppData] = kPacketToSendForPTO;
    if (conn.cryptoState->oneRttStream.lossBuffer.empty() &&
        !conn.streamManager->hasLoss() &&
        packetCount[PacketNumberSpace::AppData] < kPacketToSendForPTO) {
      numProbePackets[PacketNumberSpace::AppData] =
          packetCount[PacketNumberSpace::AppData];
    }
  }
}

template <class T, size_t N>
using InlineSetVec = folly::small_vector<T, N>;

template <
    typename Value,
    size_t N,
    class Container = InlineSetVec<Value, N>,
    typename = std::enable_if_t<std::is_integral<Value>::value>>
using InlineSet = folly::heap_vector_set<
    Value,
    std::less<Value>,
    typename Container::allocator_type,
    void,
    Container>;

void markPacketLoss(
    QuicConnectionStateBase& conn,
    RegularQuicWritePacket& packet,
    bool processed) {
  QUIC_STATS(conn.statsCallback, onPacketLoss);
  InlineSet<uint64_t, 10> streamsWithAddedStreamLossForPacket;
  for (auto& packetFrame : packet.frames) {
    switch (packetFrame.type()) {
      case QuicWriteFrame::Type::MaxStreamDataFrame: {
        MaxStreamDataFrame& frame = *packetFrame.asMaxStreamDataFrame();
        // For all other frames, we process it if it's not from a clone
        // packet, or if the clone and its siblings have never been processed.
        // But for both MaxData and MaxStreamData, we opportunistically send
        // an update to avoid stalling the peer.
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (!stream) {
          break;
        }
        // TODO: check for the stream is in Open or HalfClosedLocal state, the
        // peer doesn't need a flow control update in these cases.
        onStreamWindowUpdateLost(*stream);
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame: {
        onConnWindowUpdateLost(conn);
        break;
      }
      // For other frame types, we only process them if the packet is not a
      // processed clone.
      case QuicWriteFrame::Type::DataBlockedFrame: {
        if (processed) {
          break;
        }
        onDataBlockedLost(conn);
        break;
      }
      case QuicWriteFrame::Type::WriteStreamFrame: {
        WriteStreamFrame frame = *packetFrame.asWriteStreamFrame();
        if (processed) {
          break;
        }
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (!stream) {
          break;
        }
        if (!frame.fromBufMeta) {
          auto bufferItr = stream->retransmissionBuffer.find(frame.offset);
          if (bufferItr == stream->retransmissionBuffer.end()) {
            // It's possible that the stream was reset or data on the stream was
            // skipped while we discovered that its packet was lost so we might
            // not have the offset.
            break;
          }
          if (!streamRetransmissionDisabled(conn, *stream)) {
            stream->insertIntoLossBuffer(std::move(bufferItr->second));
          }
          if (streamsWithAddedStreamLossForPacket.find(frame.streamId) ==
              streamsWithAddedStreamLossForPacket.end()) {
            stream->streamLossCount++;
            streamsWithAddedStreamLossForPacket.insert(frame.streamId);
          }
          stream->retransmissionBuffer.erase(bufferItr);
        } else {
          auto retxBufMetaItr =
              stream->retransmissionBufMetas.find(frame.offset);
          if (retxBufMetaItr == stream->retransmissionBufMetas.end()) {
            break;
          }
          auto& bufMeta = retxBufMetaItr->second;
          CHECK_EQ(bufMeta.offset, frame.offset);
          CHECK_EQ(bufMeta.length, frame.len);
          CHECK_EQ(bufMeta.eof, frame.fin);
          if (!streamRetransmissionDisabled(conn, *stream)) {
            stream->insertIntoLossBufMeta(retxBufMetaItr->second);
          }
          if (streamsWithAddedStreamLossForPacket.find(frame.streamId) ==
              streamsWithAddedStreamLossForPacket.end()) {
            stream->streamLossCount++;
            streamsWithAddedStreamLossForPacket.insert(frame.streamId);
          }
          stream->retransmissionBufMetas.erase(retxBufMetaItr);
        }
        conn.streamManager->updateWritableStreams(*stream);
        conn.streamManager->updateLossStreams(*stream);
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame: {
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
      case QuicWriteFrame::Type::RstStreamFrame: {
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
      case QuicWriteFrame::Type::StreamDataBlockedFrame: {
        StreamDataBlockedFrame& frame = *packetFrame.asStreamDataBlockedFrame();
        if (processed) {
          break;
        }
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (!stream) {
          break;
        }
        onBlockedLost(*stream);
        break;
      }
      case QuicWriteFrame::Type::QuicSimpleFrame: {
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
