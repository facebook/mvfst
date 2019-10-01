/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/logging/QLogger.h>

#include <folly/dynamic.h>
#include <quic/codec/Types.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QLoggerTypes.h>

namespace {
void addQuicSimpleFrameToEvent(
    quic::QLogPacketEvent* event,
    const quic::QuicSimpleFrame& simpleFrame) {
  folly::variant_match(
      simpleFrame,
      [&](const quic::StopSendingFrame& frame) {
        event->frames.push_back(std::make_unique<quic::StopSendingFrameLog>(
            frame.streamId, frame.errorCode));
      },
      [&](const quic::MinStreamDataFrame& frame) {
        event->frames.push_back(std::make_unique<quic::MinStreamDataFrameLog>(
            frame.streamId, frame.maximumData, frame.minimumStreamOffset));
      },
      [&](const quic::ExpiredStreamDataFrame& frame) {
        event->frames.push_back(
            std::make_unique<quic::ExpiredStreamDataFrameLog>(
                frame.streamId, frame.minimumStreamOffset));
      },
      [&](const quic::PathChallengeFrame& frame) {
        event->frames.push_back(
            std::make_unique<quic::PathChallengeFrameLog>(frame.pathData));
      },
      [&](const quic::PathResponseFrame& frame) {
        event->frames.push_back(
            std::make_unique<quic::PathResponseFrameLog>(frame.pathData));
      },
      [&](const quic::NewConnectionIdFrame& frame) {
        event->frames.push_back(std::make_unique<quic::NewConnectionIdFrameLog>(
            frame.sequenceNumber, frame.token));
      },
      [&](const quic::MaxStreamsFrame& frame) {
        event->frames.push_back(std::make_unique<quic::MaxStreamsFrameLog>(
            frame.maxStreams, frame.isForBidirectional));
      },
      [&](const quic::RetireConnectionIdFrame& frame) {
        event->frames.push_back(
            std::make_unique<quic::RetireConnectionIdFrameLog>(
                frame.sequenceNumber));
      });
}
} // namespace

namespace quic {
std::unique_ptr<QLogPacketEvent> QLogger::createPacketEvent(
    const RegularQuicPacket& regularPacket,
    uint64_t packetSize) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);
  event->packetSize = packetSize;
  event->eventType = QLogEventType::PacketReceived;
  const ShortHeader* shortHeader = regularPacket.header.asShort();
  if (shortHeader) {
    event->packetType = kShortHeaderPacketType.toString();
  } else {
    event->packetType =
        toString(regularPacket.header.asLong()->getHeaderType());
  }
  if (event->packetType != toString(LongHeader::Types::Retry)) {
    // A Retry packet does not include a packet number.
    event->packetNum = regularPacket.header.getPacketSequenceNum();
  }

  uint64_t numPaddingFrames = 0;
  // looping through the packet to store logs created from frames in the packet
  for (const auto& quicFrame : regularPacket.frames) {
    folly::variant_match(
        quicFrame,
        [&](const PaddingFrame& /* unused */) { ++numPaddingFrames; },
        [&](const RstStreamFrame& frame) {
          event->frames.push_back(std::make_unique<RstStreamFrameLog>(
              frame.streamId, frame.errorCode, frame.offset));
        },
        [&](const ConnectionCloseFrame& frame) {
          event->frames.push_back(std::make_unique<ConnectionCloseFrameLog>(
              frame.errorCode, frame.reasonPhrase, frame.closingFrameType));
        },
        [&](const ApplicationCloseFrame& frame) {
          event->frames.push_back(std::make_unique<ApplicationCloseFrameLog>(
              frame.errorCode, frame.reasonPhrase));
        },
        [&](const MaxDataFrame& frame) {
          event->frames.push_back(
              std::make_unique<MaxDataFrameLog>(frame.maximumData));
        },
        [&](const MaxStreamDataFrame& frame) {
          event->frames.push_back(std::make_unique<MaxStreamDataFrameLog>(
              frame.streamId, frame.maximumData));
        },
        [&](const StreamsBlockedFrame& frame) {
          event->frames.push_back(std::make_unique<StreamsBlockedFrameLog>(
              frame.streamLimit, frame.isForBidirectional));
        },
        [&](const PingFrame& /* unused */) {
          event->frames.push_back(std::make_unique<PingFrameLog>());
        },
        [&](const DataBlockedFrame& frame) {
          event->frames.push_back(
              std::make_unique<DataBlockedFrameLog>(frame.dataLimit));
        },
        [&](const StreamDataBlockedFrame& frame) {
          event->frames.push_back(std::make_unique<StreamDataBlockedFrameLog>(
              frame.streamId, frame.dataLimit));
        },
        [&](const WriteAckFrame& frame) {
          event->frames.push_back(std::make_unique<WriteAckFrameLog>(
              frame.ackBlocks, frame.ackDelay));
        },
        [&](const ReadAckFrame& frame) {
          event->frames.push_back(std::make_unique<ReadAckFrameLog>(
              frame.ackBlocks, frame.ackDelay));
        },
        [&](const ReadStreamFrame& frame) {
          event->frames.push_back(std::make_unique<StreamFrameLog>(
              frame.streamId, frame.offset, frame.data->length(), frame.fin));
        },
        [&](const ReadCryptoFrame& frame) {
          event->frames.push_back(std::make_unique<CryptoFrameLog>(
              frame.offset, frame.data->length()));
        },
        [&](const ReadNewTokenFrame& /* unused */) {
          event->frames.push_back(std::make_unique<ReadNewTokenFrameLog>());
        },
        [&](const QuicSimpleFrame& simpleFrame) {
          addQuicSimpleFrameToEvent(event.get(), simpleFrame);
        },
        [&](const auto& /* unused */) {
          // Ignore other frames.
        });
  }
  if (numPaddingFrames > 0) {
    event->frames.push_back(
        std::make_unique<PaddingFrameLog>(numPaddingFrames));
  }
  return event;
}

std::unique_ptr<QLogPacketEvent> QLogger::createPacketEvent(
    const RegularQuicWritePacket& writePacket,
    uint64_t packetSize) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);
  event->packetNum = writePacket.header.getPacketSequenceNum();
  event->packetSize = packetSize;
  event->eventType = QLogEventType::PacketSent;
  const ShortHeader* shortHeader = writePacket.header.asShort();
  if (shortHeader) {
    event->packetType = kShortHeaderPacketType.toString();
  } else {
    event->packetType = toString(writePacket.header.asLong()->getHeaderType());
  }

  uint64_t numPaddingFrames = 0;
  // looping through the packet to store logs created from frames in the packet
  for (const auto& quicFrame : writePacket.frames) {
    folly::variant_match(
        quicFrame,
        [&](const PaddingFrame& /* unused */) { ++numPaddingFrames; },
        [&](const RstStreamFrame& frame) {
          event->frames.push_back(std::make_unique<RstStreamFrameLog>(
              frame.streamId, frame.errorCode, frame.offset));
        },
        [&](const ConnectionCloseFrame& frame) {
          event->frames.push_back(std::make_unique<ConnectionCloseFrameLog>(
              frame.errorCode, frame.reasonPhrase, frame.closingFrameType));
        },
        [&](const ApplicationCloseFrame& frame) {
          event->frames.push_back(std::make_unique<ApplicationCloseFrameLog>(
              frame.errorCode, frame.reasonPhrase));
        },
        [&](const MaxDataFrame& frame) {
          event->frames.push_back(
              std::make_unique<MaxDataFrameLog>(frame.maximumData));
        },
        [&](const MaxStreamDataFrame& frame) {
          event->frames.push_back(std::make_unique<MaxStreamDataFrameLog>(
              frame.streamId, frame.maximumData));
        },
        [&](const StreamsBlockedFrame& frame) {
          event->frames.push_back(std::make_unique<StreamsBlockedFrameLog>(
              frame.streamLimit, frame.isForBidirectional));
        },
        [&](const PingFrame& /* unused */) {
          event->frames.push_back(std::make_unique<PingFrameLog>());
        },
        [&](const DataBlockedFrame& frame) {
          event->frames.push_back(
              std::make_unique<DataBlockedFrameLog>(frame.dataLimit));
        },
        [&](const StreamDataBlockedFrame& frame) {
          event->frames.push_back(std::make_unique<StreamDataBlockedFrameLog>(
              frame.streamId, frame.dataLimit));
        },
        [&](const WriteAckFrame& frame) {
          event->frames.push_back(std::make_unique<WriteAckFrameLog>(
              frame.ackBlocks, frame.ackDelay));
        },
        [&](const WriteStreamFrame& frame) {
          event->frames.push_back(std::make_unique<StreamFrameLog>(
              frame.streamId, frame.offset, frame.len, frame.fin));
        },
        [&](const WriteCryptoFrame& frame) {
          event->frames.push_back(
              std::make_unique<CryptoFrameLog>(frame.offset, frame.len));
        },
        [&](const QuicSimpleFrame& simpleFrame) {
          addQuicSimpleFrameToEvent(event.get(), simpleFrame);
        },
        [&](const auto& /* unused */) {
          // Ignore other frames.
        });
  }
  if (numPaddingFrames > 0) {
    event->frames.push_back(
        std::make_unique<PaddingFrameLog>(numPaddingFrames));
  }
  return event;
}

std::unique_ptr<QLogVersionNegotiationEvent> QLogger::createPacketEvent(
    const VersionNegotiationPacket& versionPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto event = std::make_unique<QLogVersionNegotiationEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);
  event->packetSize = packetSize;
  event->eventType =
      isPacketRecvd ? QLogEventType::PacketReceived : QLogEventType::PacketSent;
  event->packetType = kVersionNegotiationPacketType;
  event->versionLog = std::make_unique<VersionNegotiationLog>(
      VersionNegotiationLog(versionPacket.versions));
  return event;
}

std::string getFlowControlEvent(int offset) {
  return "flow control event, new offset: " + folly::to<std::string>(offset);
};

std::string
getRxStreamWU(StreamId streamId, PacketNum packetNum, uint64_t maximumData) {
  return "rx stream, streamId: " + folly::to<std::string>(streamId) +
      ", packetNum: " + folly::to<std::string>(packetNum) +
      ", maximumData: " + folly::to<std::string>(maximumData);
};

std::string getRxConnWU(PacketNum packetNum, uint64_t maximumData) {
  return "rx, packetNum: " + folly::to<std::string>(packetNum) +
      ", maximumData: " + folly::to<std::string>(maximumData);
};

std::string getPeerClose(const std::string& peerCloseReason) {
  return "error message: " + peerCloseReason;
};

std::string getFlowControlWindowAvailable(uint64_t windowAvailable) {
  return "on flow control, window available: " +
      folly::to<std::string>(windowAvailable);
};

std::string getClosingStream(const std::string& streamId) {
  return "closing stream, stream id: " + streamId;
};

} // namespace quic
