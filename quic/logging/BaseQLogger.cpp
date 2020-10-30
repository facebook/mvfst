// Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

#include <quic/logging/BaseQLogger.h>

namespace {
void addQuicSimpleFrameToEvent(
    quic::QLogPacketEvent* event,
    const quic::QuicSimpleFrame& simpleFrame) {
  switch (simpleFrame.type()) {
    case quic::QuicSimpleFrame::Type::StopSendingFrame_E: {
      const quic::StopSendingFrame& frame = *simpleFrame.asStopSendingFrame();
      event->frames.push_back(std::make_unique<quic::StopSendingFrameLog>(
          frame.streamId, frame.errorCode));
      break;
    }
    case quic::QuicSimpleFrame::Type::MinStreamDataFrame_E: {
      const quic::MinStreamDataFrame& frame =
          *simpleFrame.asMinStreamDataFrame();
      event->frames.push_back(std::make_unique<quic::MinStreamDataFrameLog>(
          frame.streamId, frame.maximumData, frame.minimumStreamOffset));
      break;
    }
    case quic::QuicSimpleFrame::Type::ExpiredStreamDataFrame_E: {
      const quic::ExpiredStreamDataFrame& frame =
          *simpleFrame.asExpiredStreamDataFrame();
      event->frames.push_back(std::make_unique<quic::ExpiredStreamDataFrameLog>(
          frame.streamId, frame.minimumStreamOffset));
      break;
    }
    case quic::QuicSimpleFrame::Type::PathChallengeFrame_E: {
      const quic::PathChallengeFrame& frame =
          *simpleFrame.asPathChallengeFrame();
      event->frames.push_back(
          std::make_unique<quic::PathChallengeFrameLog>(frame.pathData));
      break;
    }
    case quic::QuicSimpleFrame::Type::PathResponseFrame_E: {
      const quic::PathResponseFrame& frame = *simpleFrame.asPathResponseFrame();
      event->frames.push_back(
          std::make_unique<quic::PathResponseFrameLog>(frame.pathData));
      break;
    }
    case quic::QuicSimpleFrame::Type::NewConnectionIdFrame_E: {
      const quic::NewConnectionIdFrame& frame =
          *simpleFrame.asNewConnectionIdFrame();
      event->frames.push_back(std::make_unique<quic::NewConnectionIdFrameLog>(
          frame.sequenceNumber, frame.token));
      break;
    }
    case quic::QuicSimpleFrame::Type::MaxStreamsFrame_E: {
      const quic::MaxStreamsFrame& frame = *simpleFrame.asMaxStreamsFrame();
      event->frames.push_back(std::make_unique<quic::MaxStreamsFrameLog>(
          frame.maxStreams, frame.isForBidirectional));
      break;
    }
    case quic::QuicSimpleFrame::Type::RetireConnectionIdFrame_E: {
      const quic::RetireConnectionIdFrame& frame =
          *simpleFrame.asRetireConnectionIdFrame();
      event->frames.push_back(
          std::make_unique<quic::RetireConnectionIdFrameLog>(
              frame.sequenceNumber));
      break;
    }
    case quic::QuicSimpleFrame::Type::HandshakeDoneFrame_E: {
      event->frames.push_back(std::make_unique<quic::HandshakeDoneFrameLog>());
      break;
    }
    case quic::QuicSimpleFrame::Type::KnobFrame_E: {
      const quic::KnobFrame& frame = *simpleFrame.asKnobFrame();
      event->frames.push_back(std::make_unique<quic::KnobFrameLog>(
          frame.knobSpace, frame.id, frame.blob->length()));
      break;
    }
  }
}
} // namespace

namespace quic {

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEvent(
    const RegularQuicPacket& regularPacket,
    uint64_t packetSize) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  event->packetSize = packetSize;
  event->eventType = QLogEventType::PacketReceived;
  const ShortHeader* shortHeader = regularPacket.header.asShort();
  if (shortHeader) {
    event->packetType = kShortHeaderPacketType.toString();
  } else {
    event->packetType =
        toQlogString(regularPacket.header.asLong()->getHeaderType()).str();
  }
  if (event->packetType != toString(LongHeader::Types::Retry)) {
    // A Retry packet does not include a packet number.
    event->packetNum = regularPacket.header.getPacketSequenceNum();
  }

  uint64_t numPaddingFrames = 0;
  // looping through the packet to store logs created from frames in the packet
  for (const auto& quicFrame : regularPacket.frames) {
    switch (quicFrame.type()) {
      case QuicFrame::Type::PaddingFrame_E: {
        ++numPaddingFrames;
        break;
      }
      case QuicFrame::Type::RstStreamFrame_E: {
        const auto& frame = *quicFrame.asRstStreamFrame();
        event->frames.push_back(std::make_unique<RstStreamFrameLog>(
            frame.streamId, frame.errorCode, frame.offset));
        break;
      }
      case QuicFrame::Type::ConnectionCloseFrame_E: {
        const auto& frame = *quicFrame.asConnectionCloseFrame();
        event->frames.push_back(std::make_unique<ConnectionCloseFrameLog>(
            frame.errorCode, frame.reasonPhrase, frame.closingFrameType));
        break;
      }
      case QuicFrame::Type::MaxDataFrame_E: {
        const auto& frame = *quicFrame.asMaxDataFrame();
        event->frames.push_back(
            std::make_unique<MaxDataFrameLog>(frame.maximumData));
        break;
      }
      case QuicFrame::Type::MaxStreamDataFrame_E: {
        const auto& frame = *quicFrame.asMaxStreamDataFrame();
        event->frames.push_back(std::make_unique<MaxStreamDataFrameLog>(
            frame.streamId, frame.maximumData));
        break;
      }
      case QuicFrame::Type::DataBlockedFrame_E: {
        const auto& frame = *quicFrame.asDataBlockedFrame();
        event->frames.push_back(
            std::make_unique<DataBlockedFrameLog>(frame.dataLimit));
        break;
      }
      case QuicFrame::Type::StreamDataBlockedFrame_E: {
        const auto& frame = *quicFrame.asStreamDataBlockedFrame();
        event->frames.push_back(std::make_unique<StreamDataBlockedFrameLog>(
            frame.streamId, frame.dataLimit));
        break;
      }
      case QuicFrame::Type::StreamsBlockedFrame_E: {
        const auto& frame = *quicFrame.asStreamsBlockedFrame();
        event->frames.push_back(std::make_unique<StreamsBlockedFrameLog>(
            frame.streamLimit, frame.isForBidirectional));
        break;
      }
      case QuicFrame::Type::ReadAckFrame_E: {
        const auto& frame = *quicFrame.asReadAckFrame();
        event->frames.push_back(
            std::make_unique<ReadAckFrameLog>(frame.ackBlocks, frame.ackDelay));
        break;
      }
      case QuicFrame::Type::ReadStreamFrame_E: {
        const auto& frame = *quicFrame.asReadStreamFrame();
        event->frames.push_back(std::make_unique<StreamFrameLog>(
            frame.streamId, frame.offset, frame.data->length(), frame.fin));
        break;
      }
      case QuicFrame::Type::ReadCryptoFrame_E: {
        const auto& frame = *quicFrame.asReadCryptoFrame();
        event->frames.push_back(std::make_unique<CryptoFrameLog>(
            frame.offset, frame.data->length()));
        break;
      }
      case QuicFrame::Type::ReadNewTokenFrame_E: {
        event->frames.push_back(std::make_unique<ReadNewTokenFrameLog>());
        break;
      }
      case QuicFrame::Type::PingFrame_E:
        event->frames.push_back(std::make_unique<quic::PingFrameLog>());
        break;
      case QuicFrame::Type::QuicSimpleFrame_E: {
        const auto& simpleFrame = *quicFrame.asQuicSimpleFrame();
        addQuicSimpleFrameToEvent(event.get(), simpleFrame);
        break;
      }
      case QuicFrame::Type::NoopFrame_E: {
        break;
      }
    }
  }
  if (numPaddingFrames > 0) {
    event->frames.push_back(
        std::make_unique<PaddingFrameLog>(numPaddingFrames));
  }
  return event;
}

std::unique_ptr<QLogPacketEvent> BaseQLogger::createPacketEvent(
    const RegularQuicWritePacket& writePacket,
    uint64_t packetSize) {
  auto event = std::make_unique<QLogPacketEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  event->packetNum = writePacket.header.getPacketSequenceNum();
  event->packetSize = packetSize;
  event->eventType = QLogEventType::PacketSent;
  const ShortHeader* shortHeader = writePacket.header.asShort();
  if (shortHeader) {
    event->packetType = kShortHeaderPacketType.toString();
  } else {
    event->packetType =
        toQlogString(writePacket.header.asLong()->getHeaderType()).str();
  }

  uint64_t numPaddingFrames = 0;
  // looping through the packet to store logs created from frames in the packet
  for (const auto& quicFrame : writePacket.frames) {
    switch (quicFrame.type()) {
      case QuicWriteFrame::Type::PaddingFrame_E:
        ++numPaddingFrames;
        break;
      case QuicWriteFrame::Type::RstStreamFrame_E: {
        const RstStreamFrame& frame = *quicFrame.asRstStreamFrame();
        event->frames.push_back(std::make_unique<RstStreamFrameLog>(
            frame.streamId, frame.errorCode, frame.offset));
        break;
      }
      case QuicWriteFrame::Type::ConnectionCloseFrame_E: {
        const ConnectionCloseFrame& frame = *quicFrame.asConnectionCloseFrame();
        event->frames.push_back(std::make_unique<ConnectionCloseFrameLog>(
            frame.errorCode, frame.reasonPhrase, frame.closingFrameType));
        break;
      }
      case QuicWriteFrame::Type::MaxDataFrame_E: {
        const MaxDataFrame& frame = *quicFrame.asMaxDataFrame();
        event->frames.push_back(
            std::make_unique<MaxDataFrameLog>(frame.maximumData));
        break;
      }
      case QuicWriteFrame::Type::MaxStreamDataFrame_E: {
        const MaxStreamDataFrame& frame = *quicFrame.asMaxStreamDataFrame();
        event->frames.push_back(std::make_unique<MaxStreamDataFrameLog>(
            frame.streamId, frame.maximumData));
        break;
      }
      case QuicWriteFrame::Type::StreamsBlockedFrame_E: {
        const StreamsBlockedFrame& frame = *quicFrame.asStreamsBlockedFrame();
        event->frames.push_back(std::make_unique<StreamsBlockedFrameLog>(
            frame.streamLimit, frame.isForBidirectional));
        break;
      }
      case QuicWriteFrame::Type::DataBlockedFrame_E: {
        const DataBlockedFrame& frame = *quicFrame.asDataBlockedFrame();
        event->frames.push_back(
            std::make_unique<DataBlockedFrameLog>(frame.dataLimit));
        break;
      }
      case QuicWriteFrame::Type::StreamDataBlockedFrame_E: {
        const StreamDataBlockedFrame& frame =
            *quicFrame.asStreamDataBlockedFrame();
        event->frames.push_back(std::make_unique<StreamDataBlockedFrameLog>(
            frame.streamId, frame.dataLimit));
        break;
      }
      case QuicWriteFrame::Type::WriteAckFrame_E: {
        const WriteAckFrame& frame = *quicFrame.asWriteAckFrame();
        event->frames.push_back(std::make_unique<WriteAckFrameLog>(
            frame.ackBlocks, frame.ackDelay));
        break;
      }
      case QuicWriteFrame::Type::WriteStreamFrame_E: {
        const WriteStreamFrame& frame = *quicFrame.asWriteStreamFrame();
        event->frames.push_back(std::make_unique<StreamFrameLog>(
            frame.streamId, frame.offset, frame.len, frame.fin));
        break;
      }
      case QuicWriteFrame::Type::WriteCryptoFrame_E: {
        const WriteCryptoFrame& frame = *quicFrame.asWriteCryptoFrame();
        event->frames.push_back(
            std::make_unique<CryptoFrameLog>(frame.offset, frame.len));
        break;
      }
      case QuicWriteFrame::Type::QuicSimpleFrame_E: {
        const QuicSimpleFrame& simpleFrame = *quicFrame.asQuicSimpleFrame();
        addQuicSimpleFrameToEvent(event.get(), simpleFrame);
        break;
      }
      default:
        break;
    }
  }
  if (numPaddingFrames > 0) {
    event->frames.push_back(
        std::make_unique<PaddingFrameLog>(numPaddingFrames));
  }
  return event;
}

std::unique_ptr<QLogVersionNegotiationEvent> BaseQLogger::createPacketEvent(
    const VersionNegotiationPacket& versionPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto event = std::make_unique<QLogVersionNegotiationEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  event->packetSize = packetSize;
  event->eventType =
      isPacketRecvd ? QLogEventType::PacketReceived : QLogEventType::PacketSent;
  event->packetType = kVersionNegotiationPacketType;
  event->versionLog = std::make_unique<VersionNegotiationLog>(
      VersionNegotiationLog(versionPacket.versions));
  return event;
}

std::unique_ptr<QLogRetryEvent> BaseQLogger::createPacketEvent(
    const RetryPacket& retryPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  auto event = std::make_unique<QLogRetryEvent>();
  event->refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  event->packetSize = packetSize;
  event->tokenSize = retryPacket.header.getToken().size();
  event->eventType =
      isPacketRecvd ? QLogEventType::PacketReceived : QLogEventType::PacketSent;
  event->packetType = toQlogString(retryPacket.header.getHeaderType()).str();
  return event;
}

} // namespace quic
