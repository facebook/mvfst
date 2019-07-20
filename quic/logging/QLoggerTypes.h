/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/dynamic.h>
#include <quic/codec/Types.h>
#include <memory>
#include <string>
#include <vector>

namespace quic {

class QLogFrame {
 public:
  QLogFrame() = default;
  virtual ~QLogFrame() = default;
  virtual folly::dynamic toDynamic() const = 0;
};

class PaddingFrameLog : public QLogFrame {
 public:
  PaddingFrameLog() = default;

  ~PaddingFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class RstStreamFrameLog : public QLogFrame {
 public:
  StreamId streamId;
  ApplicationErrorCode errorCode;
  uint64_t offset;

  RstStreamFrameLog(
      StreamId streamIdIn,
      ApplicationErrorCode errorCodeIn,
      uint64_t offsetIn)
      : streamId{streamIdIn}, errorCode{errorCodeIn}, offset{offsetIn} {}

  ~RstStreamFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class ConnectionCloseFrameLog : public QLogFrame {
 public:
  TransportErrorCode errorCode;
  std::string reasonPhrase;
  FrameType closingFrameType;

  ConnectionCloseFrameLog(
      TransportErrorCode errorCodeIn,
      std::string reasonPhraseIn,
      FrameType closingFrameTypeIn)
      : errorCode{errorCodeIn},
        reasonPhrase{std::move(reasonPhraseIn)},
        closingFrameType{closingFrameTypeIn} {}

  ~ConnectionCloseFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class ApplicationCloseFrameLog : public QLogFrame {
 public:
  ApplicationErrorCode errorCode;
  std::string reasonPhrase;

  ApplicationCloseFrameLog(
      ApplicationErrorCode errorCodeIn,
      std::string reasonPhraseIn)
      : errorCode{errorCodeIn}, reasonPhrase{std::move(reasonPhraseIn)} {}

  ~ApplicationCloseFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class MaxDataFrameLog : public QLogFrame {
 public:
  uint64_t maximumData;

  explicit MaxDataFrameLog(uint64_t maximumDataIn)
      : maximumData{maximumDataIn} {}

  ~MaxDataFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class MaxStreamDataFrameLog : public QLogFrame {
 public:
  StreamId streamId;
  uint64_t maximumData;

  MaxStreamDataFrameLog(StreamId streamIdIn, uint64_t maximumDataIn)
      : streamId{streamIdIn}, maximumData{maximumDataIn} {}

  ~MaxStreamDataFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class MaxStreamsFrameLog : public QLogFrame {
 public:
  uint64_t maxStreams;
  bool isForBidirectional;

  MaxStreamsFrameLog(uint64_t maxStreamsIn, bool isForBidirectionalIn)
      : maxStreams{maxStreamsIn}, isForBidirectional{isForBidirectionalIn} {}
  ~MaxStreamsFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class StreamsBlockedFrameLog : public QLogFrame {
 public:
  uint64_t streamLimit;
  bool isForBidirectional;

  StreamsBlockedFrameLog(uint64_t streamLimitIn, bool isForBidirectionalIn)
      : streamLimit{streamLimitIn}, isForBidirectional{isForBidirectionalIn} {}

  ~StreamsBlockedFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class PingFrameLog : public QLogFrame {
 public:
  PingFrameLog() = default;
  ~PingFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class DataBlockedFrameLog : public QLogFrame {
 public:
  uint64_t dataLimit;

  explicit DataBlockedFrameLog(uint64_t dataLimitIn) : dataLimit{dataLimitIn} {}
  ~DataBlockedFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class StreamDataBlockedFrameLog : public QLogFrame {
 public:
  StreamId streamId;
  uint64_t dataLimit;

  StreamDataBlockedFrameLog(StreamId streamIdIn, uint64_t dataLimitIn)
      : streamId{streamIdIn}, dataLimit{dataLimitIn} {}
  ~StreamDataBlockedFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class ReadAckFrameLog : public QLogFrame {
 public:
  std::vector<AckBlock> ackBlocks;
  std::chrono::microseconds ackDelay;

  ReadAckFrameLog(
      const std::vector<AckBlock>& ackBlocksIn,
      std::chrono::microseconds ackDelayIn)
      : ackBlocks{ackBlocksIn}, ackDelay{ackDelayIn} {}
  ~ReadAckFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class WriteAckFrameLog : public QLogFrame {
 public:
  IntervalSet<PacketNum> ackBlocks;
  std::chrono::microseconds ackDelay;

  WriteAckFrameLog(
      IntervalSet<PacketNum> ackBlocksIn,
      std::chrono::microseconds ackDelayIn)
      : ackBlocks{ackBlocksIn}, ackDelay{ackDelayIn} {}
  ~WriteAckFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class StreamFrameLog : public QLogFrame {
 public:
  StreamId streamId;
  uint64_t offset;
  uint64_t len;
  bool fin;

  StreamFrameLog(
      StreamId streamIdIn,
      uint64_t offsetIn,
      uint64_t lenIn,
      bool finIn)
      : streamId{streamIdIn}, offset{offsetIn}, len{lenIn}, fin{finIn} {}
  ~StreamFrameLog() override = default;

  folly::dynamic toDynamic() const override;
};

class CryptoFrameLog : public QLogFrame {
 public:
  uint64_t offset;
  uint64_t len;

  CryptoFrameLog(uint64_t offsetIn, uint64_t lenIn)
      : offset{offsetIn}, len{lenIn} {}
  ~CryptoFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class StopSendingFrameLog : public QLogFrame {
 public:
  StreamId streamId;
  ApplicationErrorCode errorCode;

  StopSendingFrameLog(StreamId streamIdIn, ApplicationErrorCode errorCodeIn)
      : streamId{streamIdIn}, errorCode{errorCodeIn} {}
  ~StopSendingFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class MinStreamDataFrameLog : public QLogFrame {
 public:
  StreamId streamId;
  uint64_t maximumData;
  uint64_t minimumStreamOffset;

  MinStreamDataFrameLog(
      StreamId streamIdIn,
      uint64_t maximumDataIn,
      uint64_t minimumStreamOffsetIn)
      : streamId{streamIdIn},
        maximumData{maximumDataIn},
        minimumStreamOffset{minimumStreamOffsetIn} {}
  ~MinStreamDataFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class ExpiredStreamDataFrameLog : public QLogFrame {
 public:
  StreamId streamId;
  uint64_t minimumStreamOffset;

  ExpiredStreamDataFrameLog(StreamId streamIdIn, uint64_t minimumStreamOffsetIn)
      : streamId{streamIdIn}, minimumStreamOffset{minimumStreamOffsetIn} {}
  ~ExpiredStreamDataFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class PathChallengeFrameLog : public QLogFrame {
 public:
  uint64_t pathData;

  explicit PathChallengeFrameLog(uint64_t pathDataIn) : pathData{pathDataIn} {}
  ~PathChallengeFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class PathResponseFrameLog : public QLogFrame {
 public:
  uint64_t pathData;

  explicit PathResponseFrameLog(uint64_t pathDataIn) : pathData{pathDataIn} {}
  ~PathResponseFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class NewConnectionIdFrameLog : public QLogFrame {
 public:
  uint16_t sequence;
  StatelessResetToken token;

  NewConnectionIdFrameLog(uint16_t sequenceIn, StatelessResetToken tokenIn)
      : sequence{sequenceIn}, token{tokenIn} {}
  ~NewConnectionIdFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class ReadNewTokenFrameLog : public QLogFrame {
 public:
  ReadNewTokenFrameLog() = default;
  ~ReadNewTokenFrameLog() override = default;
  folly::dynamic toDynamic() const override;
};

class VersionNegotiationLog {
 public:
  std::vector<QuicVersion> versions;

  explicit VersionNegotiationLog(const std::vector<QuicVersion>& versionsIn)
      : versions{versionsIn} {}
  ~VersionNegotiationLog() = default;
  folly::dynamic toDynamic() const;
};

enum class QLogEventType : uint32_t {
  PacketReceived,
  PacketSent,
  ConnectionClose,
  TransportSummary,
  CongestionMetricUpdate,
  PacingMetricUpdate,
  AppIdleUpdate,
  PacketDrop,
  DatagramReceived,
  LossAlarm,
  PacketsLost,
  TransportStateUpdate,
};

std::string toString(QLogEventType type);

class QLogEvent {
 public:
  QLogEvent() = default;
  virtual ~QLogEvent() = default;
  virtual folly::dynamic toDynamic() const = 0;
  std::chrono::microseconds refTime;
  QLogEventType eventType;
};

class QLogPacketEvent : public QLogEvent {
 public:
  QLogPacketEvent() = default;
  ~QLogPacketEvent() override = default;
  std::vector<std::unique_ptr<QLogFrame>> frames;
  std::string packetType;
  PacketNum packetNum{0};
  uint64_t packetSize{0};

  folly::dynamic toDynamic() const override;
};

class QLogVersionNegotiationEvent : public QLogEvent {
 public:
  QLogVersionNegotiationEvent() = default;
  ~QLogVersionNegotiationEvent() override = default;
  std::unique_ptr<VersionNegotiationLog> versionLog;
  std::string packetType;
  uint64_t packetSize{0};

  folly::dynamic toDynamic() const override;
};

class QLogConnectionCloseEvent : public QLogEvent {
 public:
  QLogConnectionCloseEvent(
      std::string errorIn,
      std::string reasonIn,
      bool drainConnectionIn,
      bool sendCloseImmediatelyIn,
      std::chrono::microseconds refTimeIn);
  ~QLogConnectionCloseEvent() override = default;
  std::string error;
  std::string reason;
  bool drainConnection;
  bool sendCloseImmediately;

  folly::dynamic toDynamic() const override;
};

class QLogTransportSummaryEvent : public QLogEvent {
 public:
  QLogTransportSummaryEvent(
      uint64_t totalBytesSent,
      uint64_t totalBytesRecvd,
      uint64_t sumCurWriteOffset,
      uint64_t sumMaxObservedOffset,
      uint64_t sumCurStreamBufferLen,
      uint64_t totalBytesRetransmitted,
      uint64_t totalStreamBytesCloned,
      uint64_t totalBytesCloned,
      uint64_t totalCryptoDataWritten,
      uint64_t totalCryptoDataRecvd,
      std::chrono::microseconds refTimeIn);
  ~QLogTransportSummaryEvent() override = default;
  uint64_t totalBytesSent;
  uint64_t totalBytesRecvd;
  uint64_t sumCurWriteOffset;
  uint64_t sumMaxObservedOffset;
  uint64_t sumCurStreamBufferLen;
  uint64_t totalBytesRetransmitted;
  uint64_t totalStreamBytesCloned;
  uint64_t totalBytesCloned;
  uint64_t totalCryptoDataWritten;
  uint64_t totalCryptoDataRecvd;

  folly::dynamic toDynamic() const override;
};

class QLogCongestionMetricUpdateEvent : public QLogEvent {
 public:
  QLogCongestionMetricUpdateEvent(
      uint64_t bytesInFlight,
      uint64_t currentCwnd,
      std::string congestionEvent,
      std::string state,
      std::string recoveryState,
      std::chrono::microseconds refTimeIn);
  ~QLogCongestionMetricUpdateEvent() override = default;
  uint64_t bytesInFlight;
  uint64_t currentCwnd;
  std::string congestionEvent;
  std::string state;
  std::string recoveryState;

  folly::dynamic toDynamic() const override;
};

class QLogPacingMetricUpdateEvent : public QLogEvent {
 public:
  QLogPacingMetricUpdateEvent(
      uint64_t pacingBurstSize,
      std::chrono::microseconds pacingInterval,
      std::chrono::microseconds refTime);
  ~QLogPacingMetricUpdateEvent() override = default;
  uint64_t pacingBurstSize;
  std::chrono::microseconds pacingInterval;

  folly::dynamic toDynamic() const override;
};

class QLogAppIdleUpdateEvent : public QLogEvent {
 public:
  QLogAppIdleUpdateEvent(
      std::string idleEvent,
      bool idle,
      std::chrono::microseconds refTime);
  ~QLogAppIdleUpdateEvent() override = default;
  std::string idleEvent;
  bool idle;

  folly::dynamic toDynamic() const override;
};

class QLogPacketDropEvent : public QLogEvent {
 public:
  QLogPacketDropEvent(
      size_t packetSize,
      std::string dropReason,
      std::chrono::microseconds refTime);
  ~QLogPacketDropEvent() override = default;
  size_t packetSize;
  std::string dropReason;

  folly::dynamic toDynamic() const override;
};

class QLogDatagramReceivedEvent : public QLogEvent {
 public:
  QLogDatagramReceivedEvent(
      uint64_t dataLen,
      std::chrono::microseconds refTime);
  ~QLogDatagramReceivedEvent() override = default;
  uint64_t dataLen;

  folly::dynamic toDynamic() const override;
};

class QLogLossAlarmEvent : public QLogEvent {
 public:
  QLogLossAlarmEvent(
      PacketNum largestSent,
      uint64_t alarmCount,
      uint64_t outstandingPackets,
      std::string type,
      std::chrono::microseconds refTime);
  ~QLogLossAlarmEvent() override = default;
  PacketNum largestSent;
  uint64_t alarmCount;
  uint64_t outstandingPackets;
  std::string type;
  folly::dynamic toDynamic() const override;
};

class QLogPacketsLostEvent : public QLogEvent {
 public:
  QLogPacketsLostEvent(
      PacketNum largestLostPacketNum,
      uint64_t lostBytes,
      uint64_t lostPackets,
      std::chrono::microseconds refTime);
  ~QLogPacketsLostEvent() override = default;
  PacketNum largestLostPacketNum;
  uint64_t lostBytes;
  uint64_t lostPackets;
  folly::dynamic toDynamic() const override;
};

class QLogTransportStateUpdateEvent : public QLogEvent {
 public:
  QLogTransportStateUpdateEvent(
      std::string update,
      std::chrono::microseconds refTime);
  ~QLogTransportStateUpdateEvent() override = default;
  std::string update;
  folly::dynamic toDynamic() const override;
};

std::string toString(QLogEventType type);

} // namespace quic
