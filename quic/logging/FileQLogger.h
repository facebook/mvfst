/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <fstream>
#include <sstream>

#include <folly/compression/Compression.h>
#include <folly/dynamic.h>
#include <folly/logging/AsyncFileWriter.h>
#include <quic/codec/Types.h>
#include <quic/logging/BaseQLogger.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QLoggerTypes.h>

namespace quic {

class FileQLogger : public BaseQLogger {
  const static uint64_t kCompressionBufferSize = 1024; // 1 KB

 public:
  inline const static std::string kQlogExtension = ".qlog";
  inline const static std::string kCompressedQlogExtension = ".qlog.gz";

  using QLogger::TransportSummaryArgs;
  std::vector<std::unique_ptr<QLogEvent>> logs;
  FileQLogger(
      VantagePoint vantagePointIn,
      std::string protocolTypeIn = kHTTP3ProtocolType,
      std::string path = "",
      bool prettyJson = true,
      bool streaming = false,
      bool compress = false)
      : BaseQLogger(vantagePointIn, std::move(protocolTypeIn)),
        path_(std::move(path)),
        prettyJson_(prettyJson),
        streaming_(streaming),
        compress_{compress} {}

  ~FileQLogger() override {
    if (streaming_ && dcid.hasValue()) {
      finishStream();
    }
  }
  void addPacket(const RegularQuicPacket& regularPacket, uint64_t packetSize)
      override;
  void addPacket(
      const VersionNegotiationPacket& versionPacket,
      uint64_t packetSize,
      bool isPacketRecvd) override;
  void addPacket(const RegularQuicWritePacket& writePacket, uint64_t packetSize)
      override;
  void addPacket(
      const RetryPacket& retryPacket,
      uint64_t packetSize,
      bool isPacketRecvd) override;
  void addConnectionClose(
      std::string error,
      std::string reason,
      bool drainConnection,
      bool sendCloseImmediately) override;
  void addTransportSummary(const TransportSummaryArgs& args) override;
  void addCongestionMetricUpdate(
      uint64_t bytesInFlight,
      uint64_t currentCwnd,
      std::string congestionEvent,
      std::string state = "",
      std::string recoveryState = "") override;
  void addPacingMetricUpdate(
      uint64_t pacingBurstSizeIn,
      std::chrono::microseconds pacingIntervalIn) override;
  void addPacingObservation(
      std::string actual,
      std::string expected,
      std::string conclusion) override;
  void addBandwidthEstUpdate(uint64_t bytes, std::chrono::microseconds interval)
      override;
  void addAppLimitedUpdate() override;
  void addAppUnlimitedUpdate() override;
  void addAppIdleUpdate(std::string idleEvent, bool idle) override;
  void addPacketDrop(size_t packetSize, std::string dropReasonIn) override;
  void addDatagramReceived(uint64_t dataLen) override;
  void addLossAlarm(
      PacketNum largestSent,
      uint64_t alarmCount,
      uint64_t outstandingPackets,
      std::string type) override;
  void addPacketsLost(
      PacketNum largestLostPacketNum,
      uint64_t lostBytes,
      uint64_t lostPackets) override;
  void addTransportStateUpdate(std::string update) override;
  void addPacketBuffered(ProtectionType protectionType, uint64_t packetSize)
      override;
  void addMetricUpdate(
      std::chrono::microseconds latestRtt,
      std::chrono::microseconds mrtt,
      std::chrono::microseconds srtt,
      std::chrono::microseconds ackDelay) override;
  void addStreamStateUpdate(
      StreamId id,
      std::string update,
      folly::Optional<std::chrono::milliseconds> timeSinceStreamCreation)
      override;
  virtual void addConnectionMigrationUpdate(bool intentionalMigration) override;
  virtual void addPathValidationEvent(bool success) override;
  void addPriorityUpdate(
      quic::StreamId streamId,
      uint8_t urgency,
      bool incremental) override;

  void outputLogsToFile(const std::string& path, bool prettyJson);
  folly::dynamic toDynamic() const;
  folly::dynamic toDynamicBase() const;
  folly::dynamic generateSummary(
      size_t numEvents,
      std::chrono::microseconds startTime,
      std::chrono::microseconds endTime) const;

  void setDcid(folly::Optional<ConnectionId> connID) override;
  void setScid(folly::Optional<ConnectionId> connID) override;

 private:
  void setupStream();
  void writeToStream(folly::StringPiece message);
  void finishStream();
  void handleEvent(std::unique_ptr<QLogEvent> event);

  std::unique_ptr<folly::AsyncFileWriter> writer_;
  std::unique_ptr<folly::io::StreamCodec> compressionCodec_;
  std::unique_ptr<folly::IOBuf> compressionBuffer_;

  std::string path_;
  std::string basePadding_ = "  ";
  std::string eventsPadding_ = "";
  std::string eventLine_;
  std::string token_;
  std::string endLine_;
  std::stringstream baseJson_;

  bool prettyJson_;
  bool streaming_;
  bool compress_;
  int numEvents_ = 0;
  std::chrono::microseconds startTime_ = std::chrono::microseconds::zero();
  std::chrono::microseconds endTime_;

  size_t pos_;
};
} // namespace quic
