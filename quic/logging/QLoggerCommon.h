/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/logging/BaseQLogger.h>
#include <quic/logging/QLoggerConstants.h>

namespace quic {

class QLoggerCommon : public quic::BaseQLogger {
 public:
  explicit QLoggerCommon(
      quic::VantagePoint vantagePoint,
      std::string protocolType = quic::kHTTP3ProtocolType);
  ~QLoggerCommon() override = default;
  void addPacket(
      const quic::RegularQuicPacket& regularPacket,
      uint64_t packetSize) override;
  void addPacket(
      const quic::VersionNegotiationPacket& versionPacket,
      uint64_t packetSize,
      bool isPacketRecvd) override;
  void addPacket(
      const quic::RetryPacket& retryPacket,
      uint64_t packetSize,
      bool isPacketRecvd) override;
  void addPacket(
      const quic::RegularQuicWritePacket& writePacket,
      uint64_t packetSize) override;
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
      std::string state,
      std::string recoveryState) override;
  void addBandwidthEstUpdate(uint64_t bytes, std::chrono::microseconds interval)
      override;
  void addAppLimitedUpdate() override;
  void addAppUnlimitedUpdate() override;
  void addPacingMetricUpdate(
      uint64_t pacingBurstSizeIn,
      std::chrono::microseconds pacingIntervalIn) override;
  void addPacingObservation(
      std::string actual,
      std::string expected,
      std::string conclusion) override;
  void addAppIdleUpdate(std::string idleEvent, bool idle) override;
  void addPacketDrop(size_t packetSizeIn, std::string dropReasonIn) override;
  void addDatagramReceived(uint64_t dataLen) override;
  void addLossAlarm(
      quic::PacketNum largestSent,
      uint64_t alarmCount,
      uint64_t outstandingPackets,
      std::string type) override;
  void addPacketsLost(
      quic::PacketNum largestLostPacketNum,
      uint64_t lostBytes,
      uint64_t lostPackets) override;
  void addTransportStateUpdate(std::string update) override;
  void addPacketBuffered(
      quic::ProtectionType protectionType,
      uint64_t packetSize) override;
  void addMetricUpdate(
      std::chrono::microseconds latestRtt,
      std::chrono::microseconds mrtt,
      std::chrono::microseconds srtt,
      std::chrono::microseconds ackDelay,
      Optional<std::chrono::microseconds> rttVar = std::nullopt,
      Optional<uint64_t> congestionWindow = std::nullopt,
      Optional<uint64_t> bytesInFlight = std::nullopt,
      Optional<uint64_t> ssthresh = std::nullopt,
      Optional<uint64_t> packetsInFlight = std::nullopt,
      Optional<uint64_t> pacingRateBytesPerSec = std::nullopt,
      Optional<uint32_t> ptoCount = std::nullopt) override;
  void addCongestionStateUpdate(
      Optional<std::string> oldState,
      std::string newState,
      Optional<std::string> trigger) override;
  void addStreamStateUpdate(
      quic::StreamId id,
      std::string update,
      Optional<std::chrono::milliseconds> timeSinceStreamCreation) override;
  void addConnectionMigrationUpdate(bool intentionalMigration) override;
  void addPathValidationEvent(bool success) override;
  void addPriorityUpdate(
      quic::StreamId streamId,
      PriorityQueue::PriorityLogFields priority) override;
  void addL4sWeightUpdate(double l4sWeight, uint32_t newEct1, uint32_t newCe)
      override;
  void addNetworkPathModelUpdate(
      uint64_t inflightHi,
      uint64_t inflightLo,
      uint64_t bandwidthHiBytes,
      std::chrono::microseconds bandwidthHiInterval,
      uint64_t bandwidthLoBytes,
      std::chrono::microseconds bandwidthLoInterval) override;
  void setDcid(Optional<quic::ConnectionId> connID) override;
  void setScid(Optional<quic::ConnectionId> connID) override;

  virtual void logTrace(std::unique_ptr<quic::QLogEvent> event) = 0;
};

} // namespace quic
