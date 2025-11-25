/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/logging/QLoggerCommon.h>

namespace quic {

QLoggerCommon::QLoggerCommon(
    quic::VantagePoint vantagePoint,
    std::string protocolTypeIn)
    : BaseQLogger(vantagePoint, std::move(protocolTypeIn)) {}

void QLoggerCommon::addPacket(
    const quic::RegularQuicPacket& regularPacket,
    uint64_t packetSize) {
  logTrace(createPacketEvent(regularPacket, packetSize));
}

void QLoggerCommon::addPacket(
    const quic::VersionNegotiationPacket& versionPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  logTrace(createPacketEvent(versionPacket, packetSize, isPacketRecvd));
}

void QLoggerCommon::addPacket(
    const quic::RetryPacket& retryPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  logTrace(createPacketEvent(retryPacket, packetSize, isPacketRecvd));
}

void QLoggerCommon::addPacket(
    const quic::RegularQuicWritePacket& writePacket,
    uint64_t packetSize) {
  logTrace(createPacketEvent(writePacket, packetSize));
}

void QLoggerCommon::addConnectionClose(
    std::string error,
    std::string reason,
    bool drainConnection,
    bool sendCloseImmediately) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogConnectionCloseEvent>(
          std::move(error),
          std::move(reason),
          drainConnection,
          sendCloseImmediately,
          refTime));
}

void QLoggerCommon::addTransportSummary(const TransportSummaryArgs& args) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  logTrace(
      std::make_unique<quic::QLogTransportSummaryEvent>(
          args.totalBytesSent,
          args.totalBytesRecvd,
          args.sumCurWriteOffset,
          args.sumMaxObservedOffset,
          args.sumCurStreamBufferLen,
          args.totalBytesRetransmitted,
          args.totalStreamBytesCloned,
          args.totalBytesCloned,
          args.totalCryptoDataWritten,
          args.totalCryptoDataRecvd,
          args.currentWritableBytes,
          args.currentConnFlowControl,
          args.totalPacketsSpuriouslyMarkedLost,
          args.finalPacketLossReorderingThreshold,
          args.finalPacketLossTimeReorderingThreshDividend,
          args.usedZeroRtt,
          args.quicVersion,
          args.initialPacketsReceived,
          args.uniqueInitialCryptoFramesReceived,
          args.timeUntilLastInitialCryptoFrameReceived,
          args.alpn,
          args.namedGroup,
          args.pskType,
          args.echStatus,
          refTime));
}

void QLoggerCommon::addCongestionMetricUpdate(
    uint64_t bytesInFlight,
    uint64_t currentCwnd,
    std::string congestionEvent,
    std::string state,
    std::string recoveryState) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogCongestionMetricUpdateEvent>(
          bytesInFlight,
          currentCwnd,
          std::move(congestionEvent),
          std::move(state),
          std::move(recoveryState),
          refTime));
}

void QLoggerCommon::addBandwidthEstUpdate(
    uint64_t bytes,
    std::chrono::microseconds interval) {
  logTrace(
      std::make_unique<quic::QLogBandwidthEstUpdateEvent>(
          bytes,
          interval,

          std::chrono::duration_cast<std::chrono::microseconds>(
              std::chrono::steady_clock::now().time_since_epoch())));
}

void QLoggerCommon::addAppLimitedUpdate() {
  logTrace(
      std::make_unique<quic::QLogAppLimitedUpdateEvent>(
          true,

          std::chrono::duration_cast<std::chrono::microseconds>(
              std::chrono::steady_clock::now().time_since_epoch())));
}

void QLoggerCommon::addAppUnlimitedUpdate() {
  logTrace(
      std::make_unique<quic::QLogAppLimitedUpdateEvent>(
          false,

          std::chrono::duration_cast<std::chrono::microseconds>(
              std::chrono::steady_clock::now().time_since_epoch())));
}

void QLoggerCommon::addPacketDrop(size_t packetSize, std::string dropReason) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogPacketDropEvent>(
          packetSize, std::move(dropReason), refTime));
}

void QLoggerCommon::addPacingMetricUpdate(
    uint64_t pacingBurstSizeIn,
    std::chrono::microseconds pacingIntervalIn) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogPacingMetricUpdateEvent>(
          pacingBurstSizeIn, pacingIntervalIn, refTime));
}

void QLoggerCommon::addPacingObservation(
    std::string actual,
    std::string expected,
    std::string conclusion) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogPacingObservationEvent>(
          std::move(actual),
          std::move(expected),
          std::move(conclusion),
          refTime));
}

void QLoggerCommon::addAppIdleUpdate(std::string idleEvent, bool idle) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogAppIdleUpdateEvent>(
          std::move(idleEvent), idle, refTime));
}

void QLoggerCommon::addDatagramReceived(uint64_t dataLen) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(std::make_unique<quic::QLogDatagramReceivedEvent>(dataLen, refTime));
}

void QLoggerCommon::addLossAlarm(
    quic::PacketNum largestSent,
    uint64_t alarmCount,
    uint64_t outstandingPackets,
    std::string type) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogLossAlarmEvent>(
          largestSent,
          alarmCount,
          outstandingPackets,
          std::move(type),
          refTime));
}

void QLoggerCommon::addPacketsLost(
    quic::PacketNum largestLostPacketNum,
    uint64_t lostBytes,
    uint64_t lostPackets) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogPacketsLostEvent>(
          largestLostPacketNum, lostBytes, lostPackets, refTime));
}

void QLoggerCommon::addTransportStateUpdate(std::string update) {
  // Filter out invalid ConnectionState enum values.
  static const std::unordered_set<std::string> validStates = {
      "attempted",
      "handshake_started",
      "handshake_complete",
      "closed",
      "peer_validated",
      "early_write",
      "handshake_confirmed",
      "closing",
      "draining"};

  if (validStates.find(update) == validStates.end()) {
    return; // Skip invalid states
  }

  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogTransportStateUpdateEvent>(
          std::move(update), refTime));
}

void QLoggerCommon::addPacketBuffered(
    quic::ProtectionType protectionType,
    uint64_t packetSize) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogPacketBufferedEvent>(
          protectionType, packetSize, refTime));
}

void QLoggerCommon::addMetricUpdate(
    std::chrono::microseconds latestRtt,
    std::chrono::microseconds mrtt,
    std::chrono::microseconds srtt,
    std::chrono::microseconds ackDelay,
    Optional<std::chrono::microseconds> rttVar,
    Optional<uint64_t> congestionWindow,
    Optional<uint64_t> bytesInFlight,
    Optional<uint64_t> ssthresh,
    Optional<uint64_t> packetsInFlight,
    Optional<uint64_t> pacingRateBytesPerSec,
    Optional<uint32_t> ptoCount) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogMetricUpdateEvent>(
          latestRtt,
          mrtt,
          srtt,
          ackDelay,
          refTime,
          rttVar,
          congestionWindow,
          bytesInFlight,
          ssthresh,
          packetsInFlight,
          pacingRateBytesPerSec,
          ptoCount));
}

void QLoggerCommon::addCongestionStateUpdate(
    Optional<std::string> oldState,
    std::string newState,
    Optional<std::string> trigger) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogCongestionStateUpdateEvent>(
          std::move(oldState),
          std::move(newState),
          std::move(trigger),
          refTime));
}

void QLoggerCommon::addStreamStateUpdate(
    quic::StreamId id,
    std::string update,
    Optional<std::chrono::milliseconds> timeSinceStreamCreation) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  logTrace(
      std::make_unique<quic::QLogStreamStateUpdateEvent>(
          id,
          std::move(update),
          std::move(timeSinceStreamCreation),
          vantagePoint,
          refTime));
}

void QLoggerCommon::addConnectionMigrationUpdate(bool intentionalMigration) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  logTrace(
      std::make_unique<quic::QLogConnectionMigrationEvent>(
          intentionalMigration, vantagePoint, refTime));
}

void QLoggerCommon::addPathValidationEvent(bool success) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  logTrace(
      std::make_unique<quic::QLogPathValidationEvent>(
          success, vantagePoint, refTime));
}

void QLoggerCommon::addPriorityUpdate(
    quic::StreamId streamId,
    PriorityQueue::PriorityLogFields priority) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  logTrace(
      std::make_unique<quic::QLogPriorityUpdateEvent>(
          streamId, std::move(priority), refTime));
}

void QLoggerCommon::addL4sWeightUpdate(
    double l4sWeight,
    uint32_t newEct1,
    uint32_t newCe) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  logTrace(
      std::make_unique<quic::QLogL4sWeightUpdateEvent>(
          l4sWeight, newEct1, newCe, refTime));
}

void QLoggerCommon::addNetworkPathModelUpdate(
    uint64_t inflightHi,
    uint64_t inflightLo,
    uint64_t bandwidthHiBytes,
    std::chrono::microseconds bandwidthHiInterval,
    uint64_t bandwidthLoBytes,
    std::chrono::microseconds bandwidthLoInterval) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  logTrace(
      std::make_unique<quic::QLogNetworkPathModelUpdateEvent>(
          inflightHi,
          inflightLo,
          bandwidthHiBytes,
          bandwidthHiInterval,
          bandwidthLoBytes,
          bandwidthLoInterval,
          refTime));
}

void QLoggerCommon::setDcid(Optional<quic::ConnectionId> connID) {
  if (connID.has_value()) {
    dcid = connID;
  }
}

void QLoggerCommon::setScid(Optional<quic::ConnectionId> connID) {
  if (connID.has_value()) {
    scid = connID;
  }
}

} // namespace quic
