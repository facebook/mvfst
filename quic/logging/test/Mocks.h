/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/logging/QLogger.h>

namespace quic::test {
class MockQLogger : public QLogger {
 public:
  MockQLogger() = delete;
  MockQLogger(VantagePoint vp) : QLogger(vp, kHTTP3ProtocolType) {}
  ~MockQLogger() override = default;
  MOCK_METHOD(void, addPacket, (const RegularQuicPacket&, uint64_t));
  MOCK_METHOD(
      void,
      addPacket,
      (const VersionNegotiationPacket&, uint64_t, bool));
  MOCK_METHOD(void, addPacket, (const RetryPacket&, uint64_t, bool));
  MOCK_METHOD(void, addPacket, (const RegularQuicWritePacket&, uint64_t));
  MOCK_METHOD(void, addConnectionClose, (std::string, std::string, bool, bool));
  MOCK_METHOD(void, addTransportSummary, (const TransportSummaryArgs&));
  MOCK_METHOD(
      void,
      addCongestionMetricUpdate,
      (uint64_t, uint64_t, std::string, std::string, std::string));
  MOCK_METHOD(
      void,
      addPacingMetricUpdate,
      (uint64_t, std::chrono::microseconds));
  MOCK_METHOD(
      void,
      addPacingObservation,
      (std::string, std::string, std::string));
  MOCK_METHOD(void, addAppIdleUpdate, (std::string, bool));
  MOCK_METHOD(void, addPacketDrop, (size_t, std::string));
  MOCK_METHOD(void, addDatagramReceived, (uint64_t));
  MOCK_METHOD(void, addLossAlarm, (PacketNum, uint64_t, uint64_t, std::string));
  MOCK_METHOD(void, addPacketsLost, (PacketNum, uint64_t, uint64_t));
  MOCK_METHOD(void, addTransportStateUpdate, (std::string));
  MOCK_METHOD(void, addPacketBuffered, (ProtectionType, uint64_t));
  MOCK_METHOD(
      void,
      addMetricUpdate,
      (std::chrono::microseconds,
       std::chrono::microseconds,
       std::chrono::microseconds,
       std::chrono::microseconds));
  MOCK_METHOD(
      void,
      addStreamStateUpdate,
      (quic::StreamId,
       std::string,
       folly::Optional<std::chrono::milliseconds>));
  MOCK_METHOD(
      void,
      addBandwidthEstUpdate,
      (uint64_t, std::chrono::microseconds));
  MOCK_METHOD(void, addAppLimitedUpdate, ());
  MOCK_METHOD(void, addAppUnlimitedUpdate, ());
  MOCK_METHOD(void, addConnectionMigrationUpdate, (bool));
  MOCK_METHOD(void, addPathValidationEvent, (bool));
  MOCK_METHOD(void, setDcid, (folly::Optional<ConnectionId>));
  MOCK_METHOD(void, setScid, (folly::Optional<ConnectionId>));
  MOCK_METHOD(void, addPriorityUpdate, (quic::StreamId, uint8_t, bool));
};
} // namespace quic::test
