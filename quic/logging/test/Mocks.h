/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
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
  MOCK_METHOD2(addPacket, void(const RegularQuicPacket&, uint64_t));
  MOCK_METHOD3(
      addPacket,
      void(const VersionNegotiationPacket&, uint64_t, bool));
  MOCK_METHOD3(addPacket, void(const RetryPacket&, uint64_t, bool));
  MOCK_METHOD2(addPacket, void(const RegularQuicWritePacket&, uint64_t));
  MOCK_METHOD4(addConnectionClose, void(std::string, std::string, bool, bool));
  MOCK_METHOD10(
      addTransportSummary,
      void(
          uint64_t,
          uint64_t,
          uint64_t,
          uint64_t,
          uint64_t,
          uint64_t,
          uint64_t,
          uint64_t,
          uint64_t,
          uint64_t));
  MOCK_METHOD5(
      addCongestionMetricUpdate,
      void(uint64_t, uint64_t, std::string, std::string, std::string));
  MOCK_METHOD2(
      addPacingMetricUpdate,
      void(uint64_t, std::chrono::microseconds));
  MOCK_METHOD3(
      addPacingObservation,
      void(std::string, std::string, std::string));
  MOCK_METHOD2(addAppIdleUpdate, void(std::string, bool));
  MOCK_METHOD2(addPacketDrop, void(size_t, std::string));
  MOCK_METHOD1(addDatagramReceived, void(uint64_t));
  MOCK_METHOD4(addLossAlarm, void(PacketNum, uint64_t, uint64_t, std::string));
  MOCK_METHOD3(addPacketsLost, void(PacketNum, uint64_t, uint64_t));
  MOCK_METHOD1(addTransportStateUpdate, void(std::string));
  MOCK_METHOD3(addPacketBuffered, void(PacketNum, ProtectionType, uint64_t));
  MOCK_METHOD4(
      addMetricUpdate,
      void(
          std::chrono::microseconds,
          std::chrono::microseconds,
          std::chrono::microseconds,
          std::chrono::microseconds));
  MOCK_METHOD3(
      addStreamStateUpdate,
      void(
          quic::StreamId,
          std::string,
          folly::Optional<std::chrono::milliseconds>));
  MOCK_METHOD2(
      addBandwidthEstUpdate,
      void(uint64_t, std::chrono::microseconds));
  MOCK_METHOD0(addAppLimitedUpdate, void());
  MOCK_METHOD0(addAppUnlimitedUpdate, void());
  MOCK_METHOD1(addConnectionMigrationUpdate, void(bool));
  MOCK_METHOD1(addPathValidationEvent, void(bool));
  MOCK_METHOD1(setDcid, void(folly::Optional<ConnectionId>));
  MOCK_METHOD1(setScid, void(folly::Optional<ConnectionId>));
  MOCK_METHOD3(addPriorityUpdate, void(quic::StreamId, uint8_t, bool));
};
} // namespace quic::test
