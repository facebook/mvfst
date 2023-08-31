/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/QuicConstants.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/state/StateData.h>

namespace quic {
namespace test {

class MockCongestionControllerFactory : public CongestionControllerFactory {
 public:
  MOCK_METHOD(
      std::unique_ptr<CongestionController>,
      makeCongestionController,
      (QuicConnectionStateBase&, CongestionControlType));
};

class MockCongestionController : public CongestionController {
 public:
  ~MockCongestionController() override {}
  MOCK_METHOD(void, onRemoveBytesFromInflight, (uint64_t));
  MOCK_METHOD(void, onPacketSent, (const OutstandingPacketWrapper&));
  MOCK_METHOD(
      void,
      onPacketAckOrLoss,
      (const AckEvent* FOLLY_NULLABLE, const LossEvent* FOLLY_NULLABLE));
  MOCK_METHOD(uint64_t, getWritableBytes, (), (const));
  MOCK_METHOD(uint64_t, getCongestionWindow, (), (const));
  MOCK_METHOD(folly::Optional<Bandwidth>, getBandwidth, (), (const));
  MOCK_METHOD(void, onSpuriousLoss, ());
  MOCK_METHOD(CongestionControlType, type, (), (const));
  MOCK_METHOD(void, setAppIdle, (bool, TimePoint));
  MOCK_METHOD(void, setAppLimited, ());
  MOCK_METHOD(void, setBandwidthUtilizationFactor, (float), (noexcept));
  MOCK_METHOD(bool, isInBackgroundMode, (), (const));
  MOCK_METHOD(bool, isAppLimited, (), (const));
  MOCK_METHOD(void, getStats, (CongestionControllerStats&), (const));
  MOCK_METHOD(void, setExperimental, (bool));
};

class MockPacketProcessor : public PacketProcessor {
 public:
  ~MockPacketProcessor() override = default;
  MOCK_METHOD(
      void,
      onPacketSent,
      (const OutstandingPacketWrapper&),
      (override));
  MOCK_METHOD(void, onPacketAck, (const AckEvent* FOLLY_NULLABLE), (override));
  MOCK_METHOD(
      void,
      onPacketDestroyed,
      (const OutstandingPacketWrapper&),
      (override));
  MOCK_METHOD(folly::Optional<PrewriteRequest>, prewrite, (), (override));
};

class MockThrottlingSignalProvider : public ThrottlingSignalProvider {
 public:
  ~MockThrottlingSignalProvider() override = default;
  MOCK_METHOD(
      folly::Optional<ThrottlingSignalProvider::ThrottlingSignal>,
      getCurrentThrottlingSignal,
      (),
      (override));

  void useFakeThrottlingSignal(
      ThrottlingSignalProvider::ThrottlingSignal signal) {
    ON_CALL(*this, getCurrentThrottlingSignal)
        .WillByDefault(::testing::Return(std::move(signal)));
  }
};

class MockPacer : public Pacer {
 public:
  MOCK_METHOD(
      void,
      refreshPacingRate,
      (uint64_t, std::chrono::microseconds, TimePoint currentTime));
  MOCK_METHOD(void, setPacingRate, (uint64_t));
  MOCK_METHOD(void, setMaxPacingRate, (uint64_t));
  MOCK_METHOD(void, reset, ());
  MOCK_METHOD(void, setRttFactor, (uint8_t, uint8_t));
  MOCK_METHOD(
      std::chrono::microseconds,
      getTimeUntilNextWrite,
      (TimePoint),
      (const));
  MOCK_METHOD(uint64_t, updateAndGetWriteBatchSize, (TimePoint));
  MOCK_METHOD(uint64_t, getCachedWriteBatchSize, (), (const));
  MOCK_METHOD(void, setAppLimited, (bool));
  MOCK_METHOD(void, onPacketSent, ());
  MOCK_METHOD(void, onPacketsLoss, ());
  MOCK_METHOD(void, setExperimental, (bool));
};

class MockPendingPathRateLimiter : public PendingPathRateLimiter {
 public:
  MockPendingPathRateLimiter() : PendingPathRateLimiter(0) {}
  MOCK_METHOD(void, onPacketSent, (uint64_t));
  MOCK_METHOD(
      uint64_t,
      currentCredit,
      (TimePoint, std::chrono::microseconds),
      (noexcept));
};

class MockQuicStreamPrioritiesObserver : public QuicStreamPrioritiesObserver {
 public:
  MOCK_METHOD(void, onStreamPrioritiesChange, ());
};
} // namespace test
} // namespace quic
