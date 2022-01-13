/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/QuicConstants.h>
#include <quic/state/StateData.h>

namespace quic {
namespace test {
class MockCongestionController : public CongestionController {
 public:
  ~MockCongestionController() override {}
  MOCK_METHOD1(onRemoveBytesFromInflight, void(uint64_t));
  MOCK_METHOD1(onPacketSent, void(const OutstandingPacket&));
  MOCK_METHOD2(
      onPacketAckOrLoss,
      void(const AckEvent* FOLLY_NULLABLE, const LossEvent* FOLLY_NULLABLE));
  MOCK_CONST_METHOD0(getWritableBytes, uint64_t());
  MOCK_CONST_METHOD0(getCongestionWindow, uint64_t());
  MOCK_METHOD0(onSpuriousLoss, void());
  MOCK_CONST_METHOD0(type, CongestionControlType());
  GMOCK_METHOD2_(, , , setAppIdle, void(bool, TimePoint));
  MOCK_METHOD0(setAppLimited, void());
  GMOCK_METHOD1_(, noexcept, , setBandwidthUtilizationFactor, void(float));
  MOCK_CONST_METHOD0(isInBackgroundMode, bool());
  MOCK_CONST_METHOD0(isAppLimited, bool());
  MOCK_CONST_METHOD1(getStats, void(CongestionControllerStats&));
  MOCK_METHOD1(setExperimental, void(bool));
};

class MockPacer : public Pacer {
 public:
  MOCK_METHOD3(
      refreshPacingRate,
      void(uint64_t, std::chrono::microseconds, TimePoint currentTime));
  MOCK_METHOD1(setPacingRate, void(uint64_t));
  MOCK_METHOD1(setMaxPacingRate, void(uint64_t));
  MOCK_METHOD0(reset, void());
  MOCK_METHOD2(setRttFactor, void(uint8_t, uint8_t));
  MOCK_CONST_METHOD1(
      getTimeUntilNextWrite,
      std::chrono::microseconds(TimePoint));
  MOCK_METHOD1(updateAndGetWriteBatchSize, uint64_t(TimePoint));
  MOCK_CONST_METHOD0(getCachedWriteBatchSize, uint64_t());
  MOCK_METHOD1(setAppLimited, void(bool));
  MOCK_METHOD0(onPacketSent, void());
  MOCK_METHOD0(onPacketsLoss, void());
};

class MockPendingPathRateLimiter : public PendingPathRateLimiter {
 public:
  MockPendingPathRateLimiter() : PendingPathRateLimiter(0) {}
  MOCK_METHOD1(onPacketSent, void(uint64_t));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      currentCredit,
      uint64_t(TimePoint, std::chrono::microseconds));
};

class MockQuicStreamPrioritiesObserver : public QuicStreamPrioritiesObserver {
 public:
  MOCK_METHOD0(onStreamPrioritiesChange, void());
};
} // namespace test
} // namespace quic
