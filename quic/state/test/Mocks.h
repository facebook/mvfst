/*
 * Copyright (c) Facebook, Inc. and its affiliates.
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
      void(folly::Optional<AckEvent>, folly::Optional<LossEvent>));
  MOCK_CONST_METHOD0(getWritableBytes, uint64_t());
  MOCK_CONST_METHOD0(getCongestionWindow, uint64_t());
  MOCK_METHOD0(onSpuriousLoss, void());
  MOCK_CONST_METHOD0(type, CongestionControlType());
  GMOCK_METHOD2_(, , , setAppIdle, void(bool, TimePoint));
  MOCK_METHOD0(setAppLimited, void());
  MOCK_CONST_METHOD0(isAppLimited, bool());
};

class MockPacer : public Pacer {
 public:
  MOCK_METHOD2(refreshPacingRate, void(uint64_t, std::chrono::microseconds));
  MOCK_METHOD2(setPacingRate, void(QuicConnectionStateBase&, uint64_t));
  MOCK_METHOD1(onPacedWriteScheduled, void(TimePoint));
  MOCK_CONST_METHOD0(getTimeUntilNextWrite, std::chrono::microseconds());
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
} // namespace test
} // namespace quic
