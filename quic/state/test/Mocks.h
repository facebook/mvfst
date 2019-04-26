/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook. All Rights Reserved.
#pragma once

#include <folly/portability/GMock.h>
#include <quic/QuicConstants.h>

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
  GMOCK_METHOD1_(, , , setConnectionEmulation, void(uint8_t));
  MOCK_METHOD1(setApplicationLimited, void(bool));
  MOCK_CONST_METHOD0(canBePaced, bool());
  MOCK_CONST_METHOD0(type, CongestionControlType());
  GMOCK_METHOD1_(, , , getPacingRate, uint64_t(TimePoint));
  GMOCK_METHOD1_(, , , markPacerTimeoutScheduled, void(TimePoint));
  MOCK_CONST_METHOD0(getPacingInterval, std::chrono::microseconds());
  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      setMinimalPacingInterval,
      void(std::chrono::microseconds));
  GMOCK_METHOD2_(, , , setAppLimited, void(bool, TimePoint));
  MOCK_CONST_METHOD0(isAppLimited, bool());
};
} // namespace test
} // namespace quic
