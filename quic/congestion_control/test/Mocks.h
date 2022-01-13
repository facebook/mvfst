/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GMock.h>
#include <quic/congestion_control/Bbr.h>

namespace quic {
namespace test {

class MockMinRttSampler : public BbrCongestionController::MinRttSampler {
 public:
  ~MockMinRttSampler() override = default;

  MOCK_CONST_METHOD0(minRtt, std::chrono::microseconds());
  MOCK_CONST_METHOD0(minRttExpired, bool());
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      newRttSample,
      bool(std::chrono::microseconds, TimePoint));
  GMOCK_METHOD1_(, noexcept, , timestampMinRtt, void(TimePoint));
};

class MockBandwidthSampler : public BbrCongestionController::BandwidthSampler {
 public:
  ~MockBandwidthSampler() override = default;

  MOCK_CONST_METHOD0(getBandwidth, Bandwidth());
  MOCK_CONST_METHOD0(isAppLimited, bool());

  MOCK_METHOD2(
      onPacketAcked,
      void(const CongestionController::AckEvent&, uint64_t));
  MOCK_METHOD0(onAppLimited, void());
  GMOCK_METHOD1_(, noexcept, , setWindowLength, void(const uint64_t));
};

} // namespace test
} // namespace quic
