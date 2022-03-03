/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <quic/congestion_control/Bbr.h>

namespace quic {
namespace test {

class MockMinRttSampler : public BbrCongestionController::MinRttSampler {
 public:
  ~MockMinRttSampler() override = default;

  MOCK_METHOD(std::chrono::microseconds, minRtt, (), (const));
  MOCK_METHOD(bool, minRttExpired, (), (const));
  MOCK_METHOD(
      bool,
      newRttSample,
      (std::chrono::microseconds, TimePoint),
      (noexcept));
  MOCK_METHOD(void, timestampMinRtt, (TimePoint), (noexcept));
};

class MockBandwidthSampler : public BbrCongestionController::BandwidthSampler {
 public:
  ~MockBandwidthSampler() override = default;

  MOCK_METHOD(Bandwidth, getBandwidth, (), (const));
  MOCK_METHOD(Bandwidth, getLatestSample, (), (const));
  MOCK_METHOD(bool, isAppLimited, (), (const));

  MOCK_METHOD(
      void,
      onPacketAcked,
      (const CongestionController::AckEvent&, uint64_t));
  MOCK_METHOD(void, onAppLimited, ());
  MOCK_METHOD(void, setWindowLength, (const uint64_t), (noexcept));
};

} // namespace test
} // namespace quic
