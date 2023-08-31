/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <quic/congestion_control/ThrottlingSignalProvider.h>
#include <quic/state/test/Mocks.h>

using namespace ::testing;

namespace quic::test {

TEST(ThrottlingSignalProviderTest, BasicInitSetGetTest) {
  auto mockThrottlingSignalProvider =
      std::make_shared<MockThrottlingSignalProvider>();

  EXPECT_FALSE(
      mockThrottlingSignalProvider->getCurrentThrottlingSignal().has_value());

  ThrottlingSignalProvider::ThrottlingSignal expectedSignal;
  expectedSignal.state =
      ThrottlingSignalProvider::ThrottlingSignal::State::Throttled;
  expectedSignal.maybeBytesToSend = 10000;
  expectedSignal.maybeThrottledRateBytesPerSecond = 187500;
  mockThrottlingSignalProvider->useFakeThrottlingSignal(expectedSignal);
  EXPECT_TRUE(
      mockThrottlingSignalProvider->getCurrentThrottlingSignal().has_value());
  auto signal =
      mockThrottlingSignalProvider->getCurrentThrottlingSignal().value();

  EXPECT_EQ(signal.state, expectedSignal.state);
  EXPECT_EQ(signal.maybeBytesToSend, expectedSignal.maybeBytesToSend);
  EXPECT_EQ(
      signal.maybeThrottledRateBytesPerSecond,
      expectedSignal.maybeThrottledRateBytesPerSecond);
  EXPECT_FALSE(signal.maybeUnthrottledRateBytesPerSecond.has_value());
}
} // namespace quic::test
