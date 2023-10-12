/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/TransportSettingsFunctions.h>

#include <folly/portability/GTest.h>

using namespace testing;

namespace quic::test {

class TransportSettingsFunctionsTest : public Test {};

TEST_F(TransportSettingsFunctionsTest, ParseDifferentBoolFormats) {
  std::string testString =
      "{"
      "\"conservativeRecovery\": true, "
      "\"largeProbeRttCwnd\": 1, "
      "\"enableAckAggregationInStartup\": 0, "
      "\"probeRttDisabledIfAppLimited\": false, "
      "\"drainToTarget\": \"0\" "
      "}";
  auto config = parseCongestionControlConfig(testString);
  EXPECT_EQ(config.conservativeRecovery, true);
  EXPECT_EQ(config.largeProbeRttCwnd, true);
  EXPECT_EQ(config.enableAckAggregationInStartup, false);
  EXPECT_EQ(config.probeRttDisabledIfAppLimited, false);
  EXPECT_EQ(config.drainToTarget, false);

  EXPECT_EQ(config.ackFrequencyConfig.has_value(), false);
}

TEST_F(TransportSettingsFunctionsTest, FullConfig) {
  std::string testString =
      "{"
      "\"onlyGrowCwndWhenLimited\": true,"
      "\"additiveIncreaseAfterHystart\": true, "
      "\"conservativeRecovery\": true, "
      "\"largeProbeRttCwnd\": 1, "
      "\"enableAckAggregationInStartup\": \"true\", "
      "\"probeRttDisabledIfAppLimited\": 2, "
      "\"drainToTarget\": \"1\", "
      "\"leaveHeadroomForCwndLimited\": \"1\", "
      "\"ackFrequencyConfig\": {"
      "\"ackElicitingThreshold\": 99, "
      "\"reorderingThreshold\": \"88\", "
      "\"minRttDivisor\": 77, "
      "\"useSmallThresholdDuringStartup\": true"
      "},"
      "\"ignoreInflightHi\": true, "
      "\"ignoreLoss\": true, "
      "\"advanceCycleAfterStartup\": false "
      "}";
  auto config = parseCongestionControlConfig(testString);
  EXPECT_EQ(config.conservativeRecovery, true);
  EXPECT_EQ(config.largeProbeRttCwnd, true);
  EXPECT_EQ(config.enableAckAggregationInStartup, true);
  EXPECT_EQ(config.probeRttDisabledIfAppLimited, true);
  EXPECT_EQ(config.drainToTarget, true);
  EXPECT_EQ(config.additiveIncreaseAfterHystart, true);
  EXPECT_EQ(config.onlyGrowCwndWhenLimited, true);
  EXPECT_EQ(config.leaveHeadroomForCwndLimited, true);
  EXPECT_EQ(config.ignoreInflightHi, true);
  EXPECT_EQ(config.ignoreLoss, true);
  EXPECT_EQ(config.advanceCycleAfterStartup, false);

  ASSERT_TRUE(config.ackFrequencyConfig.has_value());
  EXPECT_EQ(config.ackFrequencyConfig->ackElicitingThreshold, 99);
  EXPECT_EQ(config.ackFrequencyConfig->reorderingThreshold, 88);
  EXPECT_EQ(config.ackFrequencyConfig->minRttDivisor, 77);
  EXPECT_EQ(config.ackFrequencyConfig->useSmallThresholdDuringStartup, true);
}

TEST_F(TransportSettingsFunctionsTest, UnspecifiedFieldsAreDefaulted) {
  std::string testString =
      "{"
      "\"ackFrequencyConfig\": {"
      "\"minRttDivisor\": 77, "
      "\"useSmallThresholdDuringStartup\": true "
      "}"
      "}";
  auto config = parseCongestionControlConfig(testString);
  EXPECT_EQ(config.conservativeRecovery, false);
  EXPECT_EQ(config.largeProbeRttCwnd, false);
  EXPECT_EQ(config.enableAckAggregationInStartup, false);
  EXPECT_EQ(config.probeRttDisabledIfAppLimited, false);
  EXPECT_EQ(config.drainToTarget, false);
  EXPECT_EQ(config.ignoreInflightHi, false);
  EXPECT_EQ(config.ignoreLoss, false);
  EXPECT_EQ(config.advanceCycleAfterStartup, true);

  ASSERT_TRUE(config.ackFrequencyConfig.has_value());
  EXPECT_EQ(
      config.ackFrequencyConfig->ackElicitingThreshold,
      kDefaultRxPacketsBeforeAckAfterInit);
  EXPECT_EQ(
      config.ackFrequencyConfig->reorderingThreshold, kReorderingThreshold);
  EXPECT_EQ(config.ackFrequencyConfig->minRttDivisor, 77);
  EXPECT_EQ(config.ackFrequencyConfig->useSmallThresholdDuringStartup, true);
}

TEST_F(TransportSettingsFunctionsTest, ThrowOnWrongType) {
  std::string testString =
      "{"
      "\"conservativeRecovery\": \"bla\""
      "}";
  EXPECT_THROW(parseCongestionControlConfig(testString), std::runtime_error);

  EXPECT_FALSE(tryParseCongestionControlConfig(testString).has_value());
}

TEST_F(TransportSettingsFunctionsTest, ThrowOnWrongTypeNested) {
  std::string testString =
      "{"
      "\"ackFrequencyConfig\": {"
      "\"minRttDivisor\": \"abc\", "
      "\"useSmallThresholdDuringStartup\": true "
      "}"
      "}";
  EXPECT_THROW(parseCongestionControlConfig(testString), std::runtime_error);

  EXPECT_FALSE(tryParseCongestionControlConfig(testString).has_value());
}

TEST_F(TransportSettingsFunctionsTest, ThrowOnMalformedJson) {
  std::string testString =
      "{"
      "\"conservativeRecovery\": true," // extra comma
      "}";
  EXPECT_THROW(parseCongestionControlConfig(testString), std::runtime_error);

  EXPECT_FALSE(tryParseCongestionControlConfig(testString).has_value());
}

TEST_F(TransportSettingsFunctionsTest, IgnoreUnknownFields) {
  std::string testString =
      "{"
      "\"conservativeRecovery\": true, "
      "\"unknownField\": 1"
      "}";
  auto config = parseCongestionControlConfig(testString);
  EXPECT_EQ(config.conservativeRecovery, true);
}

} // namespace quic::test
