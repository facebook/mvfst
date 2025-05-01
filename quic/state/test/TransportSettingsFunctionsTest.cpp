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

TEST_F(TransportSettingsFunctionsTest, ParseFloats) {
  std::string testString =
      "{"
      "\"overrideCruisePacingGain\": 7.9, "
      "\"overrideCruiseCwndGain\": -0.1, "
      "\"overrideStartupPacingGain\": 2.1 "
      "}";
  auto config = parseCongestionControlConfig(testString);
  EXPECT_EQ(config.overrideCruisePacingGain, 7.9f);
  EXPECT_EQ(config.overrideCruiseCwndGain, -0.1f);
  EXPECT_EQ(config.overrideStartupPacingGain, 2.1f);
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
      "\"ignoreInflightLongTerm\": true, "
      "\"ignoreShortTerm\": true, "
      "\"exitStartupOnLoss\": false, "
      "\"enableRecoveryInStartup\": false, "
      "\"enableRecoveryInProbeStates\": false, "
      "\"enableRenoCoexistence\": true, "
      "\"paceInitCwnd\": false, "
      "\"overrideCruisePacingGain\": 7.9, "
      "\"overrideCruiseCwndGain\": -0.1, "
      "\"overrideStartupPacingGain\": -0.5, "
      "\"overrideBwShortBeta\": 0.8 "
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
  EXPECT_EQ(config.ignoreInflightLongTerm, true);
  EXPECT_EQ(config.ignoreShortTerm, true);
  EXPECT_EQ(config.exitStartupOnLoss, false);
  EXPECT_EQ(config.enableRecoveryInStartup, false);
  EXPECT_EQ(config.enableRecoveryInProbeStates, false);
  EXPECT_EQ(config.enableRenoCoexistence, true);
  EXPECT_EQ(config.paceInitCwnd, false);
  EXPECT_EQ(config.overrideCruisePacingGain, 7.9f);
  EXPECT_EQ(config.overrideCruiseCwndGain, -0.1f);
  EXPECT_EQ(config.overrideStartupPacingGain, -0.5f);
  EXPECT_EQ(config.overrideBwShortBeta, 0.8f);

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
  EXPECT_EQ(config.ignoreInflightLongTerm, false);
  EXPECT_EQ(config.ignoreShortTerm, false);
  EXPECT_EQ(config.exitStartupOnLoss, true);
  EXPECT_EQ(config.enableRecoveryInStartup, true);
  EXPECT_EQ(config.enableRecoveryInProbeStates, true);
  EXPECT_EQ(config.enableRenoCoexistence, false);
  EXPECT_EQ(config.overrideCruisePacingGain, -1.0f);
  EXPECT_EQ(config.overrideCruiseCwndGain, -1.0f);
  EXPECT_EQ(config.overrideStartupPacingGain, -1.0f);
  EXPECT_EQ(config.overrideBwShortBeta, 0.0f);

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

TEST_F(TransportSettingsFunctionsTest, OldAliases) {
  std::string testString =
      "{"
      "\"ignoreInflightHi\": true, "
      "\"ignoreLoss\": true"
      "}";
  auto config = parseCongestionControlConfig(testString);
  EXPECT_EQ(config.ignoreInflightLongTerm, true);
  EXPECT_EQ(config.ignoreShortTerm, true);
}

TEST_F(TransportSettingsFunctionsTest, NewAliasTakesPrecendence) {
  std::string testString =
      "{"
      "\"ignoreInflightLongTerm\": false,"
      "\"ignoreShortTerm\": false,"
      "\"ignoreInflightHi\": true, "
      "\"ignoreLoss\": true"
      "}";
  auto config = parseCongestionControlConfig(testString);
  EXPECT_EQ(config.ignoreInflightLongTerm, false);
  EXPECT_EQ(config.ignoreShortTerm, false);
}

} // namespace quic::test
