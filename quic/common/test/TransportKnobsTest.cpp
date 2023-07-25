/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicConstants.h>
#include <quic/common/TransportKnobs.h>

#include <folly/Format.h>
#include <folly/portability/GTest.h>

namespace quic {
namespace test {

struct QuicKnobsParsingTestFixture {
  std::string serializedKnobs;
  bool expectError;
  TransportKnobParams expectParams;
};

void run(const QuicKnobsParsingTestFixture& fixture) {
  auto result = parseTransportKnobs(fixture.serializedKnobs);
  if (fixture.expectError) {
    EXPECT_FALSE(result.hasValue());
  } else {
    ASSERT_TRUE(result.hasValue());
    EXPECT_EQ(result->size(), fixture.expectParams.size());
    for (size_t i = 0; i < result->size(); i++) {
      auto& actualKnob = (*result)[i];
      auto& expectKnob = fixture.expectParams[i];
      EXPECT_EQ(actualKnob.id, expectKnob.id) << "Knob " << i;
      EXPECT_EQ(actualKnob.val, expectKnob.val) << "Knob " << i;
    }
  }
}

TEST(QuicKnobsParsingTest, Simple) {
  QuicKnobsParsingTestFixture fixture = {
      "{ \"0\": 1,"
      "  \"11\": 5,"
      "  \"19\": 6,"
      "  \"2\": 3"
      "  }",
      false,
      {{0, uint64_t{1}},
       {2, uint64_t{3}},
       {11, uint64_t{5}},
       {19, uint64_t{6}}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ObjectValue) {
  QuicKnobsParsingTestFixture fixture = {
      "{ \"1\": "
      "  {"
      "  \"0\" : 1"
      "  }"
      "}",
      true,
      {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidJson) {
  QuicKnobsParsingTestFixture fixture = {
      "{\"0\": "
      " \"1\": "
      "  {"
      "  \"0\" : 1"
      "  }"
      "}",
      true,
      {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, Characters) {
  QuicKnobsParsingTestFixture fixture = {"{ \"o\" : 1 }", true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, NegativeNumbers) {
  QuicKnobsParsingTestFixture fixture = {"{ \"10\" : -1 }", true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ValidCCAlgorithm) {
  auto key = static_cast<uint64_t>(TransportKnobParamId::CC_ALGORITHM_KNOB);
  uint64_t val =
      static_cast<uint64_t>(congestionControlStrToType("cubic").value());
  std::string args = fmt::format(R"({{"{}" : "cubic"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      args, false, {{.id = key, .val = val}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidCCAlgorithm) {
  auto key = static_cast<uint64_t>(TransportKnobParamId::CC_ALGORITHM_KNOB);
  std::string args = fmt::format(R"({{"{}" : "foo"}})", key);
  QuicKnobsParsingTestFixture fixture = {args, true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidStringParam) {
  auto key = static_cast<uint64_t>(
      TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE);
  std::string args = fmt::format(R"({{"{}" : "foo"}})", key);
  QuicKnobsParsingTestFixture fixture = {args, true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamFormat) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1"}})", key);
  QuicKnobsParsingTestFixture fixture = {args, true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamFormatDefault) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::DEFAULT_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1"}})", key);
  QuicKnobsParsingTestFixture fixture = {args, true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamFormat2) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1,2"}})", key);
  QuicKnobsParsingTestFixture fixture = {args, true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamZeroDenom) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1/0"}})", key);
  QuicKnobsParsingTestFixture fixture = {args, true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamZeroNum) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "0/2"}})", key);
  QuicKnobsParsingTestFixture fixture = {args, true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamLargeDenom) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1/1234567"}})", key);
  QuicKnobsParsingTestFixture fixture = {args, true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidFractionParamLargeNum) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "1234567/1"}})", key);
  QuicKnobsParsingTestFixture fixture = {args, true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ValidFractionParam) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "4/5"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      args, false, {{.id = key, .val = uint64_t{4 * 100 + 5}}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ValidFractionParamDefault) {
  auto key =
      static_cast<uint64_t>(TransportKnobParamId::DEFAULT_RTT_FACTOR_KNOB);
  std::string args = fmt::format(R"({{"{}" : "4/5"}})", key);
  QuicKnobsParsingTestFixture fixture = {
      args, false, {{.id = key, .val = uint64_t{4 * 100 + 5}}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ValidMaxPacingRate) {
  auto key = static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB);
  uint64_t val = 111;
  std::string args = fmt::format(R"({{"{}" : {}}})", key, val);
  QuicKnobsParsingTestFixture fixture = {
      args, false, {{.id = key, .val = val}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, ValidMaxPacingRateAsString) {
  auto key = static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB);
  uint64_t val = 111;
  std::string args = fmt::format(R"({{"{}" : "{}"}})", key, val);
  QuicKnobsParsingTestFixture fixture = {
      args, false, {{.id = key, .val = val}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, InvalidMaxPacingRateAsLargeNumber) {
  auto key = static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB);
  // Decimal is UINT64_MAX + 1
  std::string args =
      fmt::format(R"({{"{}" : {}}})", key, "18446744073709551616");
  QuicKnobsParsingTestFixture fixture = {args, true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, MaxPacingRateWithSequenceNumber) {
  auto key = static_cast<uint64_t>(
      TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED);
  auto val = "1234,1";
  std::string args = fmt::format(R"({{"{}" : "{}"}})", key, val);
  QuicKnobsParsingTestFixture fixture = {
      args, false, {{.id = key, .val = val}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, NonStringKey) {
  QuicKnobsParsingTestFixture fixture = {
      "{ 10 : 1 }", false, {{.id = 10, .val = uint64_t{1}}}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, DoubleKey) {
  QuicKnobsParsingTestFixture fixture = {"{ \"3.14\" : 1 }", true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, DoubleValue) {
  QuicKnobsParsingTestFixture fixture = {"{  \"10\" : 0.1 }", true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, UInt64Max) {
  const uint64_t id = 10;
  const uint64_t val = std::numeric_limits<uint64_t>::max();
  std::string str = fmt::format("{{\"{}\" : {}}}", id, val);
  QuicKnobsParsingTestFixture fixture = {str, false, {{.id = id, .val = val}}};
  run(fixture);
}

} // namespace test
} // namespace quic
