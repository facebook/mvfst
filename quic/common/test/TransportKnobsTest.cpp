/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/common/TransportKnobs.h>
#include <folly/portability/GTest.h>

using namespace ::testing;

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
      "  \"1\": 5,"
      "  \"19\": 6,"
      "  \"2\": 3"
      "  }",
      false,
      {{0, 1}, {1, 5}, {2, 3}, {19, 6}}};
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
  QuicKnobsParsingTestFixture fixture = {"{ \"1\" : -1 }", true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, StringValue) {
  QuicKnobsParsingTestFixture fixture = {"{ \"1\" : \"1\" }", true, {}};
  run(fixture);
}

TEST(QuicKnobsParsingTest, NonStringKey) {
  QuicKnobsParsingTestFixture fixture = {"{ 1 : 1 }", true, {}};
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

} // namespace test
} // namespace quic
