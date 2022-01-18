/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/d6d/BinarySearchProbeSizeRaiser.h>
#include <vector>

namespace quic {
namespace test {

struct ProbeSizeRaiserTestFixture {
  struct TestUnit {
    uint16_t probeSize;
    bool pass;
    folly::Optional<uint16_t> nextProbeSize;
  };
  uint16_t groundTruth;
  std::vector<TestUnit> testUnits;
};

void run(ProbeSizeRaiser* raiser, ProbeSizeRaiserTestFixture& fixture) {
  folly::Optional<uint16_t> lastGoodProbeSize;
  for (size_t i = 0; i < fixture.testUnits.size(); i++) {
    auto& t = fixture.testUnits[i];
    if (t.probeSize > fixture.groundTruth) {
      EXPECT_FALSE(t.pass) << "Test unit " << i;
      raiser->onProbeLost(t.probeSize);
      auto result = raiser->raiseProbeSize(*lastGoodProbeSize);
      // Either both are none, or they have the same value
      EXPECT_TRUE(
          (!result.hasValue() && !t.nextProbeSize.hasValue()) ||
          (*result == *t.nextProbeSize))
          << "Test unit " << i;
    } else {
      EXPECT_TRUE(t.pass) << "Test unit " << i;
      auto result = raiser->raiseProbeSize(t.probeSize);
      EXPECT_TRUE(
          (!result.hasValue() && !t.nextProbeSize.hasValue()) ||
          (*result == *t.nextProbeSize))
          << "Test unit " << i;
      lastGoodProbeSize = t.probeSize;
    }
  }
}

TEST(BinarySearchProbeSizeRaiserTest, CloseMinAndMax) {
  BinarySearchProbeSizeRaiser raiser(1000, 1001);
  auto result = raiser.raiseProbeSize(1000);
  EXPECT_EQ(*result, 1001);
  result = raiser.raiseProbeSize(1001);
  EXPECT_FALSE(result.hasValue());
}

TEST(BinarySearchProbeSizeRaiserTest, ReachMax) {
  BinarySearchProbeSizeRaiser raiser(1200, 1499);
  ProbeSizeRaiserTestFixture fixture = {
      1499,
      {
          {1200, true, 1350},
          {1350, true, 1425},
          {1425, true, 1462},
          {1462, true, 1481},
          {1481, true, 1490},
          {1490, true, 1495},
          {1495, true, 1497},
          {1497, true, 1498},
          {1498, true, 1499},
          {1499, true, folly::none},
      },
  };
  run(dynamic_cast<ProbeSizeRaiser*>(&raiser), fixture);
}

TEST(BinarySearchProbeSizeRaiserTest, StopInTheMiddle) {
  BinarySearchProbeSizeRaiser raiser(1200, 1499);
  ProbeSizeRaiserTestFixture fixture = {
      1399,
      {
          {1200, true, 1350},
          {1350, true, 1425},
          {1425, false, 1387},
          {1387, true, 1406},
          {1406, false, 1396},
          {1396, true, 1401},
          {1401, false, 1398},
          {1398, true, 1399},
          {1399, true, 1400},
          {1400, false, folly::none},
      },
  };
  run(dynamic_cast<ProbeSizeRaiser*>(&raiser), fixture);
}

} // namespace test
} // namespace quic
