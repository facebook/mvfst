/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/BbrRttSampler.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

using namespace testing;

namespace quic {
namespace test {

class BbrMinRttSamplerTest : public Test {};

TEST_F(BbrMinRttSamplerTest, InitState) {
  BbrRttSampler sampler(100s);
  EXPECT_TRUE(sampler.minRttExpired());
  EXPECT_EQ(kDefaultMinRtt, sampler.minRtt());
}

TEST_F(BbrMinRttSamplerTest, NewSampleAndExpiration) {
  BbrRttSampler sampler(10s);
  auto currentTime = Clock::now();
  sampler.newRttSample(50us, currentTime);
  EXPECT_FALSE(sampler.minRttExpired());
  EXPECT_EQ(50us, sampler.minRtt());

  sampler.newRttSample(60us, currentTime + 1s);
  EXPECT_FALSE(sampler.minRttExpired());
  EXPECT_EQ(50us, sampler.minRtt());

  sampler.newRttSample(40us, currentTime + 2s);
  EXPECT_FALSE(sampler.minRttExpired());
  EXPECT_EQ(40us, sampler.minRtt());

  sampler.newRttSample(100us, Clock::now() + 20s);
  EXPECT_TRUE(sampler.minRttExpired());
  EXPECT_EQ(100us, sampler.minRtt());
}
} // namespace test
} // namespace quic
