/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.

#include <quic/congestion_control/BbrRttSampler.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

using namespace quic;
using namespace testing;

namespace quic {
namespace test {

class BbrMinRttSamplerTest : public Test {};

TEST_F(BbrMinRttSamplerTest, InitState) {
  BbrRttSampler sampler(100s);
  EXPECT_TRUE(sampler.minRttExpired());
  EXPECT_EQ(0us, sampler.minRtt());
}

TEST_F(BbrMinRttSamplerTest, NewSampleAndExpiration) {
  BbrRttSampler sampler(10s);
  sampler.newRttSample(50us, Clock::now());
  EXPECT_FALSE(sampler.minRttExpired());
  EXPECT_EQ(50us, sampler.minRtt());

  // Expire the current sample:
  sampler.timestampMinRtt(Clock::now() - 20s);
  EXPECT_TRUE(sampler.minRttExpired());
  // Now a larger sample can replace the current sample since it's expired:
  sampler.newRttSample(100us, Clock::now());
  EXPECT_EQ(100us, sampler.minRtt());
  EXPECT_FALSE(sampler.minRttExpired());
}
} // namespace test
} // namespace quic
