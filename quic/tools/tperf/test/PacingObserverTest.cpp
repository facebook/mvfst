/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/tools/tperf/PacingObserver.h>

#include <quic/common/test/TestUtils.h>
#include <quic/logging/test/Mocks.h>

using namespace testing;

namespace quic::test {
class QLogPacingObserverTest : public Test {
 public:
  void SetUp() override {
    auto qlogger = std::make_shared<MockQLogger>(VantagePoint::Client);
    mockQLogger_ = qlogger.get();
    qlogger_ = std::move(qlogger);
  }

 protected:
  std::shared_ptr<QLogger> qlogger_;
  MockQLogger* mockQLogger_{nullptr};
};

TEST_F(QLogPacingObserverTest, Basic) {
  QLogPacingObserver pacingObserver(qlogger_);
  for (size_t i = 0; i < 20; i++) {
    pacingObserver.onPacketSent();
  }
  EXPECT_CALL(*mockQLogger_, addPacingObservation(_, _, _))
      .Times(1)
      .WillOnce(Invoke([](std::string actual,
                          std::string expect,
                          std::string conclusion) {
        EXPECT_GT(std::stoi(actual.substr(0, actual.find("packets / "))), 20);
        EXPECT_EQ(
            Bandwidth(0, 0s, Bandwidth::UnitType::PACKETS).normalizedDescribe(),
            expect);
        EXPECT_NE(std::string::npos, conclusion.find("Pacing above expect"));
      }));
  pacingObserver.onNewPacingRate(10, 10s);

  EXPECT_CALL(*mockQLogger_, addPacingObservation(_, _, _))
      .Times(1)
      .WillOnce(Invoke([](std::string actual,
                          std::string expect,
                          std::string conclusion) {
        EXPECT_TRUE(actual.find("0packets / ") != std::string::npos);
        EXPECT_EQ(
            Bandwidth(1, 1s, Bandwidth::UnitType::PACKETS).normalizedDescribe(),
            expect);
        EXPECT_NE(std::string::npos, conclusion.find("Pacing below expect"));
      }));
  pacingObserver.onNewPacingRate(20, 10s);
}

class RttBucketTest : public Test {
 protected:
  QuicConnectionStateBase conn_{QuicNodeType::Client};
};

TEST_F(RttBucketTest, Basic) {
  auto fakeNow = Clock::now();
  MockClock::mockNow = [=]() { return fakeNow; };
  // This initialize bucketBegin_ to fakeNow:
  RttBucket<MockClock> rttBucket(conn_);
  conn_.lossState.srtt = 1s;

  MockClock::mockNow = [=]() { return fakeNow + 10ms; };
  EXPECT_FALSE(rttBucket());

  // This resets the bucketBegin_ to fakeNow + 2s
  MockClock::mockNow = [=]() { return fakeNow + 2s; };
  EXPECT_TRUE(rttBucket());

  MockClock::mockNow = [=]() { return fakeNow + 2010ms; };
  EXPECT_FALSE(rttBucket());

  MockClock::mockNow = [=]() { return fakeNow + 3010ms; };
  EXPECT_TRUE(rttBucket());
}

class FixedTimeBucketTest : public Test {};

TEST_F(FixedTimeBucketTest, Basic) {
  auto fakeNow = Clock::now();
  MockClock::mockNow = [=]() { return fakeNow; };
  FixedTimeBucket<MockClock> fixedTimeBucket(2s);

  MockClock::mockNow = [=]() { return fakeNow + 1s; };
  EXPECT_FALSE(fixedTimeBucket());

  MockClock::mockNow = [=]() { return fakeNow + 2s; };
  EXPECT_TRUE(fixedTimeBucket());

  MockClock::mockNow = [=]() { return fakeNow + 2050ms; };
  EXPECT_FALSE(fixedTimeBucket());

  MockClock::mockNow = [=]() { return fakeNow + 4s; };
  EXPECT_TRUE(fixedTimeBucket());
}

} // namespace quic::test
