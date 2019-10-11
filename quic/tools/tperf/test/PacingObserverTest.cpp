/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/tools/tperf/PacingObserver.h>
#include <quic/logging/test/Mocks.h>

using namespace testing;

namespace quic::test {
class QLogPacingObserverTest : public Test {
 public:
  void SetUp() override {
    auto qlogger = std::make_shared<MockQLogger>();
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
      .WillOnce(Invoke(
          [](std::string actual, std::string expect, std::string conclustion) {
            EXPECT_TRUE(actual.find("20packets / ") != std::string::npos);
            EXPECT_EQ(Bandwidth(0, 0us, "packets").conciseDescribe(), expect);
            EXPECT_EQ("Pacing above expect", conclustion);
          }));
  pacingObserver.onNewPacingRate(10, 10s);

  EXPECT_CALL(*mockQLogger_, addPacingObservation(_, _, _))
      .Times(1)
      .WillOnce(Invoke(
          [](std::string actual, std::string expect, std::string conclustion) {
            EXPECT_TRUE(actual.find("0packets / ") != std::string::npos);
            EXPECT_EQ(Bandwidth(10, 10s, "packets").conciseDescribe(), expect);
            EXPECT_EQ("Pacing below expect", conclustion);
          }));
  pacingObserver.onNewPacingRate(20, 10s);
}

} // namespace quic::test
