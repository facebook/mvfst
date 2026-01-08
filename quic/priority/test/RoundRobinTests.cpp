/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/priority/RoundRobin.h>

namespace {

using quic::RoundRobin;
using Identifier = quic::PriorityQueue::Identifier;

class RoundRobinTest : public ::testing::Test {
 protected:
  void SetUp() override {
    rr_.insert(Identifier::fromStreamID(1));
    rr_.insert(Identifier::fromStreamID(2));
    rr_.insert(Identifier::fromStreamID(3));
  }

  RoundRobin rr_;
};

TEST_F(RoundRobinTest, Empty) {
  RoundRobin empty_rr;
  EXPECT_TRUE(empty_rr.empty());
  EXPECT_FALSE(empty_rr.erase(Identifier()));
}

TEST_F(RoundRobinTest, Erase) {
  EXPECT_FALSE(rr_.erase(Identifier())); // doesn't match anything

  auto id1 = Identifier::fromStreamID(1);
  EXPECT_EQ(rr_.getNext(std::nullopt), id1);
  EXPECT_TRUE(rr_.erase(id1));

  auto id2 = Identifier::fromStreamID(2);
  EXPECT_EQ(rr_.getNext(std::nullopt), id2);
  // erase head - 1
  EXPECT_TRUE(rr_.erase(id2));
  rr_.insert(id1);

  // erase head + 1
  EXPECT_TRUE(rr_.erase(id1));

  auto id3 = Identifier::fromStreamID(3);
  EXPECT_EQ(rr_.getNext(std::nullopt), id3);

  EXPECT_TRUE(rr_.erase(id3));
  EXPECT_TRUE(rr_.empty());
}

TEST_F(RoundRobinTest, EraseInMiddleBeforeHead) {
  rr_.getNext(std::nullopt);
  rr_.getNext(std::nullopt);

  auto id2 = Identifier::fromStreamID(2);
  EXPECT_TRUE(rr_.erase(id2));

  auto id3 = Identifier::fromStreamID(3);
  EXPECT_EQ(rr_.getNext(std::nullopt), id3);

  auto id1 = Identifier::fromStreamID(1);
  EXPECT_EQ(rr_.getNext(std::nullopt), id1);
}

TEST_F(RoundRobinTest, GetNext) {
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(1));
}

TEST_F(RoundRobinTest, PeekAndClear) {
  auto id1 = Identifier::fromStreamID(1);
  EXPECT_EQ(rr_.peekNext(), id1);
  EXPECT_EQ(rr_.peekNext(), id1);
  for (size_t i = 4; i <= 40; i++) {
    rr_.insert(Identifier::fromStreamID(i));
  }
  rr_.clear();
  EXPECT_TRUE(rr_.empty());
}

TEST_F(RoundRobinTest, InsertResize) {
  // Erase default elements so begin_ is offset from the front of deque
  for (size_t i = 1; i < 3; i++) {
    rr_.erase(Identifier::fromStreamID(i));
  }
  EXPECT_EQ(rr_.peekNext(), Identifier::fromStreamID(3));
  // Insert enough elements to fill the queue and expand.  The head_ iterator
  // needs to change
  for (size_t i = 4; i < 20; i++) {
    rr_.insert(Identifier::fromStreamID(i));
  }
  EXPECT_EQ(rr_.peekNext(), Identifier::fromStreamID(3));
}

TEST_F(RoundRobinTest, Index) {
  for (size_t i = 4; i <= 40; i++) {
    rr_.insert(Identifier::fromStreamID(i));
  }
  for (size_t i = 0; i < 20; i++) {
    rr_.getNext(std::nullopt);
  }
  for (size_t i = 1; i < 20; i++) {
    EXPECT_TRUE(rr_.erase(Identifier::fromStreamID(i)));
    EXPECT_TRUE(rr_.erase(Identifier::fromStreamID(40 - i)));
  }
}

} // namespace
