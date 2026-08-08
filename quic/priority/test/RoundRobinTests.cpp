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

TEST_F(RoundRobinTest, AdvanceAfterNext) {
  rr_.advanceAfterBytes(3); // force 100% coverage in next call
  rr_.advanceAfterNext(3);
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(1));
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(1));
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(1));
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(2));
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(2));
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(2));
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(3));
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(3));
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(3));
}

TEST_F(RoundRobinTest, AdvanceAfterBytes) {
  rr_.advanceAfterBytes(10);
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(1));
  EXPECT_EQ(rr_.getNext(5), Identifier::fromStreamID(1));
  EXPECT_EQ(rr_.getNext(5), Identifier::fromStreamID(1));
  EXPECT_EQ(rr_.getNext(10), Identifier::fromStreamID(2));
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(3));
}

TEST_F(RoundRobinTest, EraseHeadResetsCurrent) {
  rr_.advanceAfterBytes(10);
  auto id1 = Identifier::fromStreamID(1);
  EXPECT_EQ(rr_.getNext(9), id1); // 9 of 10 bytes spent on id1
  EXPECT_TRUE(rr_.erase(id1));
  // The turn died with id1, so id2 gets a full quantum.
  auto id2 = Identifier::fromStreamID(2);
  EXPECT_EQ(rr_.getNext(9), id2);
  EXPECT_EQ(rr_.getNext(std::nullopt), id2);
}

TEST_F(RoundRobinTest, MoveEmptyThenInsert) {
  // An empty RoundRobin has nextIt_ on end(), the one iterator a list move
  // invalidates. Inserting afterwards must still work.
  RoundRobin empty_rr;
  ASSERT_TRUE(empty_rr.empty());
  RoundRobin moved(std::move(empty_rr));
  EXPECT_TRUE(moved.empty());
  moved.insert(Identifier::fromStreamID(7));
  EXPECT_FALSE(moved.empty());
  EXPECT_EQ(moved.getNext(std::nullopt), Identifier::fromStreamID(7));
}

TEST_F(RoundRobinTest, MoveKeepsRotationPosition) {
  // Take one turn, then move; the rotation must resume where it left off.
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(1));
  RoundRobin moved(std::move(rr_));
  EXPECT_EQ(moved.getNext(std::nullopt), Identifier::fromStreamID(2));
  EXPECT_EQ(moved.getNext(std::nullopt), Identifier::fromStreamID(3));
  EXPECT_EQ(moved.getNext(std::nullopt), Identifier::fromStreamID(1));
}

TEST_F(RoundRobinTest, MoveAssignEmptyOverFull) {
  RoundRobin empty_rr;
  rr_ = std::move(empty_rr);
  EXPECT_TRUE(rr_.empty());
  rr_.insert(Identifier::fromStreamID(9));
  EXPECT_EQ(rr_.getNext(std::nullopt), Identifier::fromStreamID(9));
}

TEST_F(RoundRobinTest, MoveKeepsByteDeficit) {
  rr_.advanceAfterBytes(10);
  EXPECT_EQ(rr_.getNext(5), Identifier::fromStreamID(1));
  RoundRobin moved(std::move(rr_));
  // 5 bytes already spent, so 5 more ends the turn.
  EXPECT_EQ(moved.getNext(5), Identifier::fromStreamID(1));
  EXPECT_EQ(moved.getNext(std::nullopt), Identifier::fromStreamID(2));
}

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
