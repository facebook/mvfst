/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/state/QuicPriorityQueue.h>

namespace quic::test {

class QuicPriorityQueueTest : public testing::Test {
 public:
  PriorityQueue queue_;
};

TEST_F(QuicPriorityQueueTest, TestBasic) {
  EXPECT_TRUE(queue_.empty());
  EXPECT_EQ(queue_.count(0), 0);

  StreamId id = 0;
  // Insert two streams for every level and incremental
  for (uint8_t i = 0; i < queue_.levels.size(); i++) {
    queue_.insertOrUpdate(id++, Priority(i / 2, i & 0x1));
    queue_.setNextScheduledStream(id - 1);
    queue_.insertOrUpdate(id++, Priority(i / 2, i & 0x1));
  }

  for (int16_t i = id - 1; i >= 0; i--) {
    EXPECT_EQ(queue_.count(i), 1);
  }

  for (auto& level : queue_.levels) {
    EXPECT_EQ(level.streams.size(), 2);
  }

  for (uint8_t i = 0; i < queue_.levels.size(); i++) {
    id = i * 2;
    EXPECT_EQ(queue_.getNextScheduledStream(Priority(i / 2, i & 0x1)), id);
    queue_.erase(id);
    EXPECT_EQ(queue_.count(id), 0);
    EXPECT_EQ(queue_.getNextScheduledStream(Priority(i / 2, i & 0x1)), id + 1);
  }

  queue_.clear();
  EXPECT_TRUE(queue_.empty());
}

TEST_F(QuicPriorityQueueTest, TestUpdate) {
  queue_.insertOrUpdate(0, Priority(0, false));
  EXPECT_EQ(queue_.count(0), 1);

  // Update no-op
  queue_.insertOrUpdate(0, Priority(0, false));
  EXPECT_EQ(queue_.count(0), 1);

  // Update move to different bucket
  queue_.insertOrUpdate(0, Priority(0, true));
  EXPECT_EQ(queue_.count(0), 1);

  EXPECT_EQ(queue_.getNextScheduledStream(Priority(0, true)), 0);
}

TEST_F(QuicPriorityQueueTest, UpdateIfExist) {
  queue_.updateIfExist(0);
  EXPECT_EQ(0, queue_.count(0));

  queue_.insertOrUpdate(0, Priority(0, false));
  EXPECT_EQ(queue_.getNextScheduledStream(Priority(0, false)), 0);
  queue_.updateIfExist(0, Priority(1, true));
  EXPECT_EQ(queue_.getNextScheduledStream(Priority(1, true)), 0);
}

} // namespace quic::test
