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
    queue_.insertOrUpdate(id++, Priority(i / 2, i & 0x1));
  }

  for (int16_t i = id - 1; i >= 0; i--) {
    EXPECT_EQ(queue_.count(i), 1);
  }

  for (auto& level : queue_.levels) {
    level.iterator->begin();
    size_t count = 0;
    do {
      level.iterator->next();
      count++;
    } while (!level.iterator->end());
    EXPECT_EQ(count, 2);
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

TEST_F(QuicPriorityQueueTest, Sequential) {
  PriorityQueue pq;
  Priority pri(1, false);
  const auto& level = pq.levels[PriorityQueue::priority2index(pri)];

  pq.insertOrUpdate(0, pri);
  level.iterator->begin();
  EXPECT_EQ(level.iterator->current(), 0);
  EXPECT_FALSE(level.iterator->end());
  level.iterator->next();
  EXPECT_TRUE(level.iterator->end());

  pq.insertOrUpdate(1, pri);
  level.iterator->begin();
  level.iterator->next();
  EXPECT_EQ(level.iterator->current(), 1);
  level.iterator->next();
  EXPECT_TRUE(level.iterator->end());

  pq.erase(0);
  pq.insertOrUpdate(2, pri);
  level.iterator->begin();
  EXPECT_EQ(level.iterator->current(), 1);
}

TEST_F(QuicPriorityQueueTest, IncrementalBasic) {
  PriorityQueue pq;
  Priority pri(1, true);
  const auto& level = pq.levels[PriorityQueue::priority2index(pri)];

  pq.insertOrUpdate(0, pri);

  level.iterator->begin();
  EXPECT_EQ(level.iterator->current(), 0);
  EXPECT_TRUE(level.iterator->end());
}

TEST_F(QuicPriorityQueueTest, IncrementalRoundRobin) {
  PriorityQueue pq;
  Priority pri(1, true);
  const auto& level = pq.levels[PriorityQueue::priority2index(pri)];

  pq.insertOrUpdate(0, pri);
  pq.insertOrUpdate(1, pri);

  level.iterator->begin();
  EXPECT_EQ(level.iterator->current(), 0);

  level.iterator->next();
  EXPECT_EQ(level.iterator->current(), 1);
  EXPECT_FALSE(level.iterator->end());

  level.iterator->next();
  EXPECT_EQ(level.iterator->current(), 0);
  EXPECT_TRUE(level.iterator->end());
}

TEST_F(QuicPriorityQueueTest, IncrementalMultipleIterations) {
  PriorityQueue pq;
  Priority pri(1, true);
  const auto& level = pq.levels[PriorityQueue::priority2index(pri)];

  pq.insertOrUpdate(0, pri);
  pq.insertOrUpdate(1, pri);

  level.iterator->begin();
  level.iterator->next();

  level.iterator->begin();
  EXPECT_EQ(level.iterator->current(), 1);
}

TEST_F(QuicPriorityQueueTest, IncrementalEraseLeft) {
  PriorityQueue pq;
  Priority pri(1, true);
  const auto& level = pq.levels[PriorityQueue::priority2index(pri)];

  pq.insertOrUpdate(0, pri);
  pq.insertOrUpdate(1, pri);
  level.iterator->begin();

  pq.erase(0);
  level.iterator->begin();
  EXPECT_EQ(level.iterator->current(), 1);
}

TEST_F(QuicPriorityQueueTest, IncrementalEraseMiddle) {
  PriorityQueue pq;
  Priority pri(1, true);
  const auto& level = pq.levels[PriorityQueue::priority2index(pri)];

  pq.insertOrUpdate(0, pri);
  pq.insertOrUpdate(1, pri);
  pq.insertOrUpdate(2, pri);
  level.iterator->begin();
  level.iterator->next();

  pq.erase(1);
  level.iterator->begin();
  EXPECT_EQ(level.iterator->current(), 2);
}

TEST_F(QuicPriorityQueueTest, IncrementalEraseRight) {
  PriorityQueue pq;
  Priority pri(1, true);
  const auto& level = pq.levels[PriorityQueue::priority2index(pri)];

  pq.insertOrUpdate(0, pri);
  pq.insertOrUpdate(1, pri);
  pq.insertOrUpdate(2, pri);
  level.iterator->begin();
  level.iterator->next();

  pq.erase(2);
  level.iterator->begin();
  EXPECT_EQ(level.iterator->current(), 1);
}

TEST_F(QuicPriorityQueueTest, OrderedIds) {
  PriorityQueue pq;
  pq.insertOrUpdate(0, Priority(1, false, 2));
  pq.insertOrUpdate(1, Priority(1, false, 1));
  pq.insertOrUpdate(2, Priority(1, false));

  const auto& level =
      pq.levels[PriorityQueue::priority2index(Priority(1, false))];
  level.iterator->begin();
  EXPECT_EQ(level.iterator->current(), 2);
  level.iterator->next();
  EXPECT_EQ(level.iterator->current(), 1);
  level.iterator->next();
  EXPECT_EQ(level.iterator->current(), 0);
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

  queue_.prepareIterator(Priority(0, true));
  EXPECT_EQ(queue_.getNextScheduledStream(Priority(0, true)), 0);
}

TEST_F(QuicPriorityQueueTest, UpdateIfExist) {
  queue_.updateIfExist(0, kDefaultPriority);
  EXPECT_EQ(0, queue_.count(0));

  queue_.insertOrUpdate(0, Priority(0, false));
  queue_.prepareIterator(Priority(0, false));
  EXPECT_EQ(queue_.getNextScheduledStream(Priority(0, false)), 0);
  queue_.updateIfExist(0, Priority(1, true));
  queue_.prepareIterator(Priority(1, true));
  EXPECT_EQ(queue_.getNextScheduledStream(Priority(1, true)), 0);
}

} // namespace quic::test
