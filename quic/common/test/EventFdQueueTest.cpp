/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/EventFdQueue.h>

#include <atomic>
#include <thread>
#include <vector>

#include <folly/io/async/ScopedEventBaseThread.h>
#include <gtest/gtest.h>

using namespace quic;

// Items flushed before startConsuming() fires are still delivered because
// eventfd/pipe is level-triggered: once the handler is registered it sees the
// fd is already readable and fires immediately.
TEST(EventFdQueueTest, HandlerFiresAfterStartConsuming) {
  folly::ScopedEventBaseThread consumer;
  EventFdQueue<int> queue(consumer.getEventBase(), 8);

  folly::Baton<> done;
  queue.setOnReadable([&] {
    int v;
    while (queue.dequeue(v)) {
    }
    done.post();
  });
  consumer.getEventBase()->runInEventBaseThread([&] { queue.startConsuming(); });

  queue.enqueue(42);
  queue.flush();

  done.wait();
}

TEST(EventFdQueueTest, BasicFifo) {
  folly::ScopedEventBaseThread consumer;
  EventFdQueue<int> queue(consumer.getEventBase(), 8);

  std::vector<int> received;
  folly::Baton<> done;

  consumer.getEventBase()->runInEventBaseThread([&] {
    queue.setOnReadable([&] {
      int v;
      while (queue.dequeue(v)) {
        received.push_back(v);
      }
      if (received.size() == 4) {
        done.post();
      }
    });
    queue.startConsuming();
  });

  // Give consumer thread time to register handler
  /* sleep override */ std::this_thread::sleep_for(std::chrono::milliseconds(10));

  EXPECT_TRUE(queue.enqueue(1));
  EXPECT_TRUE(queue.enqueue(2));
  EXPECT_TRUE(queue.enqueue(3));
  EXPECT_TRUE(queue.enqueue(4));
  queue.flush();

  done.wait();

  ASSERT_EQ(received.size(), 4u);
  EXPECT_EQ(received[0], 1);
  EXPECT_EQ(received[1], 2);
  EXPECT_EQ(received[2], 3);
  EXPECT_EQ(received[3], 4);
}

// Backpressure is a property of the underlying SPSC queue; no notification
// path (startConsuming / flush) is needed to test it.
TEST(EventFdQueueTest, Backpressure) {
  folly::ScopedEventBaseThread consumer;
  EventFdQueue<int> queue(consumer.getEventBase(), 4);

  // Fill the queue
  EXPECT_TRUE(queue.enqueue(1));
  EXPECT_TRUE(queue.enqueue(2));
  EXPECT_TRUE(queue.enqueue(3));
  EXPECT_TRUE(queue.enqueue(4));
  // Queue is now full
  EXPECT_FALSE(queue.enqueue(5));

  // Drain one slot and verify we can enqueue again
  int v;
  EXPECT_TRUE(queue.dequeue(v));
  EXPECT_EQ(v, 1);
  EXPECT_TRUE(queue.enqueue(5));
}

TEST(EventFdQueueTest, Coalescing) {
  // Multiple flush() calls while consumer is busy should coalesce into one
  // wakeup that drains all items.
  folly::ScopedEventBaseThread consumer;
  EventFdQueue<int> queue(consumer.getEventBase(), 64);

  std::atomic<int> wakeups{0};
  std::atomic<int> totalDrained{0};
  folly::Baton<> done;

  consumer.getEventBase()->runInEventBaseThread([&] {
    queue.setOnReadable([&] {
      wakeups.fetch_add(1);
      int v;
      while (queue.dequeue(v)) {
        totalDrained.fetch_add(1);
      }
      if (totalDrained.load() == 30) {
        done.post();
      }
    });
    queue.startConsuming();
  });

  /* sleep override */ std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // Enqueue 3 batches of 10, flushing after each
  for (int batch = 0; batch < 3; batch++) {
    for (int i = 0; i < 10; i++) {
      EXPECT_TRUE(queue.enqueue(batch * 10 + i));
    }
    queue.flush();
  }

  done.wait();
  EXPECT_EQ(totalDrained.load(), 30);
  // May be 1, 2, or 3 wakeups depending on scheduling; just verify all items
  // arrived and count is at least 1.
  EXPECT_GE(wakeups.load(), 1);
}

TEST(EventFdQueueTest, NoItemLoss) {
  folly::ScopedEventBaseThread consumer;
  const int total = 200;
  EventFdQueue<int> queue(consumer.getEventBase(), 64);

  std::atomic<int> received{0};
  folly::Baton<> done;

  consumer.getEventBase()->runInEventBaseThread([&] {
    queue.setOnReadable([&] {
      int v;
      while (queue.dequeue(v)) {
        if (received.fetch_add(1) + 1 == total) {
          done.post();
        }
      }
    });
    queue.startConsuming();
  });

  /* sleep override */ std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // Producer sends items in small batches; queue capacity may fill and require
  // the consumer to drain before we can continue.
  for (int i = 0; i < total; i++) {
    while (!queue.enqueue(i)) {
      // Queue full — yield and retry
      /* sleep override */ std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if ((i + 1) % 10 == 0) {
      queue.flush();
    }
  }
  queue.flush();

  done.wait();
  EXPECT_EQ(received.load(), total);
}
