/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <quic/datagram/DatagramFlowManager.h>
#include <quic/priority/HTTPPriorityQueue.h>

using namespace quic;
using namespace testing;

namespace {

// Helper to create a BufQueue with the given string
BufQueue makeBuf(const std::string& data) {
  BufQueue buf;
  buf.append(folly::IOBuf::copyBuffer(data));
  return buf;
}

// Helper to extract string from BufPtr
std::string toString(const BufPtr& buf) {
  if (!buf) {
    return "";
  }
  return buf->moveToFbString().toStdString();
}

} // namespace

class DatagramFlowManagerTest : public Test {
 protected:
  void SetUp() override {
    manager_ = std::make_unique<DatagramFlowManager>();
  }

  // For tests that aren't exercising expiration. Those pass their own time
  // point so they can place it relative to the enqueue.
  DatagramFlowManager::DatagramPopResult popIfFits(
      uint32_t flowId,
      uint64_t availableSpace) {
    return manager_->popDatagramIfFits(flowId, availableSpace, Clock::now());
  }

  std::unique_ptr<DatagramFlowManager> manager_;
};

TEST_F(DatagramFlowManagerTest, AddAndPopSingleDatagram) {
  EXPECT_FALSE(manager_->hasDatagramsToSend());
  EXPECT_EQ(0, manager_->getDatagramCount());

  (void)manager_->addDatagram(makeBuf("hello"), 1);

  EXPECT_TRUE(manager_->hasDatagramsToSend());
  EXPECT_EQ(1, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));
  EXPECT_FALSE(manager_->hasDatagramsForFlow(2));

  auto result = popIfFits(1, 1000);
  EXPECT_NE(nullptr, result.buf);
  EXPECT_EQ("hello", toString(result.buf));
  EXPECT_EQ(5, result.datagramLen);
  EXPECT_TRUE(result.flowEmpty);
  EXPECT_EQ(0, manager_->getDatagramCount());
  EXPECT_FALSE(manager_->hasDatagramsToSend());
}

TEST_F(DatagramFlowManagerTest, MultipleDatagramsOnSingleFlow) {
  (void)manager_->addDatagram(makeBuf("first"), 1);
  (void)manager_->addDatagram(makeBuf("second"), 1);
  (void)manager_->addDatagram(makeBuf("third"), 1);

  EXPECT_EQ(3, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));

  // Pop first datagram
  auto result1 = popIfFits(1, 1000);
  EXPECT_EQ("first", toString(result1.buf));
  EXPECT_FALSE(result1.flowEmpty);
  EXPECT_EQ(2, manager_->getDatagramCount());

  // Pop second datagram
  auto result2 = popIfFits(1, 1000);
  EXPECT_EQ("second", toString(result2.buf));
  EXPECT_FALSE(result2.flowEmpty);
  EXPECT_EQ(1, manager_->getDatagramCount());

  // Pop third datagram
  auto result3 = popIfFits(1, 1000);
  EXPECT_EQ("third", toString(result3.buf));
  EXPECT_TRUE(result3.flowEmpty);
  EXPECT_EQ(0, manager_->getDatagramCount());
}

TEST_F(DatagramFlowManagerTest, MultipleFlowsWithDifferentPriorities) {
  HTTPPriorityQueue::Priority highPri(1, false);
  HTTPPriorityQueue::Priority midPri(5, false);
  HTTPPriorityQueue::Priority lowPri(9, false);

  (void)manager_->addDatagram(makeBuf("high priority"), 100);
  (void)manager_->setFlowPriority(100, highPri);
  (void)manager_->addDatagram(makeBuf("mid priority"), 200);
  (void)manager_->setFlowPriority(200, midPri);
  (void)manager_->addDatagram(makeBuf("low priority"), 300);
  (void)manager_->setFlowPriority(300, lowPri);

  EXPECT_EQ(3, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(100));
  EXPECT_TRUE(manager_->hasDatagramsForFlow(200));
  EXPECT_TRUE(manager_->hasDatagramsForFlow(300));
  EXPECT_FALSE(manager_->hasDatagramsForFlow(400));

  // Pop from each flow
  auto result1 = popIfFits(100, 1000);
  EXPECT_EQ("high priority", toString(result1.buf));
  EXPECT_EQ(2, manager_->getDatagramCount());

  auto result2 = popIfFits(200, 1000);
  EXPECT_EQ("mid priority", toString(result2.buf));
  EXPECT_EQ(1, manager_->getDatagramCount());

  auto result3 = popIfFits(300, 1000);
  EXPECT_EQ("low priority", toString(result3.buf));
  EXPECT_EQ(0, manager_->getDatagramCount());
}

TEST_F(DatagramFlowManagerTest, SetFlowPriority) {
  HTTPPriorityQueue::Priority initialPri(5, false);
  HTTPPriorityQueue::Priority newPri(3, false);

  // Add datagram with initial priority
  (void)manager_->addDatagram(makeBuf("data"), 1);
  (void)manager_->setFlowPriority(1, initialPri);

  // Change priority
  auto result = manager_->setFlowPriority(1, newPri);
  ASSERT_TRUE(result.has_value());
  EXPECT_FALSE(result.value()); // Flow is not empty

  // Pop and verify datagram is still there
  auto popResult = popIfFits(1, 1000);
  EXPECT_EQ("data", toString(popResult.buf));
}

TEST_F(DatagramFlowManagerTest, SetFlowPriorityOnNonExistentFlow) {
  HTTPPriorityQueue::Priority pri(5, false);
  auto result = manager_->setFlowPriority(999, pri);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, result.error());
}

TEST_F(DatagramFlowManagerTest, SetFlowPriorityReturnsEmptyStatus) {
  HTTPPriorityQueue::Priority pri(5, false);

  // Add and pop datagram to create empty flow
  (void)manager_->addDatagram(makeBuf("data"), 1);
  manager_->popDatagram();

  // Flow still exists in map but is empty
  // Set priority should return true (empty)
  auto result = manager_->setFlowPriority(1, pri);
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result.value()); // Flow is empty
}

TEST_F(DatagramFlowManagerTest, PopDatagramIfFitsWithInsufficientSpace) {
  (void)manager_->addDatagram(makeBuf("this is a long datagram"), 1);

  // Try to pop with insufficient space
  auto result = popIfFits(1, 10);
  EXPECT_EQ(nullptr, result.buf);
  EXPECT_FALSE(result.flowEmpty);
  EXPECT_EQ(0, result.datagramLen);

  // Datagram should still be there
  EXPECT_EQ(1, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));

  // Now pop with sufficient space
  auto result2 = popIfFits(1, 1000);
  EXPECT_NE(nullptr, result2.buf);
  EXPECT_EQ("this is a long datagram", toString(result2.buf));
  EXPECT_EQ(0, manager_->getDatagramCount());
}

TEST_F(DatagramFlowManagerTest, PopDatagramIfFitsWithOverhead) {
  manager_->setOverheadCalculator([](uint64_t datagramLen) {
    return datagramLen / 10; // 10% overhead
  });

  (void)manager_->addDatagram(makeBuf("0123456789"), 1); // 10 bytes

  // With 10% overhead, need 11 bytes total
  auto result1 = popIfFits(1, 10);
  EXPECT_EQ(nullptr, result1.buf); // Doesn't fit

  auto result2 = popIfFits(1, 11);
  EXPECT_NE(nullptr, result2.buf); // Fits!
  EXPECT_EQ("0123456789", toString(result2.buf));
}

TEST_F(DatagramFlowManagerTest, CloseEmptyFlow) {
  // Create a flow and make it empty
  (void)manager_->addDatagram(makeBuf("data"), 1);
  manager_->popDatagram();

  EXPECT_EQ(0, manager_->getDatagramCount());

  // Close the flow
  auto result = manager_->closeFlow(1);
  EXPECT_TRUE(result.has_value());

  // Flow should no longer exist
  auto setPriResult =
      manager_->setFlowPriority(1, HTTPPriorityQueue::Priority(5, false));
  EXPECT_TRUE(setPriResult.hasError());
}

TEST_F(DatagramFlowManagerTest, CloseFlowNowWithPendingDatagrams) {
  (void)manager_->addDatagram(makeBuf("first"), 1);
  (void)manager_->addDatagram(makeBuf("second"), 1);
  (void)manager_->addDatagram(makeBuf("third"), 1);

  EXPECT_EQ(3, manager_->getDatagramCount());

  // Close flow with pending datagrams
  auto result = manager_->closeFlowNow(1);
  EXPECT_TRUE(result.has_value());

  // All datagrams should be dropped
  EXPECT_EQ(0, manager_->getDatagramCount());
  EXPECT_FALSE(manager_->hasDatagramsForFlow(1));
}

TEST_F(DatagramFlowManagerTest, CloseNonExistentFlow) {
  auto result = manager_->closeFlow(999);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, result.error());
}

TEST_F(DatagramFlowManagerTest, CloseOneFlowDoesNotAffectOthers) {
  (void)manager_->addDatagram(makeBuf("flow1-data1"), 1);
  (void)manager_->addDatagram(makeBuf("flow1-data2"), 1);
  (void)manager_->addDatagram(makeBuf("flow2-data"), 2);
  (void)manager_->addDatagram(makeBuf("flow3-data"), 3);

  EXPECT_EQ(4, manager_->getDatagramCount());

  // Close flow 1
  auto result = manager_->closeFlowNow(1);
  EXPECT_TRUE(result.has_value());

  // Flow 1 should be gone, but flows 2 and 3 should remain
  EXPECT_EQ(2, manager_->getDatagramCount());
  EXPECT_FALSE(manager_->hasDatagramsForFlow(1));
  EXPECT_TRUE(manager_->hasDatagramsForFlow(2));
  EXPECT_TRUE(manager_->hasDatagramsForFlow(3));

  // Verify we can still pop from other flows
  auto result2 = popIfFits(2, 1000);
  EXPECT_EQ("flow2-data", toString(result2.buf));

  auto result3 = popIfFits(3, 1000);
  EXPECT_EQ("flow3-data", toString(result3.buf));
}

TEST_F(DatagramFlowManagerTest, DefaultFlowUsesDefaultPriority) {
  // Add datagram without explicit priority
  (void)manager_->addDatagram(makeBuf("data"), 1);

  // Datagram should be added successfully
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));
}

TEST_F(DatagramFlowManagerTest, AddDatagramUpdatesPriorityOnExistingFlow) {
  HTTPPriorityQueue::Priority pri1(5, false);
  HTTPPriorityQueue::Priority pri2(3, false);

  // Add first datagram with priority 5
  (void)manager_->addDatagram(makeBuf("first"), 1);
  (void)manager_->setFlowPriority(1, pri1);

  // Add second datagram with priority 3 to same flow
  (void)manager_->addDatagram(makeBuf("second"), 1);
  (void)manager_->setFlowPriority(1, pri2);

  // Add third datagram without explicit priority (should keep existing)
  (void)manager_->addDatagram(makeBuf("third"), 1);

  // All three datagrams should be in the flow
  EXPECT_EQ(3, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));
}

TEST_F(DatagramFlowManagerTest, PopDatagramWithoutFitCheck) {
  (void)manager_->addDatagram(makeBuf("data1"), 1);
  (void)manager_->addDatagram(makeBuf("data2"), 2);

  EXPECT_EQ(2, manager_->getDatagramCount());

  // popDatagram() pops from arbitrary flow. Neither flow is draining, so both
  // outlive the pop and there is nothing to report to the caller.
  EXPECT_FALSE(manager_->popDatagram().has_value());
  EXPECT_EQ(1, manager_->getDatagramCount());

  EXPECT_FALSE(manager_->popDatagram().has_value());
  EXPECT_EQ(0, manager_->getDatagramCount());
}

// Drop the only queued datagram, which belongs to an ephemeral flow. The flow
// has nothing left to deliver, so popDatagram must retire it the way
// popDatagramIfFits does; otherwise it is stranded in the write buffer. The id
// comes back so the caller can drop its own scheduling state for the flow.
TEST_F(DatagramFlowManagerTest, PopDatagramRetiresEmptiedDrainingFlow) {
  (void)manager_->addDatagram(
      makeBuf("ephemeral"), 100, std::nullopt, /*draining=*/true);
  EXPECT_EQ(1, manager_->getFlowCount());

  EXPECT_EQ(100, manager_->popDatagram());

  EXPECT_EQ(0, manager_->getDatagramCount());
  EXPECT_EQ(0, manager_->getFlowCount());
  EXPECT_FALSE(manager_->hasFlow(100));
}

// Drop from a write buffer whose only flow was created but never written to.
// There is nothing to pop, so the datagram count must stay put -- it is
// unsigned, and decrementing it here wraps and defeats every size check.
TEST_F(DatagramFlowManagerTest, PopDatagramIgnoresEmptyFlows) {
  manager_->createFlow(100);
  EXPECT_EQ(1, manager_->getFlowCount());
  EXPECT_EQ(0, manager_->getDatagramCount());

  EXPECT_FALSE(manager_->popDatagram().has_value());

  EXPECT_EQ(0, manager_->getDatagramCount());
}

TEST_F(DatagramFlowManagerTest, SingleToMultiQueueTransition) {
  // Add first datagram - uses single queue
  (void)manager_->addDatagram(makeBuf("first"), 1);

  // Add second datagram - transitions to multi queue
  (void)manager_->addDatagram(makeBuf("second"), 1);

  // Add third datagram - uses existing multi queue
  (void)manager_->addDatagram(makeBuf("third"), 1);

  EXPECT_EQ(3, manager_->getDatagramCount());

  // Pop all and verify FIFO order
  auto r1 = popIfFits(1, 1000);
  EXPECT_EQ("first", toString(r1.buf));

  auto r2 = popIfFits(1, 1000);
  EXPECT_EQ("second", toString(r2.buf));

  auto r3 = popIfFits(1, 1000);
  EXPECT_EQ("third", toString(r3.buf));
  EXPECT_TRUE(r3.flowEmpty);
}

TEST_F(DatagramFlowManagerTest, EphemeralFlowSingleDatagramCleanup) {
  EXPECT_EQ(0, manager_->getFlowCount());

  // Add ephemeral datagram
  (void)manager_->addDatagram(makeBuf("ephemeral"), 100, std::nullopt, true);

  EXPECT_EQ(1, manager_->getFlowCount());
  EXPECT_TRUE(manager_->isFlowDraining(100));
  EXPECT_TRUE(manager_->hasDatagramsForFlow(100));

  // Pop the datagram - flow should be automatically cleaned up
  auto result = popIfFits(100, 1000);
  EXPECT_EQ("ephemeral", toString(result.buf));
  EXPECT_TRUE(result.flowEmpty);

  // Flow should be removed from writeBuffer
  EXPECT_EQ(0, manager_->getFlowCount());
  EXPECT_FALSE(manager_->hasDatagramsForFlow(100));
}

TEST_F(DatagramFlowManagerTest, CannotAddToExistingEphemeralFlow) {
  // Add ephemeral datagram
  auto result1 =
      manager_->addDatagram(makeBuf("first"), 100, std::nullopt, true);
  ASSERT_TRUE(result1.has_value());

  EXPECT_EQ(1, manager_->getDatagramCount());
  EXPECT_EQ(1, manager_->getFlowCount());
  EXPECT_TRUE(manager_->isFlowDraining(100));

  // Try to add another datagram to the same ephemeral flow - should fail
  auto result2 = manager_->addDatagram(makeBuf("second"), 100);
  ASSERT_TRUE(result2.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, result2.error());

  // Original datagram should still be there
  EXPECT_EQ(1, manager_->getDatagramCount());
  EXPECT_EQ(1, manager_->getFlowCount());
}

TEST_F(DatagramFlowManagerTest, NonEphemeralFlowNotCleanedUpWhenEmpty) {
  // Add non-ephemeral datagram
  (void)manager_->addDatagram(makeBuf("data"), 100, std::nullopt, false);

  EXPECT_EQ(1, manager_->getFlowCount());
  EXPECT_FALSE(manager_->isFlowDraining(100));

  // Pop the datagram
  auto result = popIfFits(100, 1000);
  EXPECT_EQ("data", toString(result.buf));
  EXPECT_TRUE(result.flowEmpty);

  // Flow should still exist (not cleaned up)
  EXPECT_EQ(1, manager_->getFlowCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(100) == false); // Empty but exists
}

TEST_F(DatagramFlowManagerTest, MixedEphemeralAndNonEphemeralFlows) {
  // Create ephemeral flow
  (void)manager_->addDatagram(makeBuf("ephemeral1"), 100, std::nullopt, true);

  // Create non-ephemeral flow
  (void)manager_->addDatagram(makeBuf("persistent1"), 200, std::nullopt, false);

  // Create another ephemeral flow
  (void)manager_->addDatagram(makeBuf("ephemeral2"), 300, std::nullopt, true);

  EXPECT_EQ(3, manager_->getFlowCount());
  EXPECT_TRUE(manager_->isFlowDraining(100));
  EXPECT_FALSE(manager_->isFlowDraining(200));
  EXPECT_TRUE(manager_->isFlowDraining(300));

  // Pop from ephemeral flow 100 - should be cleaned up
  auto r1 = popIfFits(100, 1000);
  EXPECT_EQ("ephemeral1", toString(r1.buf));
  EXPECT_EQ(2, manager_->getFlowCount());
  EXPECT_FALSE(manager_->hasDatagramsForFlow(100));

  // Pop from non-ephemeral flow 200 - should NOT be cleaned up
  auto r2 = popIfFits(200, 1000);
  EXPECT_EQ("persistent1", toString(r2.buf));
  EXPECT_EQ(2, manager_->getFlowCount()); // Still 2 (200 and 300)
  EXPECT_FALSE(manager_->hasDatagramsForFlow(200)); // Empty but exists

  // Pop from ephemeral flow 300 - should be cleaned up
  auto r3 = popIfFits(300, 1000);
  EXPECT_EQ("ephemeral2", toString(r3.buf));
  EXPECT_EQ(1, manager_->getFlowCount()); // Only 200 remains
}

TEST_F(DatagramFlowManagerTest, EphemeralFlowNotSentDueToSpaceConstraint) {
  // Add ephemeral datagram
  (void)manager_->addDatagram(
      makeBuf("large ephemeral datagram"), 100, std::nullopt, true);

  EXPECT_EQ(1, manager_->getFlowCount());
  EXPECT_TRUE(manager_->isFlowDraining(100));

  // Try to pop with insufficient space
  auto result = popIfFits(100, 10);
  EXPECT_EQ(nullptr, result.buf);
  EXPECT_FALSE(result.flowEmpty);

  // Flow should still exist (not cleaned up because datagram wasn't sent)
  EXPECT_EQ(1, manager_->getFlowCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(100));
  EXPECT_TRUE(manager_->isFlowDraining(100));

  // Now pop with sufficient space - should be cleaned up
  auto result2 = popIfFits(100, 1000);
  EXPECT_NE(nullptr, result2.buf);
  EXPECT_TRUE(result2.flowEmpty);
  EXPECT_EQ(0, manager_->getFlowCount());
}

TEST_F(DatagramFlowManagerTest, IsFlowDrainingOnNonExistentFlow) {
  // Check ephemeral status on non-existent flow
  EXPECT_FALSE(manager_->isFlowDraining(999));
}

TEST_F(DatagramFlowManagerTest, GetFlowCountWithMultipleFlows) {
  EXPECT_EQ(0, manager_->getFlowCount());

  (void)manager_->addDatagram(makeBuf("flow1"), 1);
  EXPECT_EQ(1, manager_->getFlowCount());

  (void)manager_->addDatagram(makeBuf("flow2"), 2);
  EXPECT_EQ(2, manager_->getFlowCount());

  (void)manager_->addDatagram(makeBuf("flow3"), 3);
  EXPECT_EQ(3, manager_->getFlowCount());

  // Close one flow
  (void)manager_->closeFlowNow(2);
  EXPECT_EQ(2, manager_->getFlowCount());
}

TEST_F(DatagramFlowManagerTest, CloseFlowKeepsQueuedDatagrams) {
  (void)manager_->addDatagram(makeBuf("first"), 1);
  (void)manager_->addDatagram(makeBuf("second"), 1);

  auto result = manager_->closeFlow(1);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(2, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasFlow(1));

  EXPECT_EQ("first", toString(popIfFits(1, 1000).buf));
  EXPECT_TRUE(manager_->hasFlow(1));
  EXPECT_EQ("second", toString(popIfFits(1, 1000).buf));
  EXPECT_FALSE(manager_->hasFlow(1));
}

TEST_F(DatagramFlowManagerTest, CloseEmptyFlowRemovesItImmediately) {
  manager_->createFlow(1);
  ASSERT_TRUE(manager_->hasFlow(1));

  auto result = manager_->closeFlow(1);
  ASSERT_TRUE(result.has_value());
  EXPECT_FALSE(manager_->hasFlow(1));
}

TEST_F(DatagramFlowManagerTest, CannotAddToClosedFlowStillDraining) {
  (void)manager_->addDatagram(makeBuf("queued"), 1);
  ASSERT_TRUE(manager_->closeFlow(1).has_value());

  // The id is finished as soon as the flow is closed, whether or not the
  // scheduler has drained it yet.
  auto result = manager_->addDatagram(makeBuf("late"), 1);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, result.error());

  EXPECT_EQ("queued", toString(popIfFits(1, 1000).buf));
  EXPECT_FALSE(manager_->hasFlow(1));
}

TEST_F(DatagramFlowManagerTest, CloseFlowNowOnDrainingFlowDropsRemainder) {
  (void)manager_->addDatagram(makeBuf("first"), 1);
  (void)manager_->addDatagram(makeBuf("second"), 1);
  ASSERT_TRUE(manager_->closeFlow(1).has_value());

  // Escalating from a graceful close discards whatever has not gone out yet.
  ASSERT_TRUE(manager_->closeFlowNow(1).has_value());
  EXPECT_EQ(0, manager_->getDatagramCount());
  EXPECT_FALSE(manager_->hasFlow(1));
}

TEST_F(DatagramFlowManagerTest, CloseFlowNowOnNonExistentFlow) {
  auto result = manager_->closeFlowNow(999);
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, result.error());
}

TEST_F(DatagramFlowManagerTest, ClosedFlowRemovedWhenAllDatagramsExpire) {
  auto maxQueueTime = std::chrono::milliseconds(100);
  (void)manager_->addDatagram(
      makeBuf("stale"), 1, std::nullopt, false, maxQueueTime);
  ASSERT_TRUE(manager_->closeFlow(1).has_value());

  // The last datagram leaving via expiration also has to retire the flow.
  auto result = manager_->popDatagramIfFits(
      1, 1000, Clock::now() + std::chrono::seconds(1));
  EXPECT_EQ(nullptr, result.buf);
  EXPECT_TRUE(result.flowEmpty);
  EXPECT_FALSE(manager_->hasFlow(1));
}

TEST_F(DatagramFlowManagerTest, SetMaxQueueTimeViaAddDatagram) {
  // Add datagram with maxQueueTime
  auto maxQueueTime = std::chrono::milliseconds(100);
  (void)manager_->addDatagram(
      makeBuf("data"), 1, std::nullopt, false, maxQueueTime);

  EXPECT_EQ(1, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));

  // Pop immediately - should succeed
  auto now = Clock::now();
  auto result = manager_->popDatagramIfFits(1, 1000, now);
  EXPECT_NE(nullptr, result.buf);
  EXPECT_EQ("data", toString(result.buf));
}

TEST_F(DatagramFlowManagerTest, SetMaxQueueTimeViaSetMethod) {
  // Add datagram without maxQueueTime
  (void)manager_->addDatagram(makeBuf("data"), 1);

  // Set maxQueueTime after the fact
  auto setResult = manager_->setMaxQueueTime(1, std::chrono::milliseconds(50));
  ASSERT_TRUE(setResult.has_value());

  // Pop immediately - should succeed
  auto now = Clock::now();
  auto result = manager_->popDatagramIfFits(1, 1000, now);
  EXPECT_NE(nullptr, result.buf);
}

TEST_F(DatagramFlowManagerTest, AddDatagramClearsMaxQueueTime) {
  auto maxQueueTime = std::chrono::milliseconds(50);
  auto enqueueTime = Clock::now();
  (void)manager_->addDatagram(
      makeBuf("data"), 1, std::nullopt, false, maxQueueTime);
  ASSERT_TRUE(manager_->setMaxQueueTime(1, maxQueueTime).has_value());

  // 0 removes the flow's timeout, so neither datagram can expire.
  (void)manager_->addDatagram(
      makeBuf("more"), 1, std::nullopt, false, std::chrono::milliseconds(0));

  auto popTime = enqueueTime + maxQueueTime + std::chrono::milliseconds(10);
  auto result = manager_->popDatagramIfFits(1, 1000, popTime);
  EXPECT_EQ("data", toString(result.buf));
  EXPECT_EQ(0, result.numExpired);
  EXPECT_EQ(1, manager_->getDatagramCount());
}

TEST_F(
    DatagramFlowManagerTest,
    AddDatagramWithoutMaxQueueTimeKeepsFlowSetting) {
  auto maxQueueTime = std::chrono::milliseconds(50);
  manager_->createFlow(1);
  ASSERT_TRUE(manager_->setMaxQueueTime(1, maxQueueTime).has_value());

  // Both are queued under the flow's deadline; nullopt leaves it in place.
  auto enqueueTime = Clock::now();
  ASSERT_TRUE(manager_->addDatagram(makeBuf("data"), 1).has_value());
  (void)manager_->addDatagram(makeBuf("more"), 1);

  auto popTime = enqueueTime + maxQueueTime + std::chrono::milliseconds(10);
  auto result = manager_->popDatagramIfFits(1, 1000, popTime);
  EXPECT_EQ(nullptr, result.buf);
  EXPECT_EQ(2, result.numExpired);
  EXPECT_EQ(0, manager_->getDatagramCount());
}

// A deadline nobody could mean literally -- milliseconds::max() as "never
// expire" -- folds onto no timeout rather than overflowing the ms -> ns
// promotion when the cutoff is computed.
TEST_F(DatagramFlowManagerTest, AbsurdMaxQueueTimeMeansNoTimeout) {
  (void)manager_->addDatagram(
      makeBuf("data"),
      1,
      std::nullopt,
      false,
      std::chrono::milliseconds::max());
  EXPECT_EQ(TimePoint(), manager_->nowForExpiration());

  auto result = popIfFits(1, 1000);
  EXPECT_EQ("data", toString(result.buf));
  EXPECT_EQ(0, result.numExpired);
}

TEST_F(DatagramFlowManagerTest, NegativeMaxQueueTimeMeansNoTimeout) {
  (void)manager_->addDatagram(
      makeBuf("data"), 1, std::nullopt, false, std::chrono::milliseconds(-1));
  EXPECT_EQ(TimePoint(), manager_->nowForExpiration());

  auto result = popIfFits(1, 1000);
  EXPECT_EQ("data", toString(result.buf));
  EXPECT_EQ(0, result.numExpired);
}

// Right at the boundary the deadline is still honored.
TEST_F(DatagramFlowManagerTest, MaxQueueTimeAtLimitStillExpires) {
  manager_->createFlow(1);
  ASSERT_TRUE(manager_->setMaxQueueTime(1, DatagramFlowManager::kMaxQueueTime)
                  .has_value());

  auto enqueueTime = Clock::now();
  ASSERT_TRUE(manager_->addDatagram(makeBuf("data"), 1).has_value());

  auto popTime =
      enqueueTime + DatagramFlowManager::kMaxQueueTime + std::chrono::hours(1);
  auto result = manager_->popDatagramIfFits(1, 1000, popTime);
  EXPECT_EQ(nullptr, result.buf);
  EXPECT_EQ(1, result.numExpired);
}

// A flow manager nobody gave a deadline to never reads the clock, so the
// write loop gets a default TimePoint. Nothing can expire under it.
TEST_F(DatagramFlowManagerTest, NoDeadlineMeansNoClockRead) {
  (void)manager_->addDatagram(makeBuf("data"), 1);
  EXPECT_EQ(TimePoint(), manager_->nowForExpiration());

  auto result = manager_->popDatagramIfFits(1, 1000, TimePoint());
  EXPECT_EQ("data", toString(result.buf));
  EXPECT_EQ(0, result.numExpired);

  // One deadline anywhere flips it on for good.
  (void)manager_->addDatagram(
      makeBuf("data"), 2, std::nullopt, false, std::chrono::milliseconds(50));
  EXPECT_NE(TimePoint(), manager_->nowForExpiration());
}

// A deadline set after the fact does not reach back. Whatever was already
// queued carries the never-expires sentinel, while anything added afterwards
// ages normally.
TEST_F(DatagramFlowManagerTest, DeadlineDoesNotAgeAlreadyQueuedDatagrams) {
  ASSERT_TRUE(manager_->addDatagram(makeBuf("grandfathered"), 1).has_value());
  ASSERT_TRUE(
      manager_->setMaxQueueTime(1, std::chrono::milliseconds(50)).has_value());
  ASSERT_TRUE(manager_->addDatagram(makeBuf("aging"), 1).has_value());

  auto wellPast = Clock::now() + std::chrono::hours(1);
  auto survivor = manager_->popDatagramIfFits(1, 1000, wellPast);
  EXPECT_EQ("grandfathered", toString(survivor.buf));
  EXPECT_EQ(0, survivor.numExpired);

  auto expired = manager_->popDatagramIfFits(1, 1000, wellPast);
  EXPECT_EQ(nullptr, expired.buf);
  EXPECT_TRUE(expired.flowEmpty);
  EXPECT_EQ(1, expired.numExpired);
}

TEST_F(DatagramFlowManagerTest, SetMaxQueueTimeOnNonExistentFlow) {
  auto result = manager_->setMaxQueueTime(999, std::chrono::milliseconds(100));
  ASSERT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, result.error());
}

TEST_F(DatagramFlowManagerTest, DatagramExpiresAndIsDropped) {
  auto maxQueueTime = std::chrono::milliseconds(50);
  auto enqueueTime = Clock::now();

  // Add datagram with short maxQueueTime
  (void)manager_->addDatagram(
      makeBuf("expired"), 1, std::nullopt, false, maxQueueTime);
  EXPECT_EQ(1, manager_->getDatagramCount());

  // Try to pop after expiration
  auto popTime = enqueueTime + maxQueueTime + std::chrono::milliseconds(10);
  auto result = manager_->popDatagramIfFits(1, 1000, popTime);

  // Datagram should be dropped, flow should be empty
  EXPECT_EQ(nullptr, result.buf);
  EXPECT_TRUE(result.flowEmpty);
  EXPECT_EQ(0, result.datagramLen);
  EXPECT_EQ(0, manager_->getDatagramCount());
}

TEST_F(DatagramFlowManagerTest, MultipleDatagramsWithSomeExpired) {
  auto maxQueueTime = std::chrono::milliseconds(100);
  auto enqueueTime = Clock::now();

  // Add three datagrams
  (void)manager_->addDatagram(
      makeBuf("first"), 1, std::nullopt, false, maxQueueTime);
  (void)manager_->addDatagram(
      makeBuf("second"), 1, std::nullopt, false, maxQueueTime);
  (void)manager_->addDatagram(
      makeBuf("third"), 1, std::nullopt, false, maxQueueTime);

  EXPECT_EQ(3, manager_->getDatagramCount());

  // Pop after first two have expired
  auto popTime = enqueueTime + maxQueueTime + std::chrono::milliseconds(10);
  auto result = manager_->popDatagramIfFits(1, 1000, popTime);

  // All three should be dropped (they were all enqueued at similar times)
  EXPECT_EQ(nullptr, result.buf);
  EXPECT_TRUE(result.flowEmpty);
  EXPECT_EQ(0, manager_->getDatagramCount());
}

// numExpired counts what was dropped for age, so the caller can stat each
// drop. Popping within maxQueueTime reports none; popping past it reports
// every datagram the flow dropped on the way.
TEST_F(DatagramFlowManagerTest, PopDatagramIfFitsReportsExpiredCount) {
  auto maxQueueTime = std::chrono::milliseconds(100);
  (void)manager_->addDatagram(
      makeBuf("data1"), 1, std::nullopt, false, maxQueueTime);
  (void)manager_->addDatagram(
      makeBuf("data2"), 1, std::nullopt, false, maxQueueTime);
  (void)manager_->addDatagram(
      makeBuf("data3"), 1, std::nullopt, false, maxQueueTime);

  auto inTime = Clock::now();
  auto live = manager_->popDatagramIfFits(1, 1000, inTime);
  EXPECT_EQ("data1", toString(live.buf));
  EXPECT_EQ(0, live.numExpired);

  auto tooLate = inTime + maxQueueTime + std::chrono::milliseconds(10);
  auto expired = manager_->popDatagramIfFits(1, 1000, tooLate);
  EXPECT_EQ(nullptr, expired.buf);
  EXPECT_TRUE(expired.flowEmpty);
  EXPECT_EQ(2, expired.numExpired);
}

TEST_F(DatagramFlowManagerTest, AllDatagramsExpire) {
  auto maxQueueTime = std::chrono::milliseconds(100);
  (void)manager_->addDatagram(
      makeBuf("data1"), 1, std::nullopt, false, maxQueueTime);
  (void)manager_->addDatagram(
      makeBuf("data2"), 1, std::nullopt, false, maxQueueTime);

  EXPECT_EQ(2, manager_->getDatagramCount());
  EXPECT_EQ(1, manager_->getFlowCount());

  // Pop after all expired
  auto popTime = Clock::now() + std::chrono::milliseconds(200);
  auto result = manager_->popDatagramIfFits(1, 1000, popTime);

  // All expired, flow empty but still exists (non-ephemeral)
  EXPECT_EQ(nullptr, result.buf);
  EXPECT_TRUE(result.flowEmpty);
  EXPECT_EQ(0, manager_->getDatagramCount());
  EXPECT_EQ(1, manager_->getFlowCount()); // Flow still exists
}

TEST_F(DatagramFlowManagerTest, EphemeralFlowCleanedUpWhenAllExpire) {
  auto maxQueueTime = std::chrono::milliseconds(50);
  (void)manager_->addDatagram(
      makeBuf("ephemeral"), 100, std::nullopt, true, maxQueueTime);

  EXPECT_EQ(1, manager_->getDatagramCount());
  EXPECT_EQ(1, manager_->getFlowCount());
  EXPECT_TRUE(manager_->isFlowDraining(100));

  // Pop after expiration
  auto popTime = Clock::now() + std::chrono::milliseconds(100);
  auto result = manager_->popDatagramIfFits(100, 1000, popTime);

  // Datagram expired, ephemeral flow should be cleaned up
  EXPECT_EQ(nullptr, result.buf);
  EXPECT_TRUE(result.flowEmpty);
  EXPECT_EQ(0, manager_->getDatagramCount());
  EXPECT_EQ(0, manager_->getFlowCount()); // Ephemeral flow removed
}

TEST_F(DatagramFlowManagerTest, MaxQueueTimeZeroMeansNoTimeout) {
  // Add datagram with maxQueueTime = 0 (no timeout)
  (void)manager_->addDatagram(
      makeBuf("never expires"),
      1,
      std::nullopt,
      false,
      std::chrono::milliseconds(0));

  EXPECT_EQ(1, manager_->getDatagramCount());

  // Try to pop way in the future - should still succeed
  auto farFuture = Clock::now() + std::chrono::hours(24);
  auto result = manager_->popDatagramIfFits(1, 1000, farFuture);

  EXPECT_NE(nullptr, result.buf);
  EXPECT_EQ("never expires", toString(result.buf));
}

TEST_F(DatagramFlowManagerTest, ExpiredDatagramsDroppedFromFlow) {
  auto enqueueTime = Clock::now();
  auto maxQueueTime = std::chrono::milliseconds(100);

  // Add two datagrams to same flow with same timeout
  (void)manager_->addDatagram(
      makeBuf("first"), 1, std::nullopt, false, maxQueueTime);
  (void)manager_->addDatagram(makeBuf("second"), 1);

  EXPECT_EQ(2, manager_->getDatagramCount());

  // Pop after timeout - both should be expired and dropped
  auto popTime = enqueueTime + std::chrono::milliseconds(150);
  auto result = manager_->popDatagramIfFits(1, 1000, popTime);

  EXPECT_EQ(nullptr, result.buf);
  EXPECT_TRUE(result.flowEmpty);
  EXPECT_EQ(0, manager_->getDatagramCount());
}

TEST_F(DatagramFlowManagerTest, NonExpiredDatagramRetrievedFromFlow) {
  auto enqueueTime = Clock::now();
  auto maxQueueTime = std::chrono::milliseconds(200);

  // Add datagrams with 200ms timeout
  (void)manager_->addDatagram(
      makeBuf("data"), 1, std::nullopt, false, maxQueueTime);

  EXPECT_EQ(1, manager_->getDatagramCount());

  // Pop before timeout - should succeed
  auto popTime = enqueueTime + std::chrono::milliseconds(100);
  auto result = manager_->popDatagramIfFits(1, 1000, popTime);

  EXPECT_NE(nullptr, result.buf);
  EXPECT_EQ("data", toString(result.buf));
  EXPECT_TRUE(result.flowEmpty);
}

TEST_F(DatagramFlowManagerTest, DatagramDoesNotFitAfterExpiredOnesDropped) {
  auto enqueueTime = Clock::now();
  auto maxQueueTime = std::chrono::milliseconds(100);

  // Add small and large datagrams with same timeout
  (void)manager_->addDatagram(
      makeBuf("small"), 1, std::nullopt, false, maxQueueTime);
  (void)manager_->addDatagram(makeBuf(std::string(1000, 'x')), 1);

  EXPECT_EQ(2, manager_->getDatagramCount());

  // Pop before timeout with small space - small one fits
  auto popTime = enqueueTime + std::chrono::milliseconds(50);
  auto result = manager_->popDatagramIfFits(1, 100, popTime);

  EXPECT_NE(nullptr, result.buf);
  EXPECT_EQ("small", toString(result.buf));
  EXPECT_EQ(1, manager_->getDatagramCount()); // Large one remains
}
