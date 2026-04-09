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

  std::unique_ptr<DatagramFlowManager> manager_;
};

TEST_F(DatagramFlowManagerTest, AddAndPopSingleDatagram) {
  EXPECT_FALSE(manager_->hasDatagramsToSend());
  EXPECT_EQ(0, manager_->getDatagramCount());

  manager_->addDatagram(makeBuf("hello"), 1);

  EXPECT_TRUE(manager_->hasDatagramsToSend());
  EXPECT_EQ(1, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));
  EXPECT_FALSE(manager_->hasDatagramsForFlow(2));

  auto result = manager_->popDatagramIfFits(1, 1000);
  EXPECT_NE(nullptr, result.buf);
  EXPECT_EQ("hello", toString(result.buf));
  EXPECT_EQ(5, result.datagramLen);
  EXPECT_TRUE(result.flowEmpty);
  EXPECT_EQ(0, manager_->getDatagramCount());
  EXPECT_FALSE(manager_->hasDatagramsToSend());
}

TEST_F(DatagramFlowManagerTest, MultipleDatagramsOnSingleFlow) {
  manager_->addDatagram(makeBuf("first"), 1);
  manager_->addDatagram(makeBuf("second"), 1);
  manager_->addDatagram(makeBuf("third"), 1);

  EXPECT_EQ(3, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));

  // Pop first datagram
  auto result1 = manager_->popDatagramIfFits(1, 1000);
  EXPECT_EQ("first", toString(result1.buf));
  EXPECT_FALSE(result1.flowEmpty);
  EXPECT_EQ(2, manager_->getDatagramCount());

  // Pop second datagram
  auto result2 = manager_->popDatagramIfFits(1, 1000);
  EXPECT_EQ("second", toString(result2.buf));
  EXPECT_FALSE(result2.flowEmpty);
  EXPECT_EQ(1, manager_->getDatagramCount());

  // Pop third datagram
  auto result3 = manager_->popDatagramIfFits(1, 1000);
  EXPECT_EQ("third", toString(result3.buf));
  EXPECT_TRUE(result3.flowEmpty);
  EXPECT_EQ(0, manager_->getDatagramCount());
}

TEST_F(DatagramFlowManagerTest, MultipleFlowsWithDifferentPriorities) {
  HTTPPriorityQueue::Priority highPri(1, false);
  HTTPPriorityQueue::Priority midPri(5, false);
  HTTPPriorityQueue::Priority lowPri(9, false);

  manager_->addDatagram(makeBuf("high priority"), 100);
  (void)manager_->setFlowPriority(100, highPri);
  manager_->addDatagram(makeBuf("mid priority"), 200);
  (void)manager_->setFlowPriority(200, midPri);
  manager_->addDatagram(makeBuf("low priority"), 300);
  (void)manager_->setFlowPriority(300, lowPri);

  EXPECT_EQ(3, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(100));
  EXPECT_TRUE(manager_->hasDatagramsForFlow(200));
  EXPECT_TRUE(manager_->hasDatagramsForFlow(300));
  EXPECT_FALSE(manager_->hasDatagramsForFlow(400));

  // Pop from each flow
  auto result1 = manager_->popDatagramIfFits(100, 1000);
  EXPECT_EQ("high priority", toString(result1.buf));
  EXPECT_EQ(2, manager_->getDatagramCount());

  auto result2 = manager_->popDatagramIfFits(200, 1000);
  EXPECT_EQ("mid priority", toString(result2.buf));
  EXPECT_EQ(1, manager_->getDatagramCount());

  auto result3 = manager_->popDatagramIfFits(300, 1000);
  EXPECT_EQ("low priority", toString(result3.buf));
  EXPECT_EQ(0, manager_->getDatagramCount());
}

TEST_F(DatagramFlowManagerTest, SetFlowPriority) {
  HTTPPriorityQueue::Priority initialPri(5, false);
  HTTPPriorityQueue::Priority newPri(3, false);

  // Add datagram with initial priority
  manager_->addDatagram(makeBuf("data"), 1);
  (void)manager_->setFlowPriority(1, initialPri);

  // Change priority
  auto result = manager_->setFlowPriority(1, newPri);
  ASSERT_TRUE(result.has_value());
  EXPECT_FALSE(result.value()); // Flow is not empty

  // Pop and verify datagram is still there
  auto popResult = manager_->popDatagramIfFits(1, 1000);
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
  manager_->addDatagram(makeBuf("data"), 1);
  manager_->popDatagram();

  // Flow still exists in map but is empty
  // Set priority should return true (empty)
  auto result = manager_->setFlowPriority(1, pri);
  ASSERT_TRUE(result.has_value());
  EXPECT_TRUE(result.value()); // Flow is empty
}

TEST_F(DatagramFlowManagerTest, PopDatagramIfFitsWithInsufficientSpace) {
  manager_->addDatagram(makeBuf("this is a long datagram"), 1);

  // Try to pop with insufficient space
  auto result = manager_->popDatagramIfFits(1, 10);
  EXPECT_EQ(nullptr, result.buf);
  EXPECT_FALSE(result.flowEmpty);
  EXPECT_EQ(0, result.datagramLen);

  // Datagram should still be there
  EXPECT_EQ(1, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));

  // Now pop with sufficient space
  auto result2 = manager_->popDatagramIfFits(1, 1000);
  EXPECT_NE(nullptr, result2.buf);
  EXPECT_EQ("this is a long datagram", toString(result2.buf));
  EXPECT_EQ(0, manager_->getDatagramCount());
}

TEST_F(DatagramFlowManagerTest, PopDatagramIfFitsWithOverhead) {
  manager_->setOverheadCalculator([](uint64_t datagramLen) {
    return datagramLen / 10; // 10% overhead
  });

  manager_->addDatagram(makeBuf("0123456789"), 1); // 10 bytes

  // With 10% overhead, need 11 bytes total
  auto result1 = manager_->popDatagramIfFits(1, 10);
  EXPECT_EQ(nullptr, result1.buf); // Doesn't fit

  auto result2 = manager_->popDatagramIfFits(1, 11);
  EXPECT_NE(nullptr, result2.buf); // Fits!
  EXPECT_EQ("0123456789", toString(result2.buf));
}

TEST_F(DatagramFlowManagerTest, CloseEmptyFlow) {
  // Create a flow and make it empty
  manager_->addDatagram(makeBuf("data"), 1);
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

TEST_F(DatagramFlowManagerTest, CloseFlowWithPendingDatagrams) {
  manager_->addDatagram(makeBuf("first"), 1);
  manager_->addDatagram(makeBuf("second"), 1);
  manager_->addDatagram(makeBuf("third"), 1);

  EXPECT_EQ(3, manager_->getDatagramCount());

  // Close flow with pending datagrams
  auto result = manager_->closeFlow(1);
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
  manager_->addDatagram(makeBuf("flow1-data1"), 1);
  manager_->addDatagram(makeBuf("flow1-data2"), 1);
  manager_->addDatagram(makeBuf("flow2-data"), 2);
  manager_->addDatagram(makeBuf("flow3-data"), 3);

  EXPECT_EQ(4, manager_->getDatagramCount());

  // Close flow 1
  auto result = manager_->closeFlow(1);
  EXPECT_TRUE(result.has_value());

  // Flow 1 should be gone, but flows 2 and 3 should remain
  EXPECT_EQ(2, manager_->getDatagramCount());
  EXPECT_FALSE(manager_->hasDatagramsForFlow(1));
  EXPECT_TRUE(manager_->hasDatagramsForFlow(2));
  EXPECT_TRUE(manager_->hasDatagramsForFlow(3));

  // Verify we can still pop from other flows
  auto result2 = manager_->popDatagramIfFits(2, 1000);
  EXPECT_EQ("flow2-data", toString(result2.buf));

  auto result3 = manager_->popDatagramIfFits(3, 1000);
  EXPECT_EQ("flow3-data", toString(result3.buf));
}

TEST_F(DatagramFlowManagerTest, DefaultFlowUsesDefaultPriority) {
  // Add datagram without explicit priority
  manager_->addDatagram(makeBuf("data"), 1);

  // Datagram should be added successfully
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));
}

TEST_F(DatagramFlowManagerTest, AddDatagramUpdatesPriorityOnExistingFlow) {
  HTTPPriorityQueue::Priority pri1(5, false);
  HTTPPriorityQueue::Priority pri2(3, false);

  // Add first datagram with priority 5
  manager_->addDatagram(makeBuf("first"), 1);
  (void)manager_->setFlowPriority(1, pri1);

  // Add second datagram with priority 3 to same flow
  manager_->addDatagram(makeBuf("second"), 1);
  (void)manager_->setFlowPriority(1, pri2);

  // Add third datagram without explicit priority (should keep existing)
  manager_->addDatagram(makeBuf("third"), 1);

  // All three datagrams should be in the flow
  EXPECT_EQ(3, manager_->getDatagramCount());
  EXPECT_TRUE(manager_->hasDatagramsForFlow(1));
}

TEST_F(DatagramFlowManagerTest, PopDatagramWithoutFitCheck) {
  manager_->addDatagram(makeBuf("data1"), 1);
  manager_->addDatagram(makeBuf("data2"), 2);

  EXPECT_EQ(2, manager_->getDatagramCount());

  // popDatagram() pops from arbitrary flow
  manager_->popDatagram();
  EXPECT_EQ(1, manager_->getDatagramCount());

  manager_->popDatagram();
  EXPECT_EQ(0, manager_->getDatagramCount());
}

TEST_F(DatagramFlowManagerTest, SingleToMultiQueueTransition) {
  // Add first datagram - uses single queue
  manager_->addDatagram(makeBuf("first"), 1);

  // Add second datagram - transitions to multi queue
  manager_->addDatagram(makeBuf("second"), 1);

  // Add third datagram - uses existing multi queue
  manager_->addDatagram(makeBuf("third"), 1);

  EXPECT_EQ(3, manager_->getDatagramCount());

  // Pop all and verify FIFO order
  auto r1 = manager_->popDatagramIfFits(1, 1000);
  EXPECT_EQ("first", toString(r1.buf));

  auto r2 = manager_->popDatagramIfFits(1, 1000);
  EXPECT_EQ("second", toString(r2.buf));

  auto r3 = manager_->popDatagramIfFits(1, 1000);
  EXPECT_EQ("third", toString(r3.buf));
  EXPECT_TRUE(r3.flowEmpty);
}
