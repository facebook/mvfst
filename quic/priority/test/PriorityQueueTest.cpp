/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/priority/PriorityQueue.h>
#include <unordered_map>

namespace {

using quic::PriorityQueue;

TEST(PriorityQueueIdentifier, All) {
  PriorityQueue::Identifier uninit;
  EXPECT_TRUE(
      uninit.getType() == PriorityQueue::Identifier::Type::UNINITIALIZED);
  EXPECT_FALSE(uninit.isInitialized());
  EXPECT_TRUE(uninit == PriorityQueue::Identifier());

  auto id1 = PriorityQueue::Identifier::fromStreamID(7);
  EXPECT_TRUE(id1.getType() == PriorityQueue::Identifier::Type::STREAM);
  EXPECT_TRUE(id1.isInitialized());
  EXPECT_TRUE(id1.isStreamID());
  EXPECT_FALSE(id1.isDatagramFlowID());
  EXPECT_EQ(id1.asStreamID(), 7);
  EXPECT_FALSE(id1 == uninit);

  auto idBig = PriorityQueue::Identifier::fromStreamID(1LLU << 57);
  EXPECT_TRUE(idBig.getType() == PriorityQueue::Identifier::Type::STREAM);
  EXPECT_TRUE(idBig.isInitialized());
  EXPECT_TRUE(idBig.isStreamID());
  EXPECT_FALSE(idBig.isDatagramFlowID());
  EXPECT_EQ(idBig.asStreamID(), 1LLU << 57);
  EXPECT_FALSE(idBig == uninit);

  auto id2 = PriorityQueue::Identifier::fromDatagramFlowID(7);
  EXPECT_TRUE(id2.getType() == PriorityQueue::Identifier::Type::DATAGRAM);
  EXPECT_TRUE(id2.isInitialized());
  EXPECT_FALSE(id2.isStreamID());
  EXPECT_TRUE(id2.isDatagramFlowID());
  EXPECT_EQ(id2.asDatagramFlowID(), 7);
  EXPECT_FALSE(id2 == uninit);

  EXPECT_FALSE(id1 == id2);
  EXPECT_TRUE(id2 == PriorityQueue::Identifier::fromDatagramFlowID(7));

  std::unordered_map<
      PriorityQueue::Identifier,
      uint64_t,
      PriorityQueue::Identifier::hash>
      m;
  // id1 and id2 have the same numeric value but different type, they hash and
  // compare differently
  m[id1] = 99;
  m[id2] = 100;
  EXPECT_EQ(m[id1], 99);
  EXPECT_EQ(m[id2], 100);
}

} // namespace
