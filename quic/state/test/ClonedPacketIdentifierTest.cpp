/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/ClonedPacketIdentifier.h>

#include <folly/portability/GTest.h>

namespace quic::test {
TEST(ClonedPacketIdentifierTest, EqTest) {
  ClonedPacketIdentifier initialClonedPacketIdentifier(
      PacketNumberSpace::Initial, 0);
  ClonedPacketIdentifier initialClonedPacketIdentifier0(
      PacketNumberSpace::Initial, 0);
  EXPECT_TRUE(initialClonedPacketIdentifier == initialClonedPacketIdentifier0);

  ClonedPacketIdentifier initialClonedPacketIdentifier1(
      PacketNumberSpace::Initial, 1);
  EXPECT_FALSE(
      initialClonedPacketIdentifier0 == initialClonedPacketIdentifier1);

  ClonedPacketIdentifier handshakeClonedPacketIdentifier(
      PacketNumberSpace::Handshake, 0);
  EXPECT_FALSE(
      handshakeClonedPacketIdentifier == initialClonedPacketIdentifier);
}

TEST(ClonedPacketIdentifierTest, HashTest) {
  ClonedPacketIdentifierHash hashObj;
  ClonedPacketIdentifier initialClonedPacketIdentifier0(
      PacketNumberSpace::Initial, 0);
  ClonedPacketIdentifier initialClonedPacketIdentifier1(
      PacketNumberSpace::Initial, 1);
  EXPECT_NE(
      hashObj(initialClonedPacketIdentifier0),
      hashObj(initialClonedPacketIdentifier1));

  ClonedPacketIdentifier handshakeClonedPacketIdentifier0(
      PacketNumberSpace::Handshake, 0);
  EXPECT_NE(
      hashObj(initialClonedPacketIdentifier0),
      hashObj(handshakeClonedPacketIdentifier0));
}
} // namespace quic::test
