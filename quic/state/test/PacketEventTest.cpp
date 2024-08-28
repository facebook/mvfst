/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/PacketEvent.h>

#include <folly/portability/GTest.h>

namespace quic {
namespace test {
TEST(PacketEventTest, EqTest) {
  PacketEvent initialEvent(PacketNumberSpace::Initial, 0);
  PacketEvent initialEvent0(PacketNumberSpace::Initial, 0);
  EXPECT_TRUE(initialEvent == initialEvent0);

  PacketEvent initialEvent1(PacketNumberSpace::Initial, 1);
  EXPECT_FALSE(initialEvent0 == initialEvent1);

  PacketEvent handshakeEvent(PacketNumberSpace::Handshake, 0);
  EXPECT_FALSE(handshakeEvent == initialEvent);
}

TEST(PacketEventTest, HashTest) {
  PacketEventHash hashObj;
  PacketEvent initialEvent0(PacketNumberSpace::Initial, 0);
  PacketEvent initialEvent1(PacketNumberSpace::Initial, 1);
  EXPECT_NE(hashObj(initialEvent0), hashObj(initialEvent1));

  PacketEvent handshakeEvent0(PacketNumberSpace::Handshake, 0);
  EXPECT_NE(hashObj(initialEvent0), hashObj(handshakeEvent0));
}
} // namespace test
} // namespace quic
