/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/logging/QLogger.h>

#include <folly/json.h>
#include <gtest/gtest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/handshake/QuicFizzFactory.h>
#include <memory>

using namespace quic;
using namespace testing;

namespace quic::test {

class QLoggerTest : public Test {
 public:
  StreamId streamId{10};
  PacketNum packetNumSent{10};
  uint64_t offset{0};
  uint64_t len{0};
  bool fin{true};
};

TEST_F(QLoggerTest, TestRegularWritePacket) {
  StreamId current = 10;
  PacketNum packetNumSent = 10;
  RegularQuicWritePacket regularWritePacket =
      createNewPacket(packetNumSent, PacketNumberSpace::Initial);
  WriteStreamFrame frame(current++, 0, 0, true);
  regularWritePacket.frames.emplace_back(frame);

  QLogger q;
  q.add(regularWritePacket, 10);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketEvent*>(p.get());
  auto gotObject = *static_cast<StreamFrameLog*>(gotEvent->frames[0].get());

  EXPECT_EQ(gotObject.streamId, streamId);
  EXPECT_EQ(gotObject.offset, offset);
  EXPECT_EQ(gotObject.fin, fin);
}

TEST_F(QLoggerTest, TestRegularPacket) {
  auto expected = folly::IOBuf::copyBuffer("hello");
  StreamId streamId = 5;
  uint64_t offset = 1;
  bool fin = true;
  auto packet = createStreamPacket(
      getTestConnectionId(0),
      getTestConnectionId(1),
      1,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none /* longHeaderOverride */,
      fin,
      folly::none /* shortHeaderOverride */,
      offset);

  auto regularQuicPacket = packet.packet;
  QLogger q;
  q.add(regularQuicPacket, 10);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketEvent*>(p.get());
  auto gotObject = *static_cast<StreamFrameLog*>(gotEvent->frames[0].get());

  EXPECT_EQ(gotObject.streamId, streamId);
  EXPECT_EQ(gotObject.offset, offset);
  EXPECT_EQ(gotObject.fin, fin);
}

TEST_F(QLoggerTest, TestVersionNegotiationPacket) {
  auto versions = versionList({1, 2, 3, 4, 5, 6, 7});
  auto packet = VersionNegotiationPacketBuilder(
                    getTestConnectionId(0), getTestConnectionId(1), versions)
                    .buildPacket()
                    .first;
  bool isPacketRecvd = false;
  QLogger q;
  q.add(packet, 10, isPacketRecvd);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogVersionNegotiationEvent*>(p.get());
  auto gotObject = *gotEvent->versionLog.get();

  EXPECT_EQ(gotObject.versions, packet.versions);
}

} // namespace quic::test
