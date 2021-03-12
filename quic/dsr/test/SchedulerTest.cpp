/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GTest.h>
#include <quic/dsr/Scheduler.h>
#include <quic/dsr/test/Mocks.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>

using namespace testing;

namespace quic {
namespace test {

class SchedulerTest : public Test {
 public:
  SchedulerTest() : conn_(FizzServerQuicHandshakeContext::Builder().build()) {
    conn_.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn_.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
  }

 protected:
  QuicServerConnectionState conn_;
  MockDSRPacketBuilder builder_;
};

TEST_F(SchedulerTest, ScheduleStream) {
  DSRStreamFrameScheduler scheduler(conn_);
  EXPECT_FALSE(scheduler.hasPendingData());
  auto stream = *conn_.streamManager->createNextBidirectionalStream();
  writeDataToQuicStream(
      *stream, folly::IOBuf::copyBuffer("New York Bagles"), false);
  BufferMeta bufMeta(200);
  writeBufMetaToQuicStream(*stream, bufMeta, true);
  auto expectedBufMetaOffset = stream->writeBufMeta.offset;
  ASSERT_TRUE(
      conn_.streamManager->hasWritable() &&
      conn_.streamManager->hasDSRWritable());
  EXPECT_TRUE(scheduler.hasPendingData());
  EXPECT_CALL(builder_, remainingSpaceNonConst()).WillRepeatedly(Return(1000));
  EXPECT_CALL(builder_, addSendInstruction(_, _))
      .WillOnce(Invoke([&](SendInstruction instruction, uint32_t) {
        EXPECT_EQ(stream->id, (size_t)instruction.streamId);
        EXPECT_EQ(expectedBufMetaOffset, instruction.offset);
        EXPECT_EQ(200, instruction.len);
        EXPECT_TRUE(instruction.fin);
      }));
  EXPECT_TRUE(scheduler.writeStream(builder_));

  auto writtenMeta = stream->writeBufMeta.split(200);
  EXPECT_EQ(0, stream->writeBufMeta.length);
  ++stream->writeBufMeta.offset;
  stream->retransmissionBufMetas.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(expectedBufMetaOffset),
      std::forward_as_tuple(writtenMeta));
  EXPECT_FALSE(stream->hasWritableBufMeta());
  conn_.streamManager->updateWritableStreams(*stream);
  EXPECT_FALSE(conn_.streamManager->hasDSRWritable());
  EXPECT_TRUE(conn_.streamManager->writableDSRStreams().empty());
}

} // namespace test
} // namespace quic
