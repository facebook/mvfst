/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/dsr/frontend/Scheduler.h>
#include <quic/dsr/frontend/test/Mocks.h>
#include <quic/dsr/test/Mocks.h>
#include <quic/dsr/test/TestCommon.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>

using namespace testing;

namespace quic {
namespace test {

class SchedulerTest : public DSRCommonTestFixture {
 public:
  SchedulerTest() {
    prepareFlowControlAndStreamLimit();
  }

 protected:
  MockDSRPacketBuilder builder_;
};

TEST_F(SchedulerTest, ScheduleStream) {
  DSRStreamFrameScheduler scheduler(conn_);
  EXPECT_FALSE(scheduler.hasPendingData());
  auto stream = *conn_.streamManager->createNextBidirectionalStream();
  stream->flowControlState.peerAdvertisedMaxOffset = 200;
  stream->dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
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
  uint64_t writtenLength = 0;
  EXPECT_CALL(builder_, addSendInstruction(_, _))
      .WillOnce(Invoke([&](SendInstruction&& instruction, uint32_t) {
        EXPECT_EQ(stream->id, (size_t)instruction.streamId);
        EXPECT_EQ(expectedBufMetaOffset, instruction.streamOffset);
        EXPECT_GT(200, instruction.len);
        writtenLength = instruction.len;
        EXPECT_FALSE(instruction.fin);
      }));
  EXPECT_TRUE(scheduler.writeStream(builder_).writeSuccess);

  auto writtenMeta = stream->writeBufMeta.split(writtenLength);
  auto nextExpectedOffset = stream->writeBufMeta.offset;
  EXPECT_GT(stream->writeBufMeta.length, 0);
  stream->retransmissionBufMetas.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(expectedBufMetaOffset),
      std::forward_as_tuple(writtenMeta));
  // This is now flow control blocked:
  EXPECT_FALSE(stream->hasWritableBufMeta());
  conn_.streamManager->updateWritableStreams(*stream);
  EXPECT_FALSE(conn_.streamManager->hasDSRWritable());
  EXPECT_TRUE(conn_.streamManager->writableDSRStreams().empty());

  stream->flowControlState.peerAdvertisedMaxOffset = 500;
  conn_.streamManager->updateWritableStreams(*stream);
  EXPECT_TRUE(conn_.streamManager->hasDSRWritable());
  EXPECT_FALSE(conn_.streamManager->writableDSRStreams().empty());
  EXPECT_CALL(builder_, addSendInstruction(_, _))
      .WillOnce(Invoke([&](SendInstruction&& instruction, uint32_t) {
        EXPECT_EQ(stream->id, (size_t)instruction.streamId);
        EXPECT_EQ(nextExpectedOffset, instruction.streamOffset);
        EXPECT_GT(instruction.len, 0);
        writtenLength = instruction.len;
        EXPECT_TRUE(instruction.fin);
      }));
  EXPECT_TRUE(scheduler.writeStream(builder_).writeSuccess);

  auto nextWrittenMeta = stream->writeBufMeta.split(writtenLength);
  EXPECT_EQ(stream->writeBufMeta.length, 0);
  stream->writeBufMeta.offset++;
  stream->retransmissionBufMetas.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(nextExpectedOffset),
      std::forward_as_tuple(nextWrittenMeta));
  EXPECT_FALSE(stream->hasWritableBufMeta());
  conn_.streamManager->updateWritableStreams(*stream);
  EXPECT_FALSE(conn_.streamManager->hasDSRWritable());
  EXPECT_TRUE(conn_.streamManager->writableDSRStreams().empty());
}

} // namespace test
} // namespace quic
