/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/common/test/QuicCodecUtils.h>

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <iterator>

using namespace testing;
using namespace folly;

namespace quic {
namespace test {

class QuicCodecUtilsTest : public Test {};

TEST_F(QuicCodecUtilsTest, TestIterateStreamFrames) {
  ShortHeader header(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1);
  RegularQuicPacket packet(std::move(header));

  ReadStreamFrame frame1(1, 0, true);
  ReadStreamFrame frame2(2, 1, true);

  packet.frames.push_back(frame1);
  packet.frames.push_back(frame2);

  auto checked = 0;
  for (auto& frame : all_frames<ReadStreamFrame>(packet.frames)) {
    if (checked == 0) {
      EXPECT_TRUE(frame == frame1);
    } else if (checked == 1) {
      EXPECT_TRUE(frame == frame2);
    }
    ++checked;
  }
  EXPECT_EQ(checked, 2);

  auto iter = all_frames<ReadAckFrame>(packet.frames);
  checked = std::distance(iter.begin(), iter.end());
  EXPECT_EQ(checked, 0);
}

TEST_F(QuicCodecUtilsTest, TestIterateStreamFrameInBetweenAcks) {
  ShortHeader header(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1);
  RegularQuicPacket packet(std::move(header));

  ReadStreamFrame frame1(1, 0, true);
  ReadAckFrame ack;
  ack.largestAcked = 0;
  ack.ackDelay = 0us;

  packet.frames.push_back(ack);
  packet.frames.push_back(frame1);
  packet.frames.push_back(ack);

  auto checked = 0;
  for (auto& frame : all_frames<ReadStreamFrame>(packet.frames)) {
    ++checked;
    EXPECT_EQ(frame, frame1);
  }
  EXPECT_EQ(checked, 1);

  auto iter = all_frames<ReadAckFrame>(packet.frames);
  checked = std::distance(iter.begin(), iter.end());
  EXPECT_EQ(checked, 2);
}

TEST_F(QuicCodecUtilsTest, TestIterateStreamFrameNoFrames) {
  ShortHeader header(ProtectionType::KeyPhaseZero, getTestConnectionId(), 1);
  RegularQuicPacket packet(std::move(header));
  auto checked = 0;
  auto read_stream_iter = all_frames<ReadStreamFrame>(packet.frames);
  checked = std::distance(read_stream_iter.begin(), read_stream_iter.end());
  EXPECT_EQ(checked, 0);
  auto ack_iter = all_frames<ReadAckFrame>(packet.frames);
  checked = std::distance(ack_iter.begin(), ack_iter.end());
  EXPECT_EQ(checked, 0);
}

TEST_F(QuicCodecUtilsTest, MatchesPredicate) {
  QuicFrame frame(ReadStreamFrame(1, 0, true));
  EXPECT_TRUE(matchesPredicate<ReadStreamFrame>(frame));
  EXPECT_FALSE(matchesPredicate<ReadAckFrame>(frame));
}
} // namespace test
} // namespace quic
