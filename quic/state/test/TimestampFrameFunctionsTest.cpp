/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>

#include <quic/QuicConstants.h>
#include <quic/state/TimestampFrameFunctions.h>

namespace quic::test {

using namespace std::chrono_literals;

namespace {

struct TimestampEligibilityCase {
  const char* name;
  std::optional<TimestampFrameWriteMode> mode;
  bool peerCanReceive;
  bool ackReceiveTimestampsWritten;
  std::optional<bool> suppressForAckReceiveTimestamps;
  bool expected;
};

struct TimestampObserverCase {
  const char* name;
  QuicWriteFrame::Type frameType;
  bool allEligible;
  bool ackEliciting;
  bool stream;
};

struct TimestampAckCase {
  const char* name;
  FrameType frameType;
  bool hasReceiveTimestamp;
  bool expected;
};

QuicWriteFrame makeWriteFrame(QuicWriteFrame::Type frameType) {
  switch (frameType) {
    case QuicWriteFrame::Type::PaddingFrame:
      return PaddingFrame();
    case QuicWriteFrame::Type::RstStreamFrame:
      return RstStreamFrame(0, 0, 0);
    case QuicWriteFrame::Type::ConnectionCloseFrame:
      return ConnectionCloseFrame(
          QuicErrorCode(TransportErrorCode::NO_ERROR), "closed");
    case QuicWriteFrame::Type::MaxDataFrame:
      return MaxDataFrame(1);
    case QuicWriteFrame::Type::MaxStreamDataFrame:
      return MaxStreamDataFrame(0, 1);
    case QuicWriteFrame::Type::DataBlockedFrame:
      return DataBlockedFrame(1);
    case QuicWriteFrame::Type::StreamDataBlockedFrame:
      return StreamDataBlockedFrame(0, 1);
    case QuicWriteFrame::Type::StreamsBlockedFrame:
      return StreamsBlockedFrame(1, true);
    case QuicWriteFrame::Type::WriteAckFrame:
      return WriteAckFrame();
    case QuicWriteFrame::Type::WriteStreamFrame:
      return WriteStreamFrame(0, 0, 1, false);
    case QuicWriteFrame::Type::WriteCryptoFrame:
      return WriteCryptoFrame(0, 1);
    case QuicWriteFrame::Type::QuicSimpleFrame:
      return QuicSimpleFrame(HandshakeDoneFrame());
    case QuicWriteFrame::Type::PingFrame:
      return PingFrame();
    case QuicWriteFrame::Type::NoopFrame:
      return NoopFrame();
    case QuicWriteFrame::Type::DatagramFrame:
      return DatagramFrame(0, folly::IOBuf::create(0));
    case QuicWriteFrame::Type::TimestampFrame:
      return TimestampFrame(1);
    case QuicWriteFrame::Type::ImmediateAckFrame:
      return ImmediateAckFrame();
  }
  folly::assume_unreachable();
}

} // namespace

class TimestampEligibilityTest
    : public testing::TestWithParam<TimestampEligibilityCase> {};

TEST_P(TimestampEligibilityTest, AppliesCompleteWritePolicy) {
  const auto& testCase = GetParam();
  QuicConnectionStateBase conn(QuicNodeType::Client);
  if (testCase.mode) {
    conn.transportSettings.oneRttTimestampFrameWriteMode = *testCase.mode;
  }
  if (testCase.suppressForAckReceiveTimestamps) {
    conn.transportSettings
        .suppressOneRttTimestampFrameWhenAckReceiveTimestampsWritten =
        *testCase.suppressForAckReceiveTimestamps;
  }
  conn.peerTimestampFrameState.canReceive = testCase.peerCanReceive;

  EXPECT_EQ(
      shouldWriteOneRttTimestampFrame(
          conn, testCase.ackReceiveTimestampsWritten),
      testCase.expected);
}

INSTANTIATE_TEST_SUITE_P(
    TimestampPolicy,
    TimestampEligibilityTest,
    testing::Values(
        TimestampEligibilityCase{
            "DefaultDisabled",
            std::nullopt,
            true,
            false,
            std::nullopt,
            false},
        TimestampEligibilityCase{
            "Disabled",
            TimestampFrameWriteMode::Disabled,
            true,
            false,
            false,
            false},
        TimestampEligibilityCase{
            "PeerUnsupported",
            TimestampFrameWriteMode::Opportunistic,
            false,
            false,
            false,
            false},
        TimestampEligibilityCase{
            "Opportunistic",
            TimestampFrameWriteMode::Opportunistic,
            true,
            false,
            true,
            true},
        TimestampEligibilityCase{
            "Prioritized",
            TimestampFrameWriteMode::Prioritized,
            true,
            false,
            true,
            true},
        TimestampEligibilityCase{
            "DefaultTimestampedAckSuppression",
            TimestampFrameWriteMode::Opportunistic,
            true,
            true,
            std::nullopt,
            false},
        TimestampEligibilityCase{
            "TimestampedAckSuppressed",
            TimestampFrameWriteMode::Opportunistic,
            true,
            true,
            true,
            false},
        TimestampEligibilityCase{
            "TimestampedAckAllowed",
            TimestampFrameWriteMode::Opportunistic,
            true,
            true,
            false,
            true}),
    [](const testing::TestParamInfo<TimestampEligibilityCase>& info) {
      return info.param.name;
    });

class TimestampObserverTest
    : public testing::TestWithParam<TimestampObserverCase> {};

TEST_P(TimestampObserverTest, AppliesFrameSelectionPolicy) {
  const auto& testCase = GetParam();
  TimestampFramePacketObserver observer;

  observer(makeWriteFrame(testCase.frameType));

  EXPECT_EQ(observer.hasEligibleFrame(), testCase.allEligible);
  EXPECT_EQ(observer.hasAckElicitingFrame(), testCase.ackEliciting);
  EXPECT_EQ(
      observer.matchesPacketSelection(
          TimestampFramePacketSelection::AllEligiblePackets),
      testCase.allEligible);
  EXPECT_EQ(
      observer.matchesPacketSelection(
          TimestampFramePacketSelection::AckElicitingPackets),
      testCase.ackEliciting);
  EXPECT_EQ(
      observer.matchesPacketSelection(
          TimestampFramePacketSelection::StreamPackets),
      testCase.stream);
}

INSTANTIATE_TEST_SUITE_P(
    FramePolicy,
    TimestampObserverTest,
    testing::Values(
        TimestampObserverCase{
            "Padding",
            QuicWriteFrame::Type::PaddingFrame,
            false,
            false,
            false},
        TimestampObserverCase{
            "ResetStream",
            QuicWriteFrame::Type::RstStreamFrame,
            true,
            true,
            false},
        TimestampObserverCase{
            "ConnectionClose",
            QuicWriteFrame::Type::ConnectionCloseFrame,
            false,
            false,
            false},
        TimestampObserverCase{
            "MaxData",
            QuicWriteFrame::Type::MaxDataFrame,
            true,
            true,
            false},
        TimestampObserverCase{
            "MaxStreamData",
            QuicWriteFrame::Type::MaxStreamDataFrame,
            true,
            true,
            false},
        TimestampObserverCase{
            "DataBlocked",
            QuicWriteFrame::Type::DataBlockedFrame,
            true,
            true,
            false},
        TimestampObserverCase{
            "StreamDataBlocked",
            QuicWriteFrame::Type::StreamDataBlockedFrame,
            true,
            true,
            false},
        TimestampObserverCase{
            "StreamsBlocked",
            QuicWriteFrame::Type::StreamsBlockedFrame,
            true,
            true,
            false},
        TimestampObserverCase{
            "Ack",
            QuicWriteFrame::Type::WriteAckFrame,
            true,
            false,
            false},
        TimestampObserverCase{
            "Stream",
            QuicWriteFrame::Type::WriteStreamFrame,
            true,
            true,
            true},
        TimestampObserverCase{
            "Crypto",
            QuicWriteFrame::Type::WriteCryptoFrame,
            true,
            true,
            false},
        TimestampObserverCase{
            "Simple",
            QuicWriteFrame::Type::QuicSimpleFrame,
            true,
            true,
            false},
        TimestampObserverCase{
            "Ping",
            QuicWriteFrame::Type::PingFrame,
            true,
            true,
            false},
        TimestampObserverCase{
            "Noop",
            QuicWriteFrame::Type::NoopFrame,
            false,
            false,
            false},
        TimestampObserverCase{
            "Datagram",
            QuicWriteFrame::Type::DatagramFrame,
            true,
            true,
            false},
        TimestampObserverCase{
            "Timestamp",
            QuicWriteFrame::Type::TimestampFrame,
            false,
            false,
            false},
        TimestampObserverCase{
            "ImmediateAck",
            QuicWriteFrame::Type::ImmediateAckFrame,
            true,
            true,
            false}),
    [](const testing::TestParamInfo<TimestampObserverCase>& info) {
      return info.param.name;
    });

class TimestampAckObserverTest
    : public testing::TestWithParam<TimestampAckCase> {};

TEST_P(TimestampAckObserverTest, ClassifiesReceiveTimestampEncodings) {
  const auto& testCase = GetParam();
  WriteAckFrame ackFrame;
  ackFrame.frameType = testCase.frameType;
  if (testCase.hasReceiveTimestamp) {
    ackFrame.maybeLatestRecvdPacketTime = 1us;
  }
  TimestampFramePacketObserver observer;

  observer(ackFrame);

  EXPECT_TRUE(observer.hasEligibleFrame());
  EXPECT_EQ(observer.hasAckReceiveTimestamps(), testCase.expected);
}

INSTANTIATE_TEST_SUITE_P(
    AckEncodingPolicy,
    TimestampAckObserverTest,
    testing::Values(
        TimestampAckCase{"Basic", FrameType::ACK, false, false},
        TimestampAckCase{"BasicEcn", FrameType::ACK_ECN, false, false},
        TimestampAckCase{
            "Legacy",
            FrameType::ACK_RECEIVE_TIMESTAMPS,
            false,
            true},
        TimestampAckCase{
            "Draft02",
            FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02,
            false,
            true},
        TimestampAckCase{
            "Draft02Ecn",
            FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN,
            false,
            true},
        TimestampAckCase{
            "ExtendedWithoutTimestamp",
            FrameType::ACK_EXTENDED,
            false,
            false},
        TimestampAckCase{
            "ExtendedWithTimestamp",
            FrameType::ACK_EXTENDED,
            true,
            true}),
    [](const testing::TestParamInfo<TimestampAckCase>& info) {
      return info.param.name;
    });

class TimestampGenerationTest : public testing::TestWithParam<uint64_t> {};

TEST_P(TimestampGenerationTest, AppliesBoundedExponent) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.connectionTime = Clock::now() - 4s;
  conn.transportSettings.timestampFrameTimestampExponent = GetParam();
  const auto effectiveExponent =
      std::min(GetParam(), kMaxTimestampFrameTimestampExponent);
  const auto minTimestamp =
      static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::microseconds>(
              Clock::now() - conn.connectionTime)
              .count()) >>
      effectiveExponent;

  auto result = generateOneRttTimestampFrame(conn);

  ASSERT_TRUE(result.has_value());
  const auto maxTimestamp =
      static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::microseconds>(
              Clock::now() - conn.connectionTime)
              .count()) >>
      effectiveExponent;
  EXPECT_GE(result->timestamp, minTimestamp);
  EXPECT_LE(result->timestamp, maxTimestamp);
}

INSTANTIATE_TEST_SUITE_P(
    TimestampExponent,
    TimestampGenerationTest,
    testing::Values(
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        kMaxTimestampFrameTimestampExponent,
        kMaxTimestampFrameTimestampExponent + 1),
    [](const testing::TestParamInfo<uint64_t>& info) {
      return "Exponent" + std::to_string(info.param);
    });

TEST(TimestampFrameFunctionsTest, GenerateSkipsInvalidConnectionClock) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.connectionTime = Clock::now() + 1s;

  auto result = generateOneRttTimestampFrame(conn);

  EXPECT_FALSE(result.has_value());
}

} // namespace quic::test
