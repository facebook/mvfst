/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Codec-level test verifying that ECN counts > UINT32_MAX are correctly
// preserved as uint64_t during ACK frame decoding, and that the
// EcnL4sTracker handles large counts without false PROTOCOL_VIOLATION.

#include <quic/codec/Decode.h>

#include <folly/io/IOBuf.h>
#include <folly/portability/GTest.h>
#include <quic/codec/Types.h>
#include <quic/common/BufUtil.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/EcnL4sTracker.h>
#include <quic/state/AckEvent.h>

using namespace testing;

namespace quic::test {

class EcnTruncationTest : public Test {};

ShortHeader makePocHeader() {
  PacketNum packetNum = 100;
  return {ProtectionType::KeyPhaseZero, getTestConnectionId(), packetNum};
}

// Build an ACK_ECN frame body with arbitrary uint64_t ECN count values.
std::unique_ptr<folly::IOBuf> createAckFrameWithLargeEcn(
    uint64_t largestAcked,
    uint64_t ackDelay,
    uint64_t ect0,
    uint64_t ect1,
    uint64_t ce) {
  auto buf = folly::IOBuf::create(0);
  BufAppender appender(buf.get(), 100);
  auto op = [&](auto val) { appender.writeBE(val); };

  QuicInteger(largestAcked).encode(op);
  QuicInteger(ackDelay).encode(op);
  QuicInteger(0).encode(op); // ACK Block Count
  QuicInteger(0).encode(op); // First ACK Block

  QuicInteger(ect0).encode(op);
  QuicInteger(ect1).encode(op);
  QuicInteger(ce).encode(op);

  buf->coalesce();
  return buf;
}

// Verify that ECN counts > UINT32_MAX are correctly preserved as uint64_t
// during ACK_ECN frame decoding (no truncation).
TEST_F(EcnTruncationTest, EcnCountPreservedAboveUint32Max) {
  constexpr uint64_t kLargeEcnCount = 0x100000001ULL; // 2^32 + 1

  auto buf = createAckFrameWithLargeEcn(10, 20, 0, 0, kLargeEcnCount);
  ContiguousReadCursor cursor(buf->data(), buf->length());

  auto res = decodeAckFrameWithECN(
      cursor,
      makePocHeader(),
      CodecParameters(kDefaultAckDelayExponent, QuicVersion::MVFST));
  ASSERT_TRUE(res.has_value());

  auto ackFrame = *res->asReadAckFrame();
  EXPECT_EQ(ackFrame.ecnCECount, kLargeEcnCount)
      << "ECN count > UINT32_MAX should be preserved without truncation";
}

// Verify that large ECN counts do NOT cause PROTOCOL_VIOLATION in
// EcnL4sTracker when properly preserved as uint64_t.
//
// Scenario:
//   1. Peer sends ACK with CE=100 -> tracker stores lastCEEchoed_=100
//   2. Peer sends ACK with CE=0x100000001 (monotonically increasing)
//   3. Tracker sees counts going forward -> no exception
TEST_F(EcnTruncationTest, LargeEcnCountDoesNotCauseProtocolViolation) {
  auto conn = std::make_unique<QuicConnectionStateBase>(QuicNodeType::Client);
  conn->ecnState = ECNState::ValidatedL4S;
  conn->lossState.srtt = std::chrono::milliseconds(30);

  EcnL4sTracker tracker(*conn);
  auto now = Clock::now();

  // Step 1: Normal ACK with CE=100 to establish baseline.
  auto firstAck = AckEvent::Builder()
                      .setAckTime(now + std::chrono::milliseconds(30))
                      .setAdjustedAckTime(now + std::chrono::milliseconds(30))
                      .setAckDelay(std::chrono::microseconds(0))
                      .setPacketNumberSpace(PacketNumberSpace::AppData)
                      .setLargestAckedPacket(1000)
                      .setEcnCounts(0, 100, 100)
                      .build();
  firstAck.rttSample = std::chrono::milliseconds(30);
  EXPECT_NO_THROW(tracker.onPacketAck(&firstAck));

  // Step 2: ACK with large ECN count (> UINT32_MAX, monotonically increasing).
  constexpr uint64_t kLargeCount = 0x100000001ULL;
  auto secondAck = AckEvent::Builder()
                       .setAckTime(now + std::chrono::milliseconds(60))
                       .setAdjustedAckTime(now + std::chrono::milliseconds(60))
                       .setAckDelay(std::chrono::microseconds(0))
                       .setPacketNumberSpace(PacketNumberSpace::AppData)
                       .setLargestAckedPacket(2000)
                       .setEcnCounts(0, kLargeCount, kLargeCount)
                       .build();
  secondAck.rttSample = std::chrono::milliseconds(30);

  // With uint64_t fields, counts go from 100 -> 0x100000001 (forward).
  // No PROTOCOL_VIOLATION should be triggered.
  EXPECT_NO_THROW(tracker.onPacketAck(&secondAck));
}

// Verify large ECN counts are preserved via ACK_EXTENDED frame path.
TEST_F(EcnTruncationTest, ExtendedAckEcnCountPreserved) {
  constexpr uint64_t kLargeEcnCount = 0x200000002ULL;

  auto buf = folly::IOBuf::create(0);
  BufAppender appender(buf.get(), 100);
  auto op = [&](auto val) { appender.writeBE(val); };

  QuicInteger(10).encode(op);
  QuicInteger(20).encode(op);
  QuicInteger(0).encode(op);
  QuicInteger(0).encode(op);

  QuicInteger(
      static_cast<ExtendedAckFeatureMaskType>(
          ExtendedAckFeatureMask::ECN_COUNTS))
      .encode(op);

  QuicInteger(0).encode(op);
  QuicInteger(0).encode(op);
  QuicInteger(kLargeEcnCount).encode(op);

  buf->coalesce();

  ContiguousReadCursor cursor(buf->data(), buf->length());
  auto res = decodeAckExtendedFrame(
      cursor,
      makePocHeader(),
      CodecParameters(
          kDefaultAckDelayExponent,
          QuicVersion::MVFST,
          std::nullopt,
          static_cast<ExtendedAckFeatureMaskType>(
              ExtendedAckFeatureMask::ECN_COUNTS)));
  ASSERT_TRUE(res.has_value());

  const auto& ackFrame = *res;
  EXPECT_EQ(ackFrame.ecnCECount, kLargeEcnCount)
      << "ECN count > UINT32_MAX should be preserved in extended ACK path";
}

} // namespace quic::test
