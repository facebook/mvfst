/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/EcnL4sTracker.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/StateData.h>
#include <quic/state/test/Mocks.h>

using namespace testing;
using namespace std::chrono_literals;

namespace quic::test {

class EcnTruncationIntegrationTest : public Test {
 protected:
  void SetUp() override {
    conn_ = std::make_unique<QuicServerConnectionState>(
        FizzServerQuicHandshakeContext::Builder().build());

    // Enable L4S ECN tracking
    conn_->ecnState = ECNState::ValidatedL4S;

    // Need a congestion controller for updateCongestionControllerForAck to run
    conn_->congestionController = std::make_unique<MockCongestionController>();

    // Wire up EcnL4sTracker as a PacketProcessor
    ecnTracker_ = std::make_shared<EcnL4sTracker>(*conn_);
    conn_->ecnL4sTracker = ecnTracker_;
    conn_->packetProcessors.push_back(ecnTracker_);
  }

  void addOutstandingPacket(PacketNum packetNum, TimePoint sentTime) {
    auto packet = createNewPacket(packetNum, PacketNumberSpace::AppData);
    conn_->outstandings.packetCount[packet.header.getPacketNumberSpace()]++;
    conn_->outstandings.packets.emplace_back(
        std::move(packet),
        sentTime,
        0 /* encodedSize */,
        0 /* encodedBodySize */,
        0 /* totalBytesSent */,
        packetNum /* totalBodyBytesSent */,
        packetNum + 1 /* totalPacketsSent */,
        LossState(),
        0 /* writeCount */,
        OutstandingPacketMetadata::DetailsPerStream());
  }

  quic::Expected<AckEvent, QuicError> processAck(
      ReadAckFrame& ackFrame,
      TimePoint ackReceiveTime) {
    return processAckFrame(
        *conn_,
        PacketNumberSpace::AppData,
        ackFrame,
        [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
        [](const auto&, const auto&) -> quic::Expected<void, quic::QuicError> {
          return {};
        },
        [](auto&, auto, auto&, bool) -> quic::Expected<void, quic::QuicError> {
          return {};
        },
        ackReceiveTime);
  }

  std::unique_ptr<QuicServerConnectionState> conn_;
  std::shared_ptr<EcnL4sTracker> ecnTracker_;
};

/**
 * Transport-level integration test: verifies that the full ACK processing
 * pipeline (processAckFrame -> updateCongestionControllerForAck ->
 * EcnL4sTracker::onPacketAck) correctly handles large ECN counts (> UINT32_MAX)
 * after the uint32_t -> uint64_t fix.
 *
 * With the fix, ECN counts are uint64_t throughout the pipeline, so large
 * monotonically increasing values are handled correctly without any
 * PROTOCOL_VIOLATION.
 */
TEST_F(EcnTruncationIntegrationTest, LargeEcnCountsThroughPipelineSucceed) {
  auto baseTime = Clock::now();

  // Send two packets so we can ACK them separately
  addOutstandingPacket(0, baseTime);
  addOutstandingPacket(1, baseTime + 1ms);

  // First ACK: establish baseline with CE=100
  // (simulates a legitimate ECN count)
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 0;
    ackFrame.ackBlocks.emplace_back(0, 0);
    ackFrame.ecnECT0Count = 0;
    ackFrame.ecnECT1Count = 100;
    ackFrame.ecnCECount = 100;

    auto result = processAck(ackFrame, baseTime + 10ms);
    ASSERT_FALSE(result.hasError())
        << "First ACK should succeed and establish baseline";
  }

  // Second ACK: large ECN counts (> UINT32_MAX), monotonically increasing.
  // With uint64_t fields, these values are preserved correctly and the
  // tracker sees counts going forward (100 -> 0x100000001).
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 1;
    ackFrame.ackBlocks.emplace_back(1, 1);
    ackFrame.ecnECT0Count = 0;
    ackFrame.ecnECT1Count = 0x100000001ULL;
    ackFrame.ecnCECount = 0x100000001ULL;

    auto result = processAck(ackFrame, baseTime + 60ms);
    EXPECT_FALSE(result.hasError())
        << "Large ECN counts should succeed with uint64_t fields";
  }
}

/**
 * Proves the full chain works correctly with non-truncated values.
 * ECN counts that only go forward should not trigger any violation.
 */
TEST_F(EcnTruncationIntegrationTest, NonTruncatedEcnCountsSucceed) {
  auto baseTime = Clock::now();

  addOutstandingPacket(0, baseTime);
  addOutstandingPacket(1, baseTime + 1ms);

  // First ACK with ECN counts
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 0;
    ackFrame.ackBlocks.emplace_back(0, 0);
    ackFrame.ecnECT0Count = 10;
    ackFrame.ecnECT1Count = 50;
    ackFrame.ecnCECount = 20;

    auto result = processAck(ackFrame, baseTime + 10ms);
    ASSERT_FALSE(result.hasError());
  }

  // Second ACK with higher ECN counts (no truncation)
  {
    ReadAckFrame ackFrame;
    ackFrame.largestAcked = 1;
    ackFrame.ackBlocks.emplace_back(1, 1);
    ackFrame.ecnECT0Count = 20;
    ackFrame.ecnECT1Count = 100;
    ackFrame.ecnCECount = 40;

    auto result = processAck(ackFrame, baseTime + 60ms);
    EXPECT_FALSE(result.hasError())
        << "Monotonically increasing ECN counts should not cause errors";
  }
}

} // namespace quic::test
