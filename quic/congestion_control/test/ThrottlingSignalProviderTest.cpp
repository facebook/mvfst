/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/Bbr.h>
#include <quic/congestion_control/BbrBandwidthSampler.h>
#include <quic/congestion_control/SimulatedTBF.h>
#include <quic/congestion_control/ThrottlingSignalProvider.h>
#include <quic/state/test/Mocks.h>

using namespace ::testing;

namespace quic::test {

// A simple implementation of throttling signal provider, which has a single
// static SimTBF that consumes the packets on send.
class SimpleThrottlingSignalProvider : public PacketProcessor,
                                       public ThrottlingSignalProvider {
 public:
  explicit SimpleThrottlingSignalProvider(
      SimulatedTBF::Config config,
      folly::Optional<uint64_t> unthrottledRateBytesPerSecond = folly::none)
      : stbf_(std::move(config)),
        unthrottledRateBytesPerSecond_(
            std::move(unthrottledRateBytesPerSecond)) {}
  ~SimpleThrottlingSignalProvider() override = default;
  void onPacketSent(const quic::OutstandingPacketWrapper& packet) override {
    stbf_.consumeWithBorrowNonBlockingAndUpdateState(
        packet.metadata.encodedSize, packet.metadata.time);
  }

  [[nodiscard]] folly::Optional<ThrottlingSignal> getCurrentThrottlingSignal()
      override {
    auto availTokens = stbf_.getNumAvailableTokensInBytes(quic::Clock::now());
    ThrottlingSignal signal = {};
    signal.state = availTokens > 0 ? ThrottlingSignal::State::Unthrottled
                                   : ThrottlingSignal::State::Throttled;
    signal.maybeBytesToSend.assign((uint64_t)availTokens);
    signal.maybeThrottledRateBytesPerSecond.assign(
        (uint64_t)stbf_.getRateBytesPerSecond());
    signal.maybeUnthrottledRateBytesPerSecond.assign(
        unthrottledRateBytesPerSecond_);
    return signal;
  }

 private:
  SimulatedTBF stbf_;
  folly::Optional<uint64_t> unthrottledRateBytesPerSecond_;
};

TEST(ThrottlingSignalProviderTest, BasicInitSetGetTest) {
  auto mockThrottlingSignalProvider =
      std::make_shared<MockThrottlingSignalProvider>();

  EXPECT_FALSE(
      mockThrottlingSignalProvider->getCurrentThrottlingSignal().has_value());

  ThrottlingSignalProvider::ThrottlingSignal expectedSignal;
  expectedSignal.state =
      ThrottlingSignalProvider::ThrottlingSignal::State::Throttled;
  expectedSignal.maybeBytesToSend = 10000;
  expectedSignal.maybeThrottledRateBytesPerSecond = 187500;
  mockThrottlingSignalProvider->useFakeThrottlingSignal(expectedSignal);
  EXPECT_TRUE(
      mockThrottlingSignalProvider->getCurrentThrottlingSignal().has_value());
  auto signal =
      mockThrottlingSignalProvider->getCurrentThrottlingSignal().value();

  EXPECT_EQ(signal.state, expectedSignal.state);
  EXPECT_EQ(signal.maybeBytesToSend, expectedSignal.maybeBytesToSend);
  EXPECT_EQ(
      signal.maybeThrottledRateBytesPerSecond,
      expectedSignal.maybeThrottledRateBytesPerSecond);
  EXPECT_FALSE(signal.maybeUnthrottledRateBytesPerSecond.has_value());
}

TEST(ThrottlingSignalProviderTest, TokenBasedDynamicCapOnWritableBytes) {
  QuicConnectionStateBase conn(QuicNodeType::Server);
  conn.udpSendPacketLen = 2000;
  auto signalProvider =
      std::make_shared<SimpleThrottlingSignalProvider>(SimulatedTBF::Config{
          .rateBytesPerSecond = 100 * 1000,
          .burstSizeBytes = 500 * 1000,
          .maybeMaxDebtQueueSizeBytes = 50 * 1000,
          .trackEmptyIntervals = false});
  conn.throttlingSignalProvider = signalProvider;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  conn.congestionController = std::move(mockCongestionController);

  auto now = Clock::now();
  uint64_t totalBytesSent = 0;
  // Send 1000 packets, each with 2000 bytes every 10ms = 200KBps, which is
  // enough to consume the SimTBF's burst.
  for (PacketNum pn = 0; pn < 1000; pn++) {
    auto packet = makeTestingWritePacket(pn, 2000, totalBytesSent, now);
    signalProvider->onPacketSent(packet);
    conn.congestionController->onPacketSent(packet);
    totalBytesSent += 2000;

    // Ack each sent packet after 5ms
    auto ack = makeAck(
        pn, 2000, now + std::chrono::milliseconds{5}, packet.metadata.time);
    conn.congestionController->onPacketAckOrLoss(&ack, nullptr);
    auto writableBytes = congestionControlWritableBytes(conn);
    auto maybeSignal = signalProvider->getCurrentThrottlingSignal();
    ASSERT_TRUE(maybeSignal.has_value());
    auto maybeBytesToSend = maybeSignal.value().maybeBytesToSend;
    ASSERT_TRUE(maybeBytesToSend.has_value());
    // Since congestionControlWritableBytes is rounded to the nearest
    // multiple of udpSendPacketLen, which is 2000 bytes, do the same for
    // bytesToSend.
    auto roundedBytesToSend =
        (maybeBytesToSend.value() + conn.udpSendPacketLen - 1) /
        conn.udpSendPacketLen * conn.udpSendPacketLen;
    // writable bytes must be less than bytes to sends, which is the same as the
    // number of tokens.
    EXPECT_GE(roundedBytesToSend, writableBytes);

    now += std::chrono::milliseconds{10};
  }
}

TEST(
    ThrottlingSignalProviderTest,
    OverrideBbrBwWithThrottlingSignalProviderRates) {
  QuicConnectionStateBase conn(QuicNodeType::Server);

  // enforce an unthrottled rate of 400KBps and throttledRate of 100KBps
  const uint64_t unthrottledRateBytesPerSecond = 400 * 1000;
  const uint64_t throttledRateBytesPerSecond = 100 * 1000;
  auto signalProvider = std::make_shared<SimpleThrottlingSignalProvider>(
      SimulatedTBF::Config{
          .rateBytesPerSecond = throttledRateBytesPerSecond,
          .burstSizeBytes = 500 * 1000,
          .maybeMaxDebtQueueSizeBytes = 50 * 1000,
          .trackEmptyIntervals = false},
      unthrottledRateBytesPerSecond);
  conn.throttlingSignalProvider = signalProvider;
  BbrCongestionController bbr(conn);
  bbr.setBandwidthSampler(std::make_unique<BbrBandwidthSampler>(conn));

  auto now = Clock::now();
  uint64_t totalBytesSent = 0;
  // Send 1000 packets, each with 2000 bytes every 10ms = 200KBps, which is
  // enough to consume the SimTBF burst.
  for (PacketNum pn = 0; pn < 1000; pn++) {
    auto packet = makeTestingWritePacket(pn, 2000, totalBytesSent, now);
    signalProvider->onPacketSent(packet);
    bbr.onPacketSent(packet);
    totalBytesSent += 2000;
    // Ack each sent packet after 5ms
    bbr.onPacketAckOrLoss(
        makeAck(
            pn, 2000, now + std::chrono::milliseconds{5}, packet.metadata.time),
        folly::none);
    auto maybeSignal = signalProvider->getCurrentThrottlingSignal();
    ASSERT_TRUE(maybeSignal.has_value());
    ASSERT_TRUE(bbr.getBandwidth().has_value());
    if (maybeSignal.value().state ==
        ThrottlingSignalProvider::ThrottlingSignal::State::Unthrottled) {
      // unthrottledRateBytesPerSecond is set to 400KBps during burst, which is
      // larger than send/ack rate, which is 200KBps.
      EXPECT_EQ(
          bbr.getBandwidth().value().normalize(),
          unthrottledRateBytesPerSecond);
    } else if (
        maybeSignal.value().state ==
        ThrottlingSignalProvider::ThrottlingSignal::State::Throttled) {
      // throttledRate is set to 100KBps, which is smaller than
      // send/ack rate, which is 200KBps.
      EXPECT_EQ(
          bbr.getBandwidth().value().normalize(), throttledRateBytesPerSecond);
    }

    now += std::chrono::milliseconds{10};
  }
}
} // namespace quic::test
