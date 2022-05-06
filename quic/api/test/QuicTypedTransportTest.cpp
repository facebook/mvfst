/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <chrono>

#include <quic/api/test/Mocks.h>
#include <quic/api/test/QuicTypedTransportTestUtil.h>
#include <quic/codec/Types.h>
#include <quic/congestion_control/StaticCwndCongestionController.h>
#include <quic/fizz/client/test/QuicClientTransportTestUtil.h>
#include <quic/server/test/QuicServerTransportTestUtil.h>
#include <quic/state/AckEvent.h>
#include <quic/state/OutstandingPacket.h>

using namespace folly;
using namespace testing;

namespace {

using TransportTypes = testing::Types<
    quic::test::QuicClientTransportAfterStartTestBase,
    quic::test::QuicServerTransportTestBase>;

class TransportTypeNames {
 public:
  template <typename T>
  static std::string GetName(int) {
    // we have to remove "::" from the string that we return here,
    // or gtest will silently refuse to run these tests!
    auto str = folly::demangle(typeid(T)).toStdString();
    if (str.find_last_of("::") != str.npos) {
      return str.substr(str.find_last_of("::") + 1);
    }
    return str;
  }
};

} // namespace

namespace quic::test {

template <typename T>
class QuicTypedTransportTest : public virtual testing::Test,
                               public QuicTypedTransportTestBase<T> {
 public:
  void SetUp() override {
    // trigger setup of the underlying transport
    QuicTypedTransportTestBase<T>::SetUp();
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportTest,
    ::TransportTypes,
    ::TransportTypeNames);

/**
 * Verify that RTT signals are properly passed through to TransportInfo.
 *
 * Currently tests mrtt, mrttNoAckDelay, lrttRaw, lrttRawAckDelay
 */
TYPED_TEST(QuicTypedTransportTest, TransportInfoRttSignals) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(folly::none, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      folly::none,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 31ms (5 ms) |     26ms      ||   31   |       26       | (both)
  //    2  | 30ms (3 ms) |     27ms      ||   30   |       26       | (1)
  //    3  | 30ms (8 ms) |     22ms      ||   30   |       22       | (2)
  //    4  | 37ms (8 ms) |     29ms      ||   30   |       22       | (none)
  //    5  | 25ms (0 ms) |     29ms      ||   25   |       22       | (1)
  //    6  | 25ms (4 ms) |     29ms      ||   25   |       21       | (2)
  //    7  | 20ms (0 ms) |     29ms      ||   20   |       20       | (both)

  // case 1 [31ms (5 ms)]
  {
    const auto rtt = 31ms;
    const auto ackDelay = 5ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 31ms;
    const auto expectedMinRttNoAckDelay = 26ms;
    if constexpr (std::is_same_v<
                      TypeParam,
                      QuicClientTransportAfterStartTestBase>) {
    } else if constexpr (std::is_same_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 2 [30ms (3 ms)]
  {
    const auto rtt = 30ms;
    const auto ackDelay = 3ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 30ms;
    const auto expectedMinRttNoAckDelay = 26ms;
    if constexpr (std::is_same_v<
                      TypeParam,
                      QuicClientTransportAfterStartTestBase>) {
    } else if constexpr (std::is_same_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 3 [30ms (8 ms)]
  {
    const auto rtt = 30ms;
    const auto ackDelay = 8ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 30ms;
    const auto expectedMinRttNoAckDelay = 22ms;
    if constexpr (std::is_same_v<
                      TypeParam,
                      QuicClientTransportAfterStartTestBase>) {
    } else if constexpr (std::is_same_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 4 [37ms (8 ms)]
  {
    const auto rtt = 37ms;
    const auto ackDelay = 8ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 30ms;
    const auto expectedMinRttNoAckDelay = 22ms;
    if constexpr (std::is_same_v<
                      TypeParam,
                      QuicClientTransportAfterStartTestBase>) {
    } else if constexpr (std::is_same_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 5 [25ms (0 ms)]
  {
    const auto rtt = 25ms;
    const auto ackDelay = 0ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    const auto expectedMinRttNoAckDelay = 22ms;
    if constexpr (std::is_same_v<
                      TypeParam,
                      QuicClientTransportAfterStartTestBase>) {
    } else if constexpr (std::is_same_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 6 [25ms (4 ms)]
  {
    const auto rtt = 25ms;
    const auto ackDelay = 4ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    const auto expectedMinRttNoAckDelay = 21ms;
    if constexpr (std::is_same_v<
                      TypeParam,
                      QuicClientTransportAfterStartTestBase>) {
    } else if constexpr (std::is_same_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  // case 7 [20ms (0 ms)]
  {
    const auto rtt = 20ms;
    const auto ackDelay = 0ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 20ms;
    const auto expectedMinRttNoAckDelay = 20ms;
    if constexpr (std::is_same_v<
                      TypeParam,
                      QuicClientTransportAfterStartTestBase>) {
    } else if constexpr (std::is_same_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Test case where the ACK delay is equal to the RTT sample.
 */
TYPED_TEST(QuicTypedTransportTest, RttSampleAckDelayEqual) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(folly::none, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      folly::none,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 25ms (25 ms)|     25ms      ||   25   |       0        | (both)
  {
    const auto rtt = 25ms;
    const auto ackDelay = 25ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    const auto expectedMinRttNoAckDelay = 0ms;
    if constexpr (std::is_same_v<
                      TypeParam,
                      QuicClientTransportAfterStartTestBase>) {
    } else if constexpr (std::is_same_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(expectedMinRttNoAckDelay, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Test case where the ACK delay is greater than the RTT sample.
 */
TYPED_TEST(QuicTypedTransportTest, RttSampleAckDelayGreater) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(folly::none, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      folly::none,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 25ms (26 ms)|     25ms      ||   25   |  folly::none   | (1)
  {
    const auto rtt = 25ms;
    const auto ackDelay = 26ms;
    sendAndAckPacket(rtt, ackDelay);

    const auto expectedMinRtt = 25ms;
    if constexpr (std::is_same_v<
                      TypeParam,
                      QuicClientTransportAfterStartTestBase>) {
    } else if constexpr (std::is_same_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_EQ(rtt, tInfo.maybeLrtt);
      EXPECT_EQ(ackDelay, tInfo.maybeLrttAckDelay);
      EXPECT_EQ(expectedMinRtt, tInfo.maybeMinRtt);
      EXPECT_EQ(folly::none, tInfo.maybeMinRttNoAckDelay); // unavailable
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Test case where the RTT sample has zero time based on socket RX timestamp.
 *
 * In this case, we should fallback to using system clock timestamp, and thus
 * should end up with a non-zero RTT.
 */
TYPED_TEST(QuicTypedTransportTest, RttSampleZeroTime) {
  // lambda to send and ACK a packet
  const auto sendAndAckPacket = [&](const auto& rttIn, const auto& ackDelayIn) {
    auto streamId = this->getTransport()->createBidirectionalStream().value();
    this->getTransport()->writeChain(
        streamId, IOBuf::copyBuffer("hello"), false);
    const auto maybeWriteInterval = this->loopForWrites();
    EXPECT_EQ(1, this->getNumPacketsWritten(maybeWriteInterval));

    // get the packet's send time
    const auto packetSentTime =
        CHECK_NOTNULL(this->getNewestAppDataOutstandingPacket())->metadata.time;

    // deliver an ACK for the outstanding packet rttIn ms later
    const auto packetAckTime = packetSentTime + rttIn;
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWriteInterval, ackDelayIn),
        packetAckTime);
  };

  // minRTT should not be available in any form
  EXPECT_EQ(folly::none, this->getTransport()->getTransportInfo().maybeMinRtt);
  EXPECT_EQ(
      folly::none,
      this->getTransport()->getTransportInfo().maybeMinRttNoAckDelay);

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  //                                     ||   [ Value Expected ]   |
  //  Case | RTT (delay) | RTT w/o delay ||  mRTT  |  w/o ACK delay | Updated
  //  -----|-------------|---------------||------- |----------------|----------
  //    1  | 0ms (0 ms)  |     0ms       ||   >0   |      >0        | (both)
  {
    const auto rtt = 0ms;
    const auto ackDelay = 0ms;
    sendAndAckPacket(rtt, ackDelay);
    if constexpr (std::is_same_v<
                      TypeParam,
                      QuicClientTransportAfterStartTestBase>) {
    } else if constexpr (std::is_same_v<
                             TypeParam,
                             QuicServerTransportTestBase>) {
      const auto tInfo = this->getTransport()->getTransportInfo();
      EXPECT_LE(0ms, tInfo.maybeLrtt.value());
      EXPECT_GE(500ms, tInfo.maybeLrtt.value());
      EXPECT_EQ(0ms, tInfo.maybeLrttAckDelay.value());
      EXPECT_EQ(tInfo.maybeLrtt, tInfo.maybeMinRtt);
      EXPECT_EQ(tInfo.maybeMinRtt, tInfo.maybeMinRttNoAckDelay);
    } else {
      FAIL(); // unhandled typed test
    }
  }

  this->destroyTransport();
}

/**
 * Verify vector used to store ACK events has no capacity if no pkts in flight.
 */
TYPED_TEST(QuicTypedTransportTest, AckEventsNoAllocatedSpaceWhenNoOutstanding) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(firstPacketNum, lastPacketNum),
      std::chrono::steady_clock::time_point());

  // should be no space (capacity) for ACK events
  EXPECT_EQ(0, this->getConn().lastProcessedAckEvents.capacity());

  this->destroyTransport();
}

/**
 * Verify vector used to store ACK events has no capacity if no pkts in flight.
 *
 * Two packets to give opportunity for packets in flight.
 */
TYPED_TEST(
    QuicTypedTransportTest,
    AckEventsNoAllocatedSpaceWhenNoOutstandingTwoInFlight) {
  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  {
    quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets1->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  // write some more bytes into the same stream
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // should have sent another packet
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  {
    quic::PacketNum firstPacketNum = maybeWrittenPackets2->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets2->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  // deliver an ACK for the first packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(
          maybeWrittenPackets1->start, maybeWrittenPackets1->end),
      std::chrono::steady_clock::time_point());

  // should be space allocated for ACK events
  EXPECT_NE(0, this->getConn().lastProcessedAckEvents.capacity());

  // deliver an ACK for the second packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(
          maybeWrittenPackets2->start, maybeWrittenPackets2->end),
      std::chrono::steady_clock::time_point());

  // should be no space (capacity) for ACK events
  EXPECT_EQ(0, this->getConn().lastProcessedAckEvents.capacity());

  this->destroyTransport();
}

/**
 * Verify vector used to store ACK events has no capacity if no pkts in flight.
 *
 * Two packets ACKed in reverse to give opportunity for packets in flight.
 */
TYPED_TEST(
    QuicTypedTransportTest,
    AckEventsNoAllocatedSpaceWhenNoOutstandingTwoInFlightReverse) {
  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  // clear any outstanding packets
  this->getNonConstConn().outstandings.reset();

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  {
    quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets1->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  // write some more bytes into the same stream
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // should have sent another packet
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  {
    quic::PacketNum firstPacketNum = maybeWrittenPackets2->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets2->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  // deliver an ACK for the second packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(
          maybeWrittenPackets2->start, maybeWrittenPackets2->end),
      std::chrono::steady_clock::time_point());

  // should be space allocated for ACK events
  EXPECT_NE(0, this->getConn().lastProcessedAckEvents.capacity());

  // deliver an ACK for the first packet
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(
          maybeWrittenPackets1->start, maybeWrittenPackets1->end),
      std::chrono::steady_clock::time_point());

  // should be no space (capacity) for ACK events
  EXPECT_EQ(0, this->getConn().lastProcessedAckEvents.capacity());

  this->destroyTransport();
}

template <typename T>
class QuicTypedTransportTestForObservers : public QuicTypedTransportTest<T> {
 public:
  void SetUp() override {
    QuicTypedTransportTest<T>::SetUp();
  }

  struct AckEventMatcherBuilder {
    using Builder = AckEventMatcherBuilder;
    Builder&& setExpectedAckedIntervals(
        std::vector<
            typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>
            expectedAckedIntervals) {
      maybeExpectedAckedIntervals = std::move(expectedAckedIntervals);
      return std::move(*this);
    }
    Builder&& setExpectedAckedIntervals(
        std::vector<folly::Optional<
            typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>>
            expectedAckedIntervalsOpt) {
      std::vector<
          typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>
          expectedAckedIntervals;
      for (const auto& maybeInterval : expectedAckedIntervalsOpt) {
        CHECK(maybeInterval.has_value());
        expectedAckedIntervals.push_back(maybeInterval.value());
      }
      maybeExpectedAckedIntervals = std::move(expectedAckedIntervals);
      return std::move(*this);
    }
    Builder&& setExpectedNumAckedPackets(
        const uint64_t expectedNumAckedPackets) {
      maybeExpectedNumAckedPackets = expectedNumAckedPackets;
      return std::move(*this);
    }
    Builder&& setAckTime(TimePoint ackTime) {
      maybeAckTime = ackTime;
      return std::move(*this);
    }
    Builder&& setAckDelay(std::chrono::microseconds ackDelay) {
      maybeAckDelay = ackDelay;
      return std::move(*this);
    }
    Builder&& setLargestAckedPacket(quic::PacketNum largestAckedPacketIn) {
      maybeLargestAckedPacket = largestAckedPacketIn;
      return std::move(*this);
    }
    Builder&& setLargestNewlyAckedPacket(
        quic::PacketNum largestNewlyAckedPacketIn) {
      maybeLargestNewlyAckedPacket = largestNewlyAckedPacketIn;
      return std::move(*this);
    }
    Builder&& setRtt(const folly::Optional<std::chrono::microseconds>& rttIn) {
      maybeRtt = rttIn;
      CHECK(!noRtt);
      return std::move(*this);
    }
    Builder&& setRttNoAckDelay(
        const folly::Optional<std::chrono::microseconds>& rttNoAckDelayIn) {
      maybeRttNoAckDelay = rttNoAckDelayIn;
      CHECK(!noRtt);
      CHECK(!noRttWithNoAckDelay);
      return std::move(*this);
    }
    Builder&& setNoRtt() {
      noRtt = true;
      CHECK(!maybeRtt);
      CHECK(!maybeRttNoAckDelay);
      return std::move(*this);
    }
    Builder&& setNoRttWithNoAckDelay() {
      noRttWithNoAckDelay = true;
      CHECK(!maybeRttNoAckDelay);
      return std::move(*this);
    }
    auto build() && {
      CHECK(
          noRtt ||
          (maybeRtt.has_value() &&
           (noRttWithNoAckDelay || maybeRttNoAckDelay.has_value())));

      CHECK(maybeExpectedAckedIntervals.has_value());
      const auto& expectedAckedIntervals = *maybeExpectedAckedIntervals;
      CHECK_LT(0, expectedAckedIntervals.size());

      CHECK(maybeExpectedNumAckedPackets.has_value());
      const auto& expectedNumAckedPackets = *maybeExpectedNumAckedPackets;

      CHECK(maybeAckTime.has_value());
      const auto& ackTime = *maybeAckTime;

      CHECK(maybeAckDelay.has_value());
      const auto& ackDelay = *maybeAckDelay;

      CHECK(maybeLargestAckedPacket.has_value());
      const auto& largestAckedPacket = *maybeLargestAckedPacket;

      CHECK(maybeLargestNewlyAckedPacket.has_value());
      const auto& largestNewlyAckedPacket = *maybeLargestNewlyAckedPacket;

      // sanity check expectedNumAckedPackets and expectedAckedIntervals
      // reduces potential of error in test design
      {
        uint64_t expectedNumAckedPacketsFromIntervals = 0;
        std::vector<
            typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>
            processedExpectedAckedIntervals;

        for (const auto& interval : expectedAckedIntervals) {
          CHECK_LE(interval.start, interval.end);
          CHECK_LE(0, interval.end);
          expectedNumAckedPacketsFromIntervals +=
              interval.end - interval.start + 1;

          // should not overlap with existing intervals
          for (const auto& processedInterval :
               processedExpectedAckedIntervals) {
            CHECK(
                processedInterval.end < interval.start ||
                processedInterval.start < interval.end);
          }

          processedExpectedAckedIntervals.push_back(interval);
        }
        CHECK_EQ(expectedNumAckedPacketsFromIntervals, expectedNumAckedPackets);
      }

      if constexpr (std::is_same_v<T, QuicClientTransportAfterStartTestBase>) {
        return testing::Property(
            &quic::SocketObserverInterface::AcksProcessedEvent::getAckEvents,
            testing::ElementsAre(testing::AllOf(
                // ack time, adjusted ack time, RTT not supported for client now
                testing::Field(
                    &quic::AckEvent::ackDelay, testing::Eq(ackDelay)),
                testing::Field(
                    &quic::AckEvent::largestAckedPacket,
                    testing::Eq(largestAckedPacket)),
                testing::Field(
                    &quic::AckEvent::largestNewlyAckedPacket,
                    testing::Eq(largestNewlyAckedPacket)),
                testing::Field(
                    &quic::AckEvent::ackedPackets,
                    testing::SizeIs(expectedNumAckedPackets)))));
      } else if constexpr (std::is_same_v<T, QuicServerTransportTestBase>) {
        return testing::Property(
            &quic::SocketObserverInterface::AcksProcessedEvent::getAckEvents,
            testing::ElementsAre(testing::AllOf(
                testing::Field(&quic::AckEvent::ackTime, testing::Eq(ackTime)),
                testing::Field(
                    &quic::AckEvent::adjustedAckTime,
                    testing::Eq(ackTime - ackDelay)),
                testing::Field(
                    &quic::AckEvent::ackDelay, testing::Eq(ackDelay)),
                testing::Field(
                    &quic::AckEvent::largestAckedPacket,
                    testing::Eq(largestAckedPacket)),
                testing::Field(
                    &quic::AckEvent::largestNewlyAckedPacket,
                    testing::Eq(largestNewlyAckedPacket)),
                testing::Field(
                    &quic::AckEvent::ackedPackets,
                    testing::SizeIs(expectedNumAckedPackets)),
                testing::Field(
                    &quic::AckEvent::rttSample, testing::Eq(maybeRtt)),
                testing::Field(
                    &quic::AckEvent::rttSampleNoAckDelay,
                    testing::Eq(maybeRttNoAckDelay)))));
      } else {
        FAIL(); // unhandled typed test
      }
    }
    explicit AckEventMatcherBuilder() = default;

    folly::Optional<std::vector<
        typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>>
        maybeExpectedAckedIntervals;
    folly::Optional<uint64_t> maybeExpectedNumAckedPackets;
    folly::Optional<TimePoint> maybeAckTime;
    folly::Optional<std::chrono::microseconds> maybeAckDelay;
    folly::Optional<quic::PacketNum> maybeLargestAckedPacket;
    folly::Optional<quic::PacketNum> maybeLargestNewlyAckedPacket;
    folly::Optional<std::chrono::microseconds> maybeRtt;
    folly::Optional<std::chrono::microseconds> maybeRttNoAckDelay;
    bool noRtt{false};
    bool noRttWithNoAckDelay{false};
  };

  struct ReceivedPacketMatcherBuilder {
    using Builder = ReceivedPacketMatcherBuilder;
    using Obj =
        quic::SocketObserverInterface::PacketsReceivedEvent::ReceivedPacket;
    Builder&& setExpectedPacketReceiveTime(
        const TimePoint expectedPacketReceiveTime) {
      maybeExpectedPacketReceiveTime = expectedPacketReceiveTime;
      return std::move(*this);
    }
    Builder&& setExpectedPacketNumBytes(const uint64_t expectedPacketNumBytes) {
      maybeExpectedPacketNumBytes = expectedPacketNumBytes;
      return std::move(*this);
    }
    auto build() && {
      CHECK(maybeExpectedPacketReceiveTime.has_value());
      const auto& packetReceiveTime = *maybeExpectedPacketReceiveTime;

      CHECK(maybeExpectedPacketNumBytes.has_value());
      const auto& packetNumBytes = *maybeExpectedPacketNumBytes;

      if constexpr (std::is_same_v<T, QuicClientTransportAfterStartTestBase>) {
        return testing::AllOf(
            // client does not currently support socket RX timestamps, so we
            // expect ts >= now() at time of matcher build
            testing::Field(
                &Obj::packetReceiveTime,
                testing::AnyOf(
                    testing::Eq(packetReceiveTime),
                    testing::Ge(TimePoint::clock::now()))),
            testing::Field(&Obj::packetNumBytes, testing::Eq(packetNumBytes)));
      } else if constexpr (std::is_same_v<T, QuicServerTransportTestBase>) {
        return testing::AllOf(
            testing::Field(
                &Obj::packetReceiveTime, testing::Eq(packetReceiveTime)),
            testing::Field(&Obj::packetNumBytes, testing::Eq(packetNumBytes)));
      } else {
        FAIL(); // unhandled typed test
      }
    }
    explicit ReceivedPacketMatcherBuilder() = default;

    folly::Optional<TimePoint> maybeExpectedPacketReceiveTime;
    folly::Optional<uint64_t> maybeExpectedPacketNumBytes;
  };

  auto getStreamEventMatcherOpt(
      const StreamId streamId,
      const StreamInitiator streamInitiator,
      const StreamDirectionality streamDirectionality) {
    return testing::AllOf(
        testing::Field(
            &quic::SocketObserverInterface::StreamEvent::streamId,
            testing::Eq(streamId)),
        testing::Field(
            &quic::SocketObserverInterface::StreamEvent::streamInitiator,
            testing::Eq(streamInitiator)),
        testing::Field(
            &quic::SocketObserverInterface::StreamEvent::streamDirectionality,
            testing::Eq(streamDirectionality)));
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportTestForObservers,
    ::TransportTypes,
    ::TransportTypeNames);

TYPED_TEST(QuicTypedTransportTestForObservers, AttachThenDetach) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_EQ(0, transport->numObservers());
  EXPECT_THAT(transport->getObservers(), IsEmpty());

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_EQ(1, transport->numObservers());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  EXPECT_CALL(*observer, detached(transport));
  EXPECT_TRUE(transport->removeObserver(observer.get()));
  Mock::VerifyAndClearExpectations(observer.get());
  EXPECT_EQ(0, transport->numObservers());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseNoErrorThenDestroyTransport) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError defaultError = QuicError(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *observer, close(transport, folly::Optional<QuicError>(defaultError)));
  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(observer.get());
  InSequence s;
  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
  Mock::VerifyAndClearExpectations(observer.get());
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    CloseWithErrorThenDestroyTransport) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, attached(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const auto testError = QuicError(
      QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
      std::string("testError"));
  EXPECT_CALL(
      *observer, close(transport, folly::Optional<QuicError>(testError)));
  transport->close(testError);
  Mock::VerifyAndClearExpectations(observer.get());
  InSequence s;
  EXPECT_CALL(*observer, destroyed(transport, IsNull()));
  this->destroyTransport();
  Mock::VerifyAndClearExpectations(observer.get());
}

TYPED_TEST(QuicTypedTransportTestForObservers, LegacyAttachThenDetach) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*observer, observerAttach(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));
  EXPECT_CALL(*observer, observerDetach(transport));
  EXPECT_TRUE(transport->removeObserver(observer.get()));
  Mock::VerifyAndClearExpectations(observer.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    LegacyCloseNoErrorThenDestroyTransport) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*observer, observerAttach(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const QuicError defaultError = QuicError(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *observer, close(transport, folly::Optional<QuicError>(defaultError)));
  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(observer.get());
  InSequence s;
  EXPECT_CALL(*observer, destroy(transport));
  this->destroyTransport();
  Mock::VerifyAndClearExpectations(observer.get());
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    LegacyCloseWithErrorThenDestroyTransport) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*observer, observerAttach(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const auto testError = QuicError(
      QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
      std::string("testError"));
  EXPECT_CALL(
      *observer, close(transport, folly::Optional<QuicError>(testError)));
  transport->close(testError);
  Mock::VerifyAndClearExpectations(observer.get());
  InSequence s;
  EXPECT_CALL(*observer, destroy(transport));
  this->destroyTransport();
  Mock::VerifyAndClearExpectations(observer.get());
}

TYPED_TEST(QuicTypedTransportTestForObservers, StreamEventsLocalOpenedStream) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createBidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data, see a packet be written
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver ACK for first packet sent by local
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver a packet with stream data from the remote
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello2")));

  // local sends goodbye with EOF, gets the ACK
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("goodbye1"), true /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  // one more message from the peer, this time with EOF
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye2")));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsLocalOpenedStreamImmediateEofLocal) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createBidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data with EOF, see a packet be written
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), true /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver ACK for first packet sent by local
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver a packet with stream data from the remote
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello2")));

  // one more message from the peer, this time with EOF
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye")));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsLocalOpenedStreamImmediateEofLocalRemote) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  const auto streamId = this->createBidirectionalStream();
  EXPECT_EQ(expectedStreamId, streamId);

  // send some stream data with EOF, see a packet be written
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello1"), true /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver ACK for first packet sent by local
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver a packet with stream data from the remote with an EOF
  // stream should close on arrival of packet from remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Local, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello2")));

  this->destroyTransport();
}

TYPED_TEST(QuicTypedTransportTestForObservers, StreamEventsPeerOpenedStream) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, gets the ACK
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // one more message from the peer, this time with EOF
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye1")));

  // local sends goodbye with EOF too, get the ACK, stream should close
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("goodbye2"), true /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsPeerOpenedStreamImmediateEofRemote) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data + EOF from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // send some stream data, see a packet be written, get the ACK
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // local sends goodbye with EOF too, get the ACK, stream should close
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("goodbye"), true /* eof */);
  const auto maybeWrittenPackets2 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets2));
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsPeerOpenedStreamImmediateEofLocalRemote) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data + EOF from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // send some stream data with EOF, see a packet be written, get the ACK
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), true /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // stream should close on arrival of ACK
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsPeerOpenedStreamStopSendingPlusRstTriggersRst) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, gets the ACK
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  // deliver reset from remote
  this->deliverPacket(
      this->buildPeerPacketWithRstStreamFrame(streamId, 6 /* offset */));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for rst packet, then stream should close
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsPeerOpenedStreamStopSendingPlusRstTriggersRstBytesInFlight) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamData(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, ACK not received
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver reset from remote
  this->deliverPacket(
      this->buildPeerPacketWithRstStreamFrame(streamId, 6 /* offset */));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for rst packet, then stream should close
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsPeerOpenedStreamImmediateEorStopSendingTriggersRstBytesInFlight) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamOpened(transport, matcher));
    EXPECT_CALL(*obs3, streamOpened(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello1")));

  // local sends some stream data, see a packet be written, ACK not received
  this->getTransport()->writeChain(
      streamId, IOBuf::copyBuffer("hello2"), false /* eof */);
  const auto maybeWrittenPackets1 = this->loopForWrites();
  EXPECT_EQ(1, this->getNumPacketsWritten(maybeWrittenPackets1));

  // deliver stop sending frame, trigger reset locally on receipt of frame
  // give opportunity for packets to be sent
  EXPECT_FALSE(this->template getFirstOutstandingPacketWithFrame<
                       QuicWriteFrame::Type::RstStreamFrame>()
                   .has_value());
  EXPECT_CALL(
      this->getConnCallback(),
      onStopSending(streamId, GenericApplicationErrorCode::UNKNOWN))
      .WillRepeatedly(Invoke([this](const auto& streamId, const auto& error) {
        const auto result = this->getTransport()->resetStream(streamId, error);
        EXPECT_FALSE(result.hasError());
      }));
  this->deliverPacket(this->buildPeerPacketWithStopSendingFrame(streamId));
  const auto maybeRstPacketNum =
      this->template getFirstOutstandingPacketWithFrame<
          QuicWriteFrame::Type::RstStreamFrame>();
  ASSERT_TRUE(maybeRstPacketNum.has_value());

  // deliver ACK for rst packet, then stream should close
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*obs1, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*obs2, streamClosed(transport, matcher));
    EXPECT_CALL(*obs3, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    WriteEventsOutstandingPacketSent) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // install StaticCwndCongestionController
  const auto cwndInBytes = 10000;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // string to write
  const std::string str1 = "hello";
  const auto strLength = str1.length();

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // setup matchers
  {
    writeCount++; // write count will be incremented

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(
        *obs2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *obs3,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(cwndInBytes - strLength))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(strLength)));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    // matcher for event from appRateLimited
    const auto appRateLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(cwndInBytes - strLength))));

    EXPECT_CALL(*obs1, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
    EXPECT_CALL(*obs3, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
  }

  // open a stream and write string
  {
    this->getTransport()->writeChain(streamId, IOBuf::copyBuffer(str1), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    WriteEventsOutstandingPacketSentWroteMoreThanCwnd) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // install StaticCwndCongestionController with a CWND < MSS
  const auto cwndInBytes = 800;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // we're going to write 1000 bytes with a smaller CWND
  // because MSS > CWND, we're going to overshoot
  const auto bufLength = 1000;
  auto buf = buildRandomInputData(bufLength);
  EXPECT_GT(bufLength, cwndInBytes);

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // setup matchers
  {
    writeCount++; // write count will be incremented

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(
        *obs2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *obs3,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(0))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce(), expect overshoot CWND
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::AllOf(testing::Gt(bufLength), testing::Gt(cwndInBytes))));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
  }

  // open a stream and write string
  {
    this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  // TODO(bschlinker): Check for appRateLimited on ACK so that we get an
  // appRateLimited signal when the outstanding packet is ACKed.

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    WriteEventsOutstandingPacketsSentCwndLimited) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // install StaticCwndCongestionController
  const auto cwndInBytes = 7000;
  this->getNonConstConn().congestionController =
      std::make_unique<StaticCwndCongestionController>(
          StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // we're going to write 10000 bytes with a CWND of 7000
  const auto bufLength = 10000;
  auto buf = buildRandomInputData(bufLength);
  EXPECT_EQ(7000, cwndInBytes);

  // setup matchers for first write, write the entire buffer, trigger loop
  // we will NOT become app limited after this write, as CWND limited
  {
    writeCount++; // write count will be incremented
    const auto packetsExpectedWritten = 5;

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(
        *obs2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *obs3,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(0))), // CWND exhausted
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Ge(cwndInBytes))); // full CWND written
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    this->getTransport()->writeChain(streamId, std::move(buf), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // make sure we wrote
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(packetsExpectedWritten, lastPacketNum - firstPacketNum + 1);
  }

  // ACK all outstanding packets
  this->ackAllOutstandingPackets();

  // setup matchers for second write, then trigger loop
  // we will become app limited after this write
  {
    writeCount++; // write count will be incremented
    const auto packetsExpectedWritten = 2;

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Lt(cwndInBytes)));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    // matcher for event from appRateLimited
    const auto appRateLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*obs1, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
    EXPECT_CALL(*obs3, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });

    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(packetsExpectedWritten, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    WriteEventsOutstandingPacketSentNoCongestionController) {
  InSequence s;

  // ACK outstanding packets so that we can switch out the congestion control
  this->ackAllOutstandingPackets();
  EXPECT_THAT(this->getConn().outstandings.packets, IsEmpty());

  // determine the starting writeCount
  auto writeCount = this->getConn().writeCount;

  // remove congestion controller
  this->getNonConstConn().congestionController = nullptr;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::appRateLimitedEvents,
      SocketObserverInterface::Events::packetsWrittenEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // string to write
  const std::string str1 = "hello";
  const auto strLength = str1.length();

  // open stream that we will write to
  const auto streamId =
      this->getTransport()->createBidirectionalStream().value();

  // setup matchers
  {
    writeCount++; // write count will be incremented

    // no congestion controller == no startWritingFromAppLimited events
    EXPECT_CALL(*obs1, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, startWritingFromAppLimited(_, _)).Times(0);
    EXPECT_CALL(*obs3, startWritingFromAppLimited(_, _)).Times(0);

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(1)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeCount)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(folly::none))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(folly::none))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce()
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(strLength)));
    EXPECT_CALL(*obs1, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(*obs3, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    // no congestion controller == no appRateLimited events
    EXPECT_CALL(*obs1, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs2, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*obs3, appRateLimited(_, _)).Times(0);
  }

  // open a stream and write str1
  {
    this->getTransport()->writeChain(streamId, IOBuf::copyBuffer(str1), false);
    const auto maybeWrittenPackets = this->loopForWrites();

    // should have sent one packet
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
    quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
    EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsOutstandingPacketSentThenAckedNoAckDelay) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 27ms;
  const auto ackDelay = 0us;
  const auto matcher =
      typename TestFixture::AckEventMatcherBuilder()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(ackDelay)
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
              ackRecvTime - sentTime))
          .setRttNoAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime - ackDelay))
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(ackDelay)
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsOutstandingPacketSentThenAckedWithAckDelay) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  const quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  const quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 50ms;
  const auto ackDelay = 5ms;
  const auto matcher =
      typename TestFixture::AckEventMatcherBuilder()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(ackDelay)
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
              ackRecvTime - sentTime))
          .setRttNoAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime - ackDelay))
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(ackDelay)
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsOutstandingPacketSentThenAckedWithAckDelayEqRtt) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  const quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  const quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 50ms;
  const auto ackDelay = ackRecvTime - sentTime; // ack delay == RTT!
  const auto matcher =
      typename TestFixture::AckEventMatcherBuilder()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
              ackRecvTime - sentTime))
          .setRttNoAckDelay(0us)
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(
      *observerWithAcks1,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(testing::AllOf(testing::Field(
                      &quic::AckEvent::rttSampleNoAckDelay,
                      testing::AnyOf(
                          testing::Eq(0ms), testing::Eq(folly::none)))))))));
  EXPECT_CALL(
      *observerWithAcks2,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(testing::AllOf(testing::Field(
                      &quic::AckEvent::rttSampleNoAckDelay,
                      testing::AnyOf(
                          testing::Eq(0ms), testing::Eq(folly::none)))))))));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsOutstandingPacketSentThenAckedWithTooLargeAckDelay) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets = this->loopForWrites();

  // should have sent one packet
  ASSERT_TRUE(maybeWrittenPackets.has_value());
  const quic::PacketNum firstPacketNum = maybeWrittenPackets->start;
  const quic::PacketNum lastPacketNum = maybeWrittenPackets->end;
  EXPECT_EQ(1, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets->sentTime;
  const auto ackRecvTime = sentTime + 50ms;
  const auto ackDelay = ackRecvTime + 1ms - sentTime; // ack delay >> RTT!
  const auto matcher =
      typename TestFixture::AckEventMatcherBuilder()
          .setExpectedAckedIntervals({maybeWrittenPackets})
          .setExpectedNumAckedPackets(1)
          .setAckTime(ackRecvTime)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .setLargestAckedPacket(maybeWrittenPackets->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
          .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
              ackRecvTime - sentTime))
          .setNoRttWithNoAckDelay()
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(
      *observerWithAcks1,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(testing::AllOf(testing::Field(
                      &quic::AckEvent::rttSampleNoAckDelay,
                      testing::Eq(folly::none))))))));
  EXPECT_CALL(
      *observerWithAcks2,
      acksProcessed(
          transport,
          testing::AllOf(
              matcher,
              testing::Property(
                  &quic::SocketObserverInterface::AcksProcessedEvent::
                      getAckEvents,
                  testing::ElementsAre(testing::AllOf(testing::Field(
                      &quic::AckEvent::rttSampleNoAckDelay,
                      testing::Eq(folly::none))))))));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(ackDelay))
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenAllAckedAtOnce) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets3->end;
  EXPECT_EQ(3, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for all of the outstanding packets
  const auto sentTime = maybeWrittenPackets3->sentTime;
  const auto ackRecvTime = sentTime + 27ms;
  const auto ackDelay = 5ms;
  const auto matcher =
      typename TestFixture::AckEventMatcherBuilder()
          .setExpectedAckedIntervals(
              {maybeWrittenPackets1,
               maybeWrittenPackets2,
               maybeWrittenPackets3})
          .setExpectedNumAckedPackets(3)
          .setAckTime(ackRecvTime)
          .setAckDelay(ackDelay)
          .setLargestAckedPacket(maybeWrittenPackets3->end)
          .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
          .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
              ackRecvTime - sentTime))
          .setRttNoAckDelay(
              std::chrono::duration_cast<std::chrono::microseconds>(
                  ackRecvTime - sentTime - ackDelay))
          .build();
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

  const quic::AckBlocks ackBlocks = {{firstPacketNum, lastPacketNum}};
  auto buf = quic::test::packetToBuf(
      AckPacketBuilder()
          .setDstConn(&this->getNonConstConn())
          .setPacketNumberSpace(PacketNumberSpace::AppData)
          .setAckPacketNumStore(&this->peerPacketNumStore)
          .setAckBlocks(ackBlocks)
          .setAckDelay(ackDelay)
          .build());
  buf->coalesce();
  this->deliverPacket(std::move(buf), ackRecvTime);
  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsThreeOutstandingPacketsSentAndAckedSequentially) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream, write some bytes, send packet, deliver ACK
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());

    const auto sentTime = maybeWrittenPackets->sentTime;
    const auto ackRecvTime = sentTime + 27ms;
    const auto ackDelay = 5ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals({maybeWrittenPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets->start, maybeWrittenPackets->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // write some more bytes into the same stream, send packet, deliver ACK
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("world"), false);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    const auto sentTime = maybeWrittenPackets->sentTime;
    const auto ackRecvTime = sentTime + 443ms;
    const auto ackDelay = 7ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals({maybeWrittenPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets->start, maybeWrittenPackets->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // third and final write, this time with EOF, send packet, deliver ACK
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());

    const auto sentTime = maybeWrittenPackets->sentTime;
    const auto ackRecvTime = sentTime + 62ms;
    const auto ackDelay = 3ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals({maybeWrittenPackets})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets->start, maybeWrittenPackets->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenAckedSequentially) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  quic::PacketNum firstPacketNum = maybeWrittenPackets1->start;
  quic::PacketNum lastPacketNum = maybeWrittenPackets3->end;
  EXPECT_EQ(3, lastPacketNum - firstPacketNum + 1);

  // deliver an ACK for packet 1
  {
    const auto sentTime = maybeWrittenPackets1->sentTime;
    const auto ackRecvTime = sentTime + 122ms;
    const auto ackDelay = 3ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets1->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets1->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    const auto sentTime = maybeWrittenPackets2->sentTime;
    const auto ackRecvTime = sentTime + 62ms;
    const auto ackDelay = 1ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals({maybeWrittenPackets2})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets2->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets2->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets2->start, maybeWrittenPackets2->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 3
  {
    const auto sentTime = maybeWrittenPackets3->sentTime;
    const auto ackRecvTime = sentTime + 82ms;
    const auto ackDelay = 20ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals({maybeWrittenPackets3})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets3->start, maybeWrittenPackets3->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenFirstLastAckedSequentiallyThenSecondAcked) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  EXPECT_EQ(
      3,
      this->getNumPacketsWritten(
          {maybeWrittenPackets1, maybeWrittenPackets2, maybeWrittenPackets3}));

  // deliver an ACK for packet 1
  {
    const auto sentTime = maybeWrittenPackets1->sentTime;
    const auto ackRecvTime = sentTime + 20ms;
    const auto ackDelay = 5ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets1->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets1->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 3
  {
    const auto sentTime = maybeWrittenPackets3->sentTime;
    const auto ackRecvTime = sentTime + 11ms;
    const auto ackDelay = 4ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets3->start, maybeWrittenPackets3->end},
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    // base ACK receive time off of (3) as sent packet was reordered
    const auto ackRecvTime = maybeWrittenPackets3->sentTime + 11ms;
    const auto ackDelay = 2ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end) // still 3
            .setLargestNewlyAckedPacket(maybeWrittenPackets2->end) // 2
            .setNoRtt() // no RTT because largest ACKed (3) acked earlier
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets3->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenFirstLastAckedAtOnceThenSecondAcked) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::acksProcessedEvents);

  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*observerWithNoAcks, observerAttach(transport));
  transport->addObserver(observerWithNoAcks.get());
  EXPECT_CALL(*observerWithAcks1, observerAttach(transport));
  transport->addObserver(observerWithAcks1.get());
  EXPECT_CALL(*observerWithAcks2, observerAttach(transport));
  transport->addObserver(observerWithAcks2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoAcks.get(),
          observerWithAcks1.get(),
          observerWithAcks2.get()));

  // open a stream and write some bytes
  auto streamId = this->getTransport()->createBidirectionalStream().value();
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("hello"), false);
  const auto maybeWrittenPackets1 = this->loopForWrites();

  // write some more bytes into the same stream
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("world"), false);
  const auto maybeWrittenPackets2 = this->loopForWrites();

  // third and final write, this time with EOF
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  const auto maybeWrittenPackets3 = this->loopForWrites();

  // should have sent three packets
  ASSERT_TRUE(maybeWrittenPackets1.has_value());
  ASSERT_TRUE(maybeWrittenPackets2.has_value());
  ASSERT_TRUE(maybeWrittenPackets3.has_value());
  EXPECT_EQ(
      3,
      this->getNumPacketsWritten(
          {maybeWrittenPackets1, maybeWrittenPackets2, maybeWrittenPackets3}));

  // deliver an ACK for packet 1 and 3
  {
    const auto sentTime = maybeWrittenPackets3->sentTime; // 3 is latest sent
    const auto ackRecvTime = sentTime + 20ms;
    const auto ackDelay = 5ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals(
                {maybeWrittenPackets1, maybeWrittenPackets3})
            .setExpectedNumAckedPackets(2)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end)
            .setLargestNewlyAckedPacket(maybeWrittenPackets3->end)
            .setRtt(std::chrono::duration_cast<std::chrono::microseconds>(
                ackRecvTime - sentTime))
            .setRttNoAckDelay(
                std::chrono::duration_cast<std::chrono::microseconds>(
                    ackRecvTime - sentTime - ackDelay))
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets3->start, maybeWrittenPackets3->end},
        {maybeWrittenPackets1->start, maybeWrittenPackets1->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    // base ACK receive time off of (3) as sent packet was reordered
    const auto ackRecvTime = maybeWrittenPackets3->sentTime + 11ms;
    const auto ackDelay = 2ms;
    const auto matcher =
        typename TestFixture::AckEventMatcherBuilder()
            .setExpectedAckedIntervals({maybeWrittenPackets1})
            .setExpectedNumAckedPackets(1)
            .setAckTime(ackRecvTime)
            .setAckDelay(ackDelay)
            .setLargestAckedPacket(maybeWrittenPackets3->end) // still 3
            .setLargestNewlyAckedPacket(maybeWrittenPackets2->end) // 2
            .setNoRtt() // no RTT because largest ACKed (3) acked earlier
            .build();
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));

    const quic::AckBlocks ackBlocks = {
        {maybeWrittenPackets1->start, maybeWrittenPackets3->end}};
    auto buf = quic::test::packetToBuf(
        AckPacketBuilder()
            .setDstConn(&this->getNonConstConn())
            .setPacketNumberSpace(PacketNumberSpace::AppData)
            .setAckPacketNumStore(&this->peerPacketNumStore)
            .setAckBlocks(ackBlocks)
            .setAckDelay(ackDelay)
            .build());
    buf->coalesce();
    this->deliverPacket(std::move(buf), ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(QuicTypedTransportTestForObservers, PacketsReceivedEventsSingle) {
  using Event = quic::SocketObserverInterface::PacketsReceivedEvent;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsReceivedEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver pkt1 with stream data from the remote
  auto pkt1 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(100));
  const auto pkt1RecvTime = TimePoint::clock::now();
  const auto pkt1NumBytes = pkt1->computeChainDataLength();
  {
    const auto matcher = testing::AllOf(
        testing::Field(
            &Event::receiveLoopTime, testing::Ge(TimePoint::clock::now())),
        testing::Field(&Event::numPacketsReceived, testing::Eq(1)),
        testing::Field(&Event::numBytesReceived, testing::Eq(pkt1NumBytes)),
        testing::Field(&Event::receivedPackets, testing::SizeIs(1)),
        testing::Field(
            &Event::receivedPackets,
            testing::ElementsAre(
                typename TestFixture::ReceivedPacketMatcherBuilder()
                    .setExpectedPacketReceiveTime(pkt1RecvTime)
                    .setExpectedPacketNumBytes(pkt1NumBytes)
                    .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPacket(std::move(pkt1), pkt1RecvTime);

  // deliver pkt2 with stream data from the remote
  auto pkt2 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(500));
  const auto pkt2RecvTime = pkt1RecvTime + 50ms;
  const auto pkt2NumBytes = pkt2->computeChainDataLength();
  EXPECT_NE(pkt2NumBytes, pkt1NumBytes);
  {
    const auto matcher = testing::AllOf(
        testing::Field(
            &Event::receiveLoopTime, testing::Ge(TimePoint::clock::now())),
        testing::Field(&Event::numPacketsReceived, testing::Eq(1)),
        testing::Field(&Event::numBytesReceived, testing::Eq(pkt2NumBytes)),
        testing::Field(&Event::receivedPackets, testing::SizeIs(1)),
        testing::Field(
            &Event::receivedPackets,
            testing::ElementsAre(
                typename TestFixture::ReceivedPacketMatcherBuilder()
                    .setExpectedPacketReceiveTime(pkt2RecvTime)
                    .setExpectedPacketNumBytes(pkt2NumBytes)
                    .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPacket(std::move(pkt2), pkt2RecvTime);

  this->destroyTransport();
}

TYPED_TEST(QuicTypedTransportTestForObservers, PacketsReceivedEventsMulti) {
  // skip for client transport tests for now as supporting test foundation
  // does not properly support batch delivery
  if constexpr (std::is_same_v<
                    TypeParam,
                    QuicClientTransportAfterStartTestBase>) {
    return;
  }

  using Event = quic::SocketObserverInterface::PacketsReceivedEvent;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsReceivedEvents);

  auto transport = this->getTransport();
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);

  EXPECT_CALL(*obs1, observerAttach(transport));
  transport->addObserver(obs1.get());
  EXPECT_CALL(*obs2, observerAttach(transport));
  transport->addObserver(obs2.get());
  EXPECT_CALL(*obs3, observerAttach(transport));
  transport->addObserver(obs3.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(obs1.get(), obs2.get(), obs3.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver pkt1 and pkt2 at same time with stream data from the remote
  auto pkt1 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(100));
  auto pkt2 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(500));
  const auto pkt1NumBytes = pkt1->computeChainDataLength();
  const auto pkt2NumBytes = pkt2->computeChainDataLength();
  EXPECT_NE(pkt1NumBytes, pkt2NumBytes);

  std::vector<std::unique_ptr<folly::IOBuf>> pktBatch1;
  pktBatch1.emplace_back(std::move(pkt1));
  pktBatch1.emplace_back(std::move(pkt2));
  const auto pktBatch1RecvTime = TimePoint::clock::now();
  const auto pktBatch1NumBytes = pkt1NumBytes + pkt2NumBytes;
  {
    const auto matcher = testing::AllOf(
        testing::Field(
            &Event::receiveLoopTime, testing::Ge(TimePoint::clock::now())),
        testing::Field(&Event::numPacketsReceived, testing::Eq(2)),
        testing::Field(
            &Event::numBytesReceived, testing::Eq(pktBatch1NumBytes)),
        testing::Field(&Event::receivedPackets, testing::SizeIs(2)),
        testing::Field(
            &Event::receivedPackets,
            testing::ElementsAre(
                // pkt1
                typename TestFixture::ReceivedPacketMatcherBuilder()
                    .setExpectedPacketReceiveTime(pktBatch1RecvTime)
                    .setExpectedPacketNumBytes(pkt1NumBytes)
                    .build(),
                // pkt2
                typename TestFixture::ReceivedPacketMatcherBuilder()
                    .setExpectedPacketReceiveTime(pktBatch1RecvTime)
                    .setExpectedPacketNumBytes(pkt2NumBytes)
                    .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPackets(std::move(pktBatch1), pktBatch1RecvTime);

  // deliver pkt3 and pkt4 at same time with stream data from the remote
  auto pkt3 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(200));
  auto pkt4 =
      this->buildPeerPacketWithStreamData(streamId, buildRandomInputData(800));
  const auto pkt3NumBytes = pkt3->computeChainDataLength();
  const auto pkt4NumBytes = pkt4->computeChainDataLength();
  EXPECT_NE(pkt3NumBytes, pkt4NumBytes);

  std::vector<std::unique_ptr<folly::IOBuf>> pktBatch2;
  pktBatch2.emplace_back(std::move(pkt3));
  pktBatch2.emplace_back(std::move(pkt4));
  const auto pktBatch2RecvTime = pktBatch1RecvTime + 50ms;
  const auto pktBatch2NumBytes = pkt3NumBytes + pkt4NumBytes;
  EXPECT_NE(pktBatch1NumBytes, pktBatch2NumBytes);
  {
    const auto matcher = testing::AllOf(
        testing::Field(
            &Event::receiveLoopTime, testing::Ge(TimePoint::clock::now())),
        testing::Field(&Event::numPacketsReceived, testing::Eq(2)),
        testing::Field(
            &Event::numBytesReceived, testing::Eq(pktBatch2NumBytes)),
        testing::Field(&Event::receivedPackets, testing::SizeIs(2)),
        testing::Field(
            &Event::receivedPackets,
            testing::ElementsAre(
                // pkt1
                typename TestFixture::ReceivedPacketMatcherBuilder()
                    .setExpectedPacketReceiveTime(pktBatch2RecvTime)
                    .setExpectedPacketNumBytes(pkt3NumBytes)
                    .build(),
                // pkt2
                typename TestFixture::ReceivedPacketMatcherBuilder()
                    .setExpectedPacketReceiveTime(pktBatch2RecvTime)
                    .setExpectedPacketNumBytes(pkt4NumBytes)
                    .build())));

    EXPECT_CALL(*obs1, packetsReceived(_, _)).Times(0);
    EXPECT_CALL(*obs2, packetsReceived(transport, matcher));
    EXPECT_CALL(*obs3, packetsReceived(transport, matcher));
  }
  this->deliverPackets(std::move(pktBatch2), pktBatch2RecvTime);

  this->destroyTransport();
}

} // namespace quic::test
