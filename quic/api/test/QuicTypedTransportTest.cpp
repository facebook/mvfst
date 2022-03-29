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
  this->getNonConstConn().outstandings.packets.clear();
  this->getNonConstConn().outstandings.packetCount = {};
  this->getNonConstConn().outstandings.clonedPacketCount = {};

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
  this->getNonConstConn().outstandings.packets.clear();
  this->getNonConstConn().outstandings.packetCount = {};
  this->getNonConstConn().outstandings.clonedPacketCount = {};

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
  this->getNonConstConn().outstandings.packets.clear();
  this->getNonConstConn().outstandings.packetCount = {};
  this->getNonConstConn().outstandings.clonedPacketCount = {};

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
  this->getNonConstConn().outstandings.packets.clear();
  this->getNonConstConn().outstandings.packetCount = {};
  this->getNonConstConn().outstandings.clonedPacketCount = {};

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
  this->getNonConstConn().outstandings.packets.clear();
  this->getNonConstConn().outstandings.packetCount = {};
  this->getNonConstConn().outstandings.clonedPacketCount = {};

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
  this->getNonConstConn().outstandings.packets.clear();
  this->getNonConstConn().outstandings.packetCount = {};
  this->getNonConstConn().outstandings.clonedPacketCount = {};

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
  this->getNonConstConn().outstandings.packets.clear();
  this->getNonConstConn().outstandings.packetCount = {};
  this->getNonConstConn().outstandings.clonedPacketCount = {};

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

  auto getAcksProcessedEventMatcher(
      const std::vector<typename QuicTypedTransportTest<
          T>::NewOutstandingPacketInterval>& expectedAckedIntervals,
      const uint64_t expectedNumAckedPackets,
      const quic::TimePoint ackTime,
      const quic::TimePoint adjustedAckTime) {
    CHECK_LT(0, expectedAckedIntervals.size());

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
        for (const auto& processedInterval : processedExpectedAckedIntervals) {
          CHECK(
              processedInterval.end < interval.start ||
              processedInterval.start < interval.end);
        }

        processedExpectedAckedIntervals.push_back(interval);
      }
      CHECK_EQ(expectedNumAckedPacketsFromIntervals, expectedNumAckedPackets);
    }

    // get last packet ACKed
    const quic::PacketNum largestAckedPacketNum = [&expectedAckedIntervals]() {
      CHECK_LT(0, expectedAckedIntervals.size());
      quic::PacketNum packetNum = 0;
      for (const auto& interval : expectedAckedIntervals) {
        CHECK_LE(interval.start, interval.end);
        CHECK_LE(0, interval.end);
        packetNum = std::max(packetNum, interval.end);
      }

      return packetNum;
    }();

    // only check ack timing for server; we don't support passing for client
    if constexpr (std::is_same_v<T, QuicClientTransportAfterStartTestBase>) {
      return testing::Property(
          &quic::Observer::AcksProcessedEvent::getAckEvents,
          testing::ElementsAre(testing::AllOf(
              testing::Field(
                  &quic::AckEvent::largestAckedPacket,
                  testing::Eq(largestAckedPacketNum)),
              testing::Field(
                  &quic::AckEvent::ackedPackets,
                  testing::SizeIs(expectedNumAckedPackets)))));
    } else if constexpr (std::is_same_v<T, QuicServerTransportTestBase>) {
      return testing::Property(
          &quic::Observer::AcksProcessedEvent::getAckEvents,
          testing::ElementsAre(testing::AllOf(
              testing::Field(
                  &quic::AckEvent::largestAckedPacket,
                  testing::Eq(largestAckedPacketNum)),
              testing::Field(
                  &quic::AckEvent::ackedPackets,
                  testing::SizeIs(expectedNumAckedPackets)),
              testing::Field(&quic::AckEvent::ackTime, testing::Eq(ackTime)),
              testing::Field(
                  &quic::AckEvent::adjustedAckTime,
                  testing::Eq(adjustedAckTime)))));
    } else {
      FAIL(); // unhandled typed test
    }
  }

  auto getAcksProcessedEventMatcherOpt(
      const std::vector<folly::Optional<typename QuicTypedTransportTest<
          T>::NewOutstandingPacketInterval>>& expectedAckedIntervalsOptionals,
      const uint64_t expectedNumAckedPackets,
      const quic::TimePoint ackTime,
      const quic::TimePoint adjustedAckTime) {
    std::vector<
        typename QuicTypedTransportTest<T>::NewOutstandingPacketInterval>
        expectedAckedIntervals;
    for (const auto& maybeInterval : expectedAckedIntervalsOptionals) {
      CHECK(maybeInterval.has_value());
      expectedAckedIntervals.push_back(maybeInterval.value());
    }
    return getAcksProcessedEventMatcher(
        expectedAckedIntervals,
        expectedNumAckedPackets,
        ackTime,
        adjustedAckTime);
  }

  auto getStreamEventMatcherOpt(
      const StreamId streamId,
      const StreamInitiator streamInitiator,
      const StreamDirectionality streamDirectionality) {
    return testing::AllOf(
        testing::Field(
            &quic::Observer::StreamEvent::streamId, testing::Eq(streamId)),
        testing::Field(
            &quic::Observer::StreamEvent::streamInitiator,
            testing::Eq(streamInitiator)),
        testing::Field(
            &quic::Observer::StreamEvent::streamDirectionality,
            testing::Eq(streamDirectionality)));
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportTestForObservers,
    ::TransportTypes,
    ::TransportTypeNames);

TYPED_TEST(QuicTypedTransportTestForObservers, Attach) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

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
    CloseNoErrorThenDestroyTransport) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

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
    CloseWithErrorThenDestroyTransport) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

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
  MockObserver::Config configWithStreamEventsEnabled;
  configWithStreamEventsEnabled.streamEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoStreamEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithStreamEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);
  auto observerWithStreamEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);

  EXPECT_CALL(*observerWithNoStreamEvents, observerAttach(transport));
  transport->addObserver(observerWithNoStreamEvents.get());
  EXPECT_CALL(*observerWithStreamEvents1, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents1.get());
  EXPECT_CALL(*observerWithStreamEvents2, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoStreamEvents.get(),
          observerWithStreamEvents1.get(),
          observerWithStreamEvents2.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*observerWithNoStreamEvents, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamOpened(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamOpened(transport, matcher));
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
    EXPECT_CALL(*observerWithNoStreamEvents, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamClosed(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye2")));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsLocalOpenedStreamImmediateEofLocal) {
  MockObserver::Config configWithStreamEventsEnabled;
  configWithStreamEventsEnabled.streamEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoStreamEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithStreamEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);
  auto observerWithStreamEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);

  EXPECT_CALL(*observerWithNoStreamEvents, observerAttach(transport));
  transport->addObserver(observerWithNoStreamEvents.get());
  EXPECT_CALL(*observerWithStreamEvents1, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents1.get());
  EXPECT_CALL(*observerWithStreamEvents2, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoStreamEvents.get(),
          observerWithStreamEvents1.get(),
          observerWithStreamEvents2.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*observerWithNoStreamEvents, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamOpened(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamOpened(transport, matcher));
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
    EXPECT_CALL(*observerWithNoStreamEvents, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamClosed(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("goodbye")));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsLocalOpenedStreamImmediateEofLocalRemote) {
  MockObserver::Config configWithStreamEventsEnabled;
  configWithStreamEventsEnabled.streamEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoStreamEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithStreamEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);
  auto observerWithStreamEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);

  EXPECT_CALL(*observerWithNoStreamEvents, observerAttach(transport));
  transport->addObserver(observerWithNoStreamEvents.get());
  EXPECT_CALL(*observerWithStreamEvents1, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents1.get());
  EXPECT_CALL(*observerWithStreamEvents2, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoStreamEvents.get(),
          observerWithStreamEvents1.get(),
          observerWithStreamEvents2.get()));

  // create a new stream locally
  const auto expectedStreamId = this->getNextLocalBidirectionalStreamId();
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        expectedStreamId,
        StreamInitiator::Local,
        StreamDirectionality::Bidirectional);
    EXPECT_CALL(*observerWithNoStreamEvents, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamOpened(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamOpened(transport, matcher));
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
    EXPECT_CALL(*observerWithNoStreamEvents, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamClosed(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamClosed(transport, matcher));
  }
  this->deliverPacket(this->buildPeerPacketWithStreamDataAndEof(
      streamId, IOBuf::copyBuffer("hello2")));

  this->destroyTransport();
}

TYPED_TEST(QuicTypedTransportTestForObservers, StreamEventsPeerOpenedStream) {
  MockObserver::Config configWithStreamEventsEnabled;
  configWithStreamEventsEnabled.streamEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoStreamEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithStreamEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);
  auto observerWithStreamEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);

  EXPECT_CALL(*observerWithNoStreamEvents, observerAttach(transport));
  transport->addObserver(observerWithNoStreamEvents.get());
  EXPECT_CALL(*observerWithStreamEvents1, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents1.get());
  EXPECT_CALL(*observerWithStreamEvents2, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoStreamEvents.get(),
          observerWithStreamEvents1.get(),
          observerWithStreamEvents2.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*observerWithNoStreamEvents, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamOpened(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamOpened(transport, matcher));
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
    EXPECT_CALL(*observerWithNoStreamEvents, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamClosed(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsPeerOpenedStreamImmediateEofRemote) {
  MockObserver::Config configWithStreamEventsEnabled;
  configWithStreamEventsEnabled.streamEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoStreamEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithStreamEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);
  auto observerWithStreamEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);

  EXPECT_CALL(*observerWithNoStreamEvents, observerAttach(transport));
  transport->addObserver(observerWithNoStreamEvents.get());
  EXPECT_CALL(*observerWithStreamEvents1, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents1.get());
  EXPECT_CALL(*observerWithStreamEvents2, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoStreamEvents.get(),
          observerWithStreamEvents1.get(),
          observerWithStreamEvents2.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data + EOF from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*observerWithNoStreamEvents, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamOpened(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamOpened(transport, matcher));
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
    EXPECT_CALL(*observerWithNoStreamEvents, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamClosed(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsPeerOpenedStreamImmediateEofLocalRemote) {
  MockObserver::Config configWithStreamEventsEnabled;
  configWithStreamEventsEnabled.streamEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoStreamEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithStreamEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);
  auto observerWithStreamEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);

  EXPECT_CALL(*observerWithNoStreamEvents, observerAttach(transport));
  transport->addObserver(observerWithNoStreamEvents.get());
  EXPECT_CALL(*observerWithStreamEvents1, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents1.get());
  EXPECT_CALL(*observerWithStreamEvents2, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoStreamEvents.get(),
          observerWithStreamEvents1.get(),
          observerWithStreamEvents2.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data + EOF from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*observerWithNoStreamEvents, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamOpened(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamOpened(transport, matcher));
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
    EXPECT_CALL(*observerWithNoStreamEvents, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamClosed(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsPeerOpenedStreamStopSendingPlusRstTriggersRst) {
  MockObserver::Config configWithStreamEventsEnabled;
  configWithStreamEventsEnabled.streamEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoStreamEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithStreamEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);
  auto observerWithStreamEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);

  EXPECT_CALL(*observerWithNoStreamEvents, observerAttach(transport));
  transport->addObserver(observerWithNoStreamEvents.get());
  EXPECT_CALL(*observerWithStreamEvents1, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents1.get());
  EXPECT_CALL(*observerWithStreamEvents2, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoStreamEvents.get(),
          observerWithStreamEvents1.get(),
          observerWithStreamEvents2.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*observerWithNoStreamEvents, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamOpened(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamOpened(transport, matcher));
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
    EXPECT_CALL(*observerWithNoStreamEvents, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamClosed(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsPeerOpenedStreamStopSendingPlusRstTriggersRstBytesInFlight) {
  MockObserver::Config configWithStreamEventsEnabled;
  configWithStreamEventsEnabled.streamEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoStreamEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithStreamEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);
  auto observerWithStreamEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);

  EXPECT_CALL(*observerWithNoStreamEvents, observerAttach(transport));
  transport->addObserver(observerWithNoStreamEvents.get());
  EXPECT_CALL(*observerWithStreamEvents1, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents1.get());
  EXPECT_CALL(*observerWithStreamEvents2, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoStreamEvents.get(),
          observerWithStreamEvents1.get(),
          observerWithStreamEvents2.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*observerWithNoStreamEvents, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamOpened(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamOpened(transport, matcher));
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
    EXPECT_CALL(*observerWithNoStreamEvents, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamClosed(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamClosed(transport, matcher));
  }
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPacket(maybeRstPacketNum.value()));

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    StreamEventsPeerOpenedStreamImmediateEorStopSendingTriggersRstBytesInFlight) {
  MockObserver::Config configWithStreamEventsEnabled;
  configWithStreamEventsEnabled.streamEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoStreamEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithStreamEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);
  auto observerWithStreamEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithStreamEventsEnabled);

  EXPECT_CALL(*observerWithNoStreamEvents, observerAttach(transport));
  transport->addObserver(observerWithNoStreamEvents.get());
  EXPECT_CALL(*observerWithStreamEvents1, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents1.get());
  EXPECT_CALL(*observerWithStreamEvents2, observerAttach(transport));
  transport->addObserver(observerWithStreamEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoStreamEvents.get(),
          observerWithStreamEvents1.get(),
          observerWithStreamEvents2.get()));

  // get stream ID for peer
  const auto streamId = this->getNextPeerBidirectionalStreamId();

  // deliver a packet with stream data from the remote
  {
    const auto matcher = this->getStreamEventMatcherOpt(
        streamId, StreamInitiator::Remote, StreamDirectionality::Bidirectional);
    EXPECT_CALL(*observerWithNoStreamEvents, streamOpened(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamOpened(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamOpened(transport, matcher));
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
    EXPECT_CALL(*observerWithNoStreamEvents, streamClosed(_, _)).Times(0);
    EXPECT_CALL(*observerWithStreamEvents1, streamClosed(transport, matcher));
    EXPECT_CALL(*observerWithStreamEvents2, streamClosed(transport, matcher));
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

  MockObserver::Config configWithEventsEnabled;
  configWithEventsEnabled.appRateLimitedEvents = true;
  configWithEventsEnabled.packetsWrittenEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithEventsEnabled);
  auto observerWithEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithEventsEnabled);

  EXPECT_CALL(*observerWithNoEvents, observerAttach(transport));
  transport->addObserver(observerWithNoEvents.get());
  EXPECT_CALL(*observerWithEvents1, observerAttach(transport));
  transport->addObserver(observerWithEvents1.get());
  EXPECT_CALL(*observerWithEvents2, observerAttach(transport));
  transport->addObserver(observerWithEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoEvents.get(),
          observerWithEvents1.get(),
          observerWithEvents2.get()));

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
            &Observer::WriteEvent::getOutstandingPackets, testing::IsEmpty()),
        testing::Field(
            &Observer::WriteEvent::writeCount, testing::Eq(writeCount)),
        testing::Field(
            &Observer::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &Observer::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*observerWithNoEvents, startWritingFromAppLimited(_, _))
        .Times(0);
    EXPECT_CALL(
        *observerWithEvents1,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *observerWithEvents2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &Observer::WriteEvent::getOutstandingPackets, testing::SizeIs(1)),
        testing::Field(
            &Observer::WriteEvent::writeCount, testing::Eq(writeCount)),
        testing::Field(
            &Observer::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &Observer::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(cwndInBytes - strLength))),
        testing::Field(
            &Observer::PacketsWrittenEvent::numPacketsWritten, testing::Eq(1)),
        testing::Field(
            &Observer::PacketsWrittenEvent::numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce()
            &Observer::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(strLength)));
    EXPECT_CALL(*observerWithNoEvents, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(
        *observerWithEvents1, packetsWritten(transport, packetsWrittenMatcher))
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
    EXPECT_CALL(
        *observerWithEvents2, packetsWritten(transport, packetsWrittenMatcher))
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
            &Observer::WriteEvent::getOutstandingPackets, testing::SizeIs(1)),
        testing::Field(
            &Observer::WriteEvent::writeCount, testing::Eq(writeCount)),
        testing::Field(
            &Observer::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &Observer::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(cwndInBytes - strLength))));

    EXPECT_CALL(*observerWithNoEvents, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(
        *observerWithEvents1, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
    EXPECT_CALL(
        *observerWithEvents2, appRateLimited(transport, appRateLimitedMatcher))
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

  MockObserver::Config configWithEventsEnabled;
  configWithEventsEnabled.appRateLimitedEvents = true;
  configWithEventsEnabled.packetsWrittenEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithEventsEnabled);
  auto observerWithEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithEventsEnabled);

  EXPECT_CALL(*observerWithNoEvents, observerAttach(transport));
  transport->addObserver(observerWithNoEvents.get());
  EXPECT_CALL(*observerWithEvents1, observerAttach(transport));
  transport->addObserver(observerWithEvents1.get());
  EXPECT_CALL(*observerWithEvents2, observerAttach(transport));
  transport->addObserver(observerWithEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoEvents.get(),
          observerWithEvents1.get(),
          observerWithEvents2.get()));

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
            &Observer::WriteEvent::getOutstandingPackets, testing::IsEmpty()),
        testing::Field(
            &Observer::WriteEvent::writeCount, testing::Eq(writeCount)),
        testing::Field(
            &Observer::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &Observer::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*observerWithNoEvents, startWritingFromAppLimited(_, _))
        .Times(0);
    EXPECT_CALL(
        *observerWithEvents1,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *observerWithEvents2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &Observer::WriteEvent::getOutstandingPackets, testing::SizeIs(1)),
        testing::Field(
            &Observer::WriteEvent::writeCount, testing::Eq(writeCount)),
        testing::Field(
            &Observer::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &Observer::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(0))),
        testing::Field(
            &Observer::PacketsWrittenEvent::numPacketsWritten, testing::Eq(1)),
        testing::Field(
            &Observer::PacketsWrittenEvent::numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce(), expect overshoot CWND
            &Observer::PacketsWrittenEvent::numBytesWritten,
            testing::AllOf(testing::Gt(bufLength), testing::Gt(cwndInBytes))));
    EXPECT_CALL(*observerWithNoEvents, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(
        *observerWithEvents1, packetsWritten(transport, packetsWrittenMatcher))
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
    EXPECT_CALL(
        *observerWithEvents2, packetsWritten(transport, packetsWrittenMatcher))
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

  MockObserver::Config configWithEventsEnabled;
  configWithEventsEnabled.appRateLimitedEvents = true;
  configWithEventsEnabled.packetsWrittenEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithEventsEnabled);
  auto observerWithEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithEventsEnabled);

  EXPECT_CALL(*observerWithNoEvents, observerAttach(transport));
  transport->addObserver(observerWithNoEvents.get());
  EXPECT_CALL(*observerWithEvents1, observerAttach(transport));
  transport->addObserver(observerWithEvents1.get());
  EXPECT_CALL(*observerWithEvents2, observerAttach(transport));
  transport->addObserver(observerWithEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoEvents.get(),
          observerWithEvents1.get(),
          observerWithEvents2.get()));

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
            &Observer::WriteEvent::getOutstandingPackets, testing::IsEmpty()),
        testing::Field(
            &Observer::WriteEvent::writeCount, testing::Eq(writeCount)),
        testing::Field(
            &Observer::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &Observer::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*observerWithNoEvents, startWritingFromAppLimited(_, _))
        .Times(0);
    EXPECT_CALL(
        *observerWithEvents1,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));
    EXPECT_CALL(
        *observerWithEvents2,
        startWritingFromAppLimited(
            transport, startWritingFromAppLimitedMatcher));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &Observer::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &Observer::WriteEvent::writeCount, testing::Eq(writeCount)),
        testing::Field(
            &Observer::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &Observer::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(0))), // CWND exhausted
        testing::Field(
            &Observer::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field(
            &Observer::PacketsWrittenEvent::numAckElicitingPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field( // precise check in WillOnce()
            &Observer::PacketsWrittenEvent::numBytesWritten,
            testing::Ge(cwndInBytes))); // full CWND written
    EXPECT_CALL(*observerWithNoEvents, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(
        *observerWithEvents1, packetsWritten(transport, packetsWrittenMatcher))
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
    EXPECT_CALL(
        *observerWithEvents2, packetsWritten(transport, packetsWrittenMatcher))
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
            &Observer::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &Observer::WriteEvent::writeCount, testing::Eq(writeCount)),
        testing::Field(
            &Observer::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &Observer::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &Observer::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field(
            &Observer::PacketsWrittenEvent::numAckElicitingPacketsWritten,
            testing::Eq(packetsExpectedWritten)),
        testing::Field( // precise check in WillOnce()
            &Observer::PacketsWrittenEvent::numBytesWritten,
            testing::Lt(cwndInBytes)));
    EXPECT_CALL(*observerWithNoEvents, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(
        *observerWithEvents1, packetsWritten(transport, packetsWrittenMatcher))
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
    EXPECT_CALL(
        *observerWithEvents2, packetsWritten(transport, packetsWrittenMatcher))
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
            &Observer::WriteEvent::getOutstandingPackets,
            testing::SizeIs(packetsExpectedWritten)),
        testing::Field(
            &Observer::WriteEvent::writeCount, testing::Eq(writeCount)),
        testing::Field(
            &Observer::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check in WillOnce()
            &Observer::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(cwndInBytes))));
    EXPECT_CALL(*observerWithNoEvents, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(
        *observerWithEvents1, appRateLimited(transport, appRateLimitedMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(
              folly::Optional<uint64_t>(std::max(
                  int64_t(cwndInBytes) - int64_t(bytesWritten), int64_t(0))),
              event.maybeWritableBytes);
        });
    EXPECT_CALL(
        *observerWithEvents2, appRateLimited(transport, appRateLimitedMatcher))
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

  MockObserver::Config configWithEventsEnabled;
  configWithEventsEnabled.appRateLimitedEvents = true;
  configWithEventsEnabled.packetsWrittenEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoEvents = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithEvents1 =
      std::make_unique<NiceMock<MockObserver>>(configWithEventsEnabled);
  auto observerWithEvents2 =
      std::make_unique<NiceMock<MockObserver>>(configWithEventsEnabled);

  EXPECT_CALL(*observerWithNoEvents, observerAttach(transport));
  transport->addObserver(observerWithNoEvents.get());
  EXPECT_CALL(*observerWithEvents1, observerAttach(transport));
  transport->addObserver(observerWithEvents1.get());
  EXPECT_CALL(*observerWithEvents2, observerAttach(transport));
  transport->addObserver(observerWithEvents2.get());
  EXPECT_THAT(
      transport->getObservers(),
      UnorderedElementsAre(
          observerWithNoEvents.get(),
          observerWithEvents1.get(),
          observerWithEvents2.get()));

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
    EXPECT_CALL(*observerWithNoEvents, startWritingFromAppLimited(_, _))
        .Times(0);
    EXPECT_CALL(*observerWithEvents1, startWritingFromAppLimited(_, _))
        .Times(0);
    EXPECT_CALL(*observerWithEvents2, startWritingFromAppLimited(_, _))
        .Times(0);

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &Observer::WriteEvent::getOutstandingPackets, testing::SizeIs(1)),
        testing::Field(
            &Observer::WriteEvent::writeCount, testing::Eq(writeCount)),
        testing::Field(
            &Observer::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(folly::none))),
        testing::Field(
            &Observer::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(folly::none))),
        testing::Field(
            &Observer::PacketsWrittenEvent::numPacketsWritten, testing::Eq(1)),
        testing::Field(
            &Observer::PacketsWrittenEvent::numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field( // precise check in WillOnce()
            &Observer::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(strLength)));
    EXPECT_CALL(*observerWithNoEvents, packetsWritten(_, _)).Times(0);
    EXPECT_CALL(
        *observerWithEvents1, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });
    EXPECT_CALL(
        *observerWithEvents2, packetsWritten(transport, packetsWrittenMatcher))
        .WillOnce([oldTInfo = this->getTransport()->getTransportInfo()](
                      const auto& socket, const auto& event) {
          const auto bytesWritten =
              socket->getTransportInfo().bytesSent - oldTInfo.bytesSent;
          EXPECT_EQ(bytesWritten, event.numBytesWritten);
        });

    // no congestion controller == no appRateLimited events
    EXPECT_CALL(*observerWithNoEvents, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*observerWithEvents1, appRateLimited(_, _)).Times(0);
    EXPECT_CALL(*observerWithEvents2, appRateLimited(_, _)).Times(0);
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
    AckEventsOutstandingPacketSentThenAcked) {
  MockObserver::Config configWithAcksEnabled;
  configWithAcksEnabled.acksProcessedEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);

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
  auto ackRecvTime =
      std::chrono::steady_clock::time_point() + std::chrono::minutes(5);
  const auto matcher = this->getAcksProcessedEventMatcherOpt(
      {maybeWrittenPackets}, 1, ackRecvTime, ackRecvTime);
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(firstPacketNum, lastPacketNum),
      ackRecvTime);

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenAllAckedAtOnce) {
  MockObserver::Config configWithAcksEnabled;
  configWithAcksEnabled.acksProcessedEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);

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
  auto ackRecvTime =
      std::chrono::steady_clock::time_point() + std::chrono::minutes(5);
  const auto matcher = this->getAcksProcessedEventMatcherOpt(
      {maybeWrittenPackets1, maybeWrittenPackets2, maybeWrittenPackets3},
      3,
      ackRecvTime,
      ackRecvTime);
  EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
  EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
  EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
  this->deliverPacket(
      this->buildAckPacketForSentAppDataPackets(firstPacketNum, lastPacketNum),
      ackRecvTime);

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsThreeOutstandingPacketsSentAndAckedSequentially) {
  MockObserver::Config configWithAcksEnabled;
  configWithAcksEnabled.acksProcessedEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);

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
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(5);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {maybeWrittenPackets}, 1, ackRecvTime, ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWrittenPackets->start, maybeWrittenPackets->end),
        ackRecvTime);
  }

  // write some more bytes into the same stream, send packet, deliver ACK
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("world"), false);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(6);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {maybeWrittenPackets}, 1, ackRecvTime, ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWrittenPackets->start, maybeWrittenPackets->end),
        ackRecvTime);
  }

  // third and final write, this time with EOF, send packet, deliver ACK
  this->getTransport()->writeChain(streamId, IOBuf::copyBuffer("!"), true);
  {
    const auto maybeWrittenPackets = this->loopForWrites();
    ASSERT_TRUE(maybeWrittenPackets.has_value());
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(7);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {*maybeWrittenPackets}, 1, ackRecvTime, ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWrittenPackets->start, maybeWrittenPackets->end),
        ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenAckedSequentially) {
  MockObserver::Config configWithAcksEnabled;
  configWithAcksEnabled.acksProcessedEvents = true;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);

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
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(5);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {maybeWrittenPackets1}, 1, ackRecvTime, ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWrittenPackets1->start, maybeWrittenPackets1->end),
        ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(6);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {maybeWrittenPackets2}, 1, ackRecvTime, ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWrittenPackets2->start, maybeWrittenPackets2->end),
        ackRecvTime);
  }

  // deliver an ACK for packet 3
  {
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(6);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {maybeWrittenPackets3}, 1, ackRecvTime, ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWrittenPackets3->start, maybeWrittenPackets3->end),
        ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenFirstLastAckedSequentiallyThenSecondAcked) {
  MockObserver::Config configWithAcksEnabled;
  configWithAcksEnabled.acksProcessedEvents = true;

  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);

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
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(5);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {maybeWrittenPackets1}, 1, ackRecvTime, ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets1),
        ackRecvTime);
  }

  // deliver an ACK for packet 3
  {
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(6);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {maybeWrittenPackets3}, 1, ackRecvTime, ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets3),
        ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(6);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {maybeWrittenPackets2}, 1, ackRecvTime, ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(maybeWrittenPackets2),
        ackRecvTime);
  }

  this->destroyTransport();
}

TYPED_TEST(
    QuicTypedTransportTestForObservers,
    AckEventsThreeOutstandingPacketsSentThenFirstLastAckedAtOnceThenSecondAcked) {
  MockObserver::Config configWithAcksEnabled;
  configWithAcksEnabled.acksProcessedEvents = true;

  // prevent packets from being marked as lost
  this->getNonConstConn().lossState.reorderingThreshold = 10;
  this->getNonConstConn().transportSettings.timeReorderingThreshDividend =
      1000000;
  this->getNonConstConn().transportSettings.timeReorderingThreshDivisor = 1;

  auto transport = this->getTransport();
  auto observerWithNoAcks = std::make_unique<NiceMock<MockObserver>>();
  auto observerWithAcks1 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);
  auto observerWithAcks2 =
      std::make_unique<NiceMock<MockObserver>>(configWithAcksEnabled);

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

  // deliver an ACK for packet 1 and 3
  {
    quic::AckBlocks ackBlocks;
    ackBlocks.insert(maybeWrittenPackets1->start, maybeWrittenPackets1->end);
    ackBlocks.insert(maybeWrittenPackets3->start, maybeWrittenPackets3->end);
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(5);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {maybeWrittenPackets1, maybeWrittenPackets3},
        2,
        ackRecvTime,
        ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(ackBlocks), ackRecvTime);
  }

  // deliver an ACK for packet 2
  {
    auto ackRecvTime =
        std::chrono::steady_clock::time_point() + std::chrono::minutes(6);
    const auto matcher = this->getAcksProcessedEventMatcherOpt(
        {maybeWrittenPackets2}, 1, ackRecvTime, ackRecvTime);
    EXPECT_CALL(*observerWithNoAcks, acksProcessed(_, _)).Times(0);
    EXPECT_CALL(*observerWithAcks1, acksProcessed(transport, matcher));
    EXPECT_CALL(*observerWithAcks2, acksProcessed(transport, matcher));
    this->deliverPacket(
        this->buildAckPacketForSentAppDataPackets(
            maybeWrittenPackets2->start, maybeWrittenPackets2->end),
        ackRecvTime);
  }

  this->destroyTransport();
}

} // namespace quic::test
