/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <chrono>

#include <quic/api/test/Mocks.h>
#include <quic/api/test/QuicTypedTransportTestUtil.h>
#include <quic/codec/Types.h>
#include <quic/fizz/client/test/QuicClientTransportTestUtil.h>
#include <quic/server/test/QuicServerTransportTestUtil.h>
#include <quic/state/AckEvent.h>
#include <quic/state/OutstandingPacket.h>

using namespace folly;
using namespace folly::test;
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

  const std::pair<QuicErrorCode, std::string> defaultError = std::make_pair(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *observer,
      close(
          transport,
          folly::Optional<std::pair<QuicErrorCode, std::string>>(
              defaultError)));
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

  const auto testError = std::make_pair(
      QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
      std::string("testError"));
  EXPECT_CALL(
      *observer,
      close(
          transport,
          folly::Optional<std::pair<QuicErrorCode, std::string>>(testError)));
  transport->close(testError);
  Mock::VerifyAndClearExpectations(observer.get());
  InSequence s;
  EXPECT_CALL(*observer, destroy(transport));
  this->destroyTransport();
  Mock::VerifyAndClearExpectations(observer.get());
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
