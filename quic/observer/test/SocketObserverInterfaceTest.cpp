/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <quic/common/test/TestPacketBuilders.h>
#include <quic/common/test/TestUtils.h>
#include <quic/observer/SocketObserverInterface.h>
#include <chrono>

namespace quic::test {
class SocketObserverInterfaceTest : public ::testing::Test {
 public:
  /**
   * Fields in OutstandingPacket that are relevant to this test.
   */
  struct OutstandingPacketRelevantFields {
    folly::Optional<PacketNumberSpace> maybePnSpace;
    folly::Optional<PacketNum> maybePacketNum;
    folly::Optional<uint64_t> maybeWriteCount;
    folly::Optional<uint64_t> maybeNumPacketsWritten;
    folly::Optional<uint64_t> maybeNumAckElicitingPacketsWritten;
  };

  static OutstandingPacket buildOutstandingPacket(
      const OutstandingPacketRelevantFields& relevantFields) {
    // unwrap optionals
    const auto& pnSpace = relevantFields.maybePnSpace.value();
    const auto& packetNum = relevantFields.maybePacketNum.value();
    const auto& writeCount = relevantFields.maybeWriteCount.value();
    const auto& numPacketsWritten =
        relevantFields.maybeNumPacketsWritten.value();
    const auto& numAckElicitingPacketsWritten =
        relevantFields.maybeNumAckElicitingPacketsWritten.value();

    // setup relevant LossState fields
    //
    // LossState is taken as a reference but does not need to remain alive
    // after OutstandingPacket generation; relevant fields are stored within
    // the OutstandingPacket's metadata
    LossState lossState;
    lossState.totalPacketsSent = numPacketsWritten;
    lossState.totalAckElicitingPacketsSent = numAckElicitingPacketsWritten;

    auto regularPacket = createNewPacket(packetNum, pnSpace);
    OutstandingPacket::Metadata::DetailsPerStream detailsPerStream;

    return OutstandingPacketBuilder()
        .setPacket(regularPacket)
        .setTime(TimePoint())
        .setEncodedSize(0)
        .setEncodedBodySize(0)
        .setIsHandshake(false)
        .setIsD6DProbe(false)
        .setTotalBytesSent(0)
        .setTotalBodyBytesSent(0)
        .setInflightBytes(0)
        .setPacketsInflight(0)
        .setLossState(lossState)
        .setWriteCount(writeCount)
        .setDetailsPerStream(detailsPerStream)
        .setTotalAppLimitedTimeUsecs(0us)
        .build();
  }
};

TEST_F(SocketObserverInterfaceTest, InvokeForEachNewOutstandingPacketOrdered) {
  struct InvokedOutstandingPacketFields {
    PacketNumberSpace pnSpace{PacketNumberSpace::Initial};
    PacketNum packetNum{0};
  };

  // no new packets, no old packets
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;

    // build event with writeCount = 10
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(10)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(0)
                           .setNumAckElicitingPacketsWritten(0)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(outstandingPacketsDuringInvoke, ::testing::IsEmpty());
  }

  // no new packets, has old packets
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 13;
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 16;
      fields.maybeNumAckElicitingPacketsWritten = 16;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 10
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(10)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(0)
                           .setNumAckElicitingPacketsWritten(0)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(outstandingPacketsDuringInvoke, ::testing::IsEmpty());
  }

  // no new ack eliciting packets, no old packets
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;

    // build event with writeCount = 10
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(10)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(1)
                           .setNumAckElicitingPacketsWritten(0)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(outstandingPacketsDuringInvoke, ::testing::IsEmpty());
  }

  // no new ack eliciting packets, has old packets
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 13;
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 16;
      fields.maybeNumAckElicitingPacketsWritten = 16;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 10
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(10)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(1)
                           .setNumAckElicitingPacketsWritten(0)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(outstandingPacketsDuringInvoke, ::testing::IsEmpty());
  }

  // first packet sent for initial, handshake, app data, single write, ordered
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Initial;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 1;
      fields.maybeNumAckElicitingPacketsWritten = 1;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Handshake;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 2;
      fields.maybeNumAckElicitingPacketsWritten = 2;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 3;
      fields.maybeNumAckElicitingPacketsWritten = 3;
      return buildOutstandingPacket(fields);
    }());

    // build event
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(1)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(3)
                           .setNumAckElicitingPacketsWritten(3)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::Initial),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 1)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::Handshake),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 1)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 1))));
  }

  // first packet sent for initial, handshake, app data, single write, reversed
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 3;
      fields.maybeNumAckElicitingPacketsWritten = 3;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Handshake;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 2;
      fields.maybeNumAckElicitingPacketsWritten = 2;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Initial;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 1;
      fields.maybeNumAckElicitingPacketsWritten = 1;
      return buildOutstandingPacket(fields);
    }());

    // build event
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(1)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(3)
                           .setNumAckElicitingPacketsWritten(3)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::Initial),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 1)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::Handshake),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 1)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 1))));
  }

  // first packet sent for initial, handshake, app data, single write, misorder
  // specifically, ordered by packet number, but random on pnspace
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Handshake;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 2;
      fields.maybeNumAckElicitingPacketsWritten = 2;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 3;
      fields.maybeNumAckElicitingPacketsWritten = 3;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Initial;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 1;
      fields.maybeNumAckElicitingPacketsWritten = 1;
      return buildOutstandingPacket(fields);
    }());

    // build event
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(1)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(3)
                           .setNumAckElicitingPacketsWritten(3)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::Initial),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 1)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::Handshake),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 1)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 1))));
  }

  // first packet for initial, handshake, app data, separate writes, ordered
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Initial;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 1;
      fields.maybeNumAckElicitingPacketsWritten = 1;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Handshake;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 2;
      fields.maybeNumPacketsWritten = 2;
      fields.maybeNumAckElicitingPacketsWritten = 2;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 3;
      fields.maybeNumPacketsWritten = 3;
      fields.maybeNumAckElicitingPacketsWritten = 3;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 3
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(3)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(1)
                           .setNumAckElicitingPacketsWritten(1)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(::testing::AllOf(
            ::testing::Field(
                &InvokedOutstandingPacketFields::pnSpace,
                PacketNumberSpace::AppData),
            ::testing::Field(&InvokedOutstandingPacketFields::packetNum, 1))));
  }

  // first packet for initial, handshake, app data, separate writes, reversed
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 3;
      fields.maybeNumPacketsWritten = 3;
      fields.maybeNumAckElicitingPacketsWritten = 3;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Initial;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 1;
      fields.maybeNumAckElicitingPacketsWritten = 1;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Handshake;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 2;
      fields.maybeNumPacketsWritten = 2;
      fields.maybeNumAckElicitingPacketsWritten = 2;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 3
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(3)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(1)
                           .setNumAckElicitingPacketsWritten(1)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(::testing::AllOf(
            ::testing::Field(
                &InvokedOutstandingPacketFields::pnSpace,
                PacketNumberSpace::AppData),
            ::testing::Field(&InvokedOutstandingPacketFields::packetNum, 1))));
  }

  // retransmit initial
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Initial;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 1;
      fields.maybeNumAckElicitingPacketsWritten = 1;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Handshake;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 2;
      fields.maybeNumAckElicitingPacketsWritten = 2;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 3;
      fields.maybeNumAckElicitingPacketsWritten = 3;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Initial;
      fields.maybePacketNum = 2;
      fields.maybeWriteCount = 2;
      fields.maybeNumPacketsWritten = 4;
      fields.maybeNumAckElicitingPacketsWritten = 4;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 2
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(2)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(1)
                           .setNumAckElicitingPacketsWritten(1)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(::testing::AllOf(
            ::testing::Field(
                &InvokedOutstandingPacketFields::pnSpace,
                PacketNumberSpace::Initial),
            ::testing::Field(&InvokedOutstandingPacketFields::packetNum, 2))));
  }

  // retransmit all three
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Initial;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 1;
      fields.maybeNumAckElicitingPacketsWritten = 1;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Handshake;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 2;
      fields.maybeNumAckElicitingPacketsWritten = 2;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 1;
      fields.maybeWriteCount = 1;
      fields.maybeNumPacketsWritten = 3;
      fields.maybeNumAckElicitingPacketsWritten = 3;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Initial;
      fields.maybePacketNum = 2;
      fields.maybeWriteCount = 2;
      fields.maybeNumPacketsWritten = 4;
      fields.maybeNumAckElicitingPacketsWritten = 4;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::Handshake;
      fields.maybePacketNum = 2;
      fields.maybeWriteCount = 2;
      fields.maybeNumPacketsWritten = 5;
      fields.maybeNumAckElicitingPacketsWritten = 5;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 2;
      fields.maybeWriteCount = 2;
      fields.maybeNumPacketsWritten = 6;
      fields.maybeNumAckElicitingPacketsWritten = 6;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 2
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(2)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(3)
                           .setNumAckElicitingPacketsWritten(3)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::Initial),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 2)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::Handshake),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 2)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 2))));
  }

  // just app data, single new packet
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 13;
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 16;
      fields.maybeNumAckElicitingPacketsWritten = 16;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 9
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(9)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(1)
                           .setNumAckElicitingPacketsWritten(1)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(::testing::AllOf(
            ::testing::Field(
                &InvokedOutstandingPacketFields::pnSpace,
                PacketNumberSpace::AppData),
            ::testing::Field(&InvokedOutstandingPacketFields::packetNum, 13))));
  }

  // just app data, single new packet, non-ack eliciting written
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 13;
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 16;
      fields.maybeNumAckElicitingPacketsWritten = 16;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 9
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(9)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(2)
                           .setNumAckElicitingPacketsWritten(1)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(::testing::AllOf(
            ::testing::Field(
                &InvokedOutstandingPacketFields::pnSpace,
                PacketNumberSpace::AppData),
            ::testing::Field(&InvokedOutstandingPacketFields::packetNum, 13))));
  }

  // just app data, multiple new packets
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 12;
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 15;
      fields.maybeNumAckElicitingPacketsWritten = 15;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 13;
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 16;
      fields.maybeNumAckElicitingPacketsWritten = 16;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 9
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(9)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(2)
                           .setNumAckElicitingPacketsWritten(2)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 12)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 13))));
  }

  // just app data, multiple new packets, non-ack eliciting written
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 12;
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 15;
      fields.maybeNumAckElicitingPacketsWritten = 15;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 14; // gap due to non-ack eliciting
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 17;
      fields.maybeNumAckElicitingPacketsWritten = 16;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 9
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(9)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(3)
                           .setNumAckElicitingPacketsWritten(2)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 12)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 14))));
  }

  // just app data, multiple old packets, multiple new packets
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 11;
      fields.maybeWriteCount = 8;
      fields.maybeNumPacketsWritten = 14;
      fields.maybeNumAckElicitingPacketsWritten = 14;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 12;
      fields.maybeWriteCount = 8;
      fields.maybeNumPacketsWritten = 15;
      fields.maybeNumAckElicitingPacketsWritten = 15;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 13;
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 16;
      fields.maybeNumAckElicitingPacketsWritten = 16;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 14;
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 17;
      fields.maybeNumAckElicitingPacketsWritten = 17;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 9
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(9)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(2)
                           .setNumAckElicitingPacketsWritten(2)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 13)),
            ::testing::AllOf(
                ::testing::Field(
                    &InvokedOutstandingPacketFields::pnSpace,
                    PacketNumberSpace::AppData),
                ::testing::Field(
                    &InvokedOutstandingPacketFields::packetNum, 14))));
  }

  // just app data, multiple old packets, single new packet
  {
    // create OutstandingPacket deque
    std::deque<OutstandingPacket> outstandingPackets;
    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 11;
      fields.maybeWriteCount = 8;
      fields.maybeNumPacketsWritten = 14;
      fields.maybeNumAckElicitingPacketsWritten = 14;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 12;
      fields.maybeWriteCount = 8;
      fields.maybeNumPacketsWritten = 15;
      fields.maybeNumAckElicitingPacketsWritten = 15;
      return buildOutstandingPacket(fields);
    }());

    outstandingPackets.emplace_back([]() {
      OutstandingPacketRelevantFields fields;
      fields.maybePnSpace = PacketNumberSpace::AppData;
      fields.maybePacketNum = 13;
      fields.maybeWriteCount = 9;
      fields.maybeNumPacketsWritten = 16;
      fields.maybeNumAckElicitingPacketsWritten = 16;
      return buildOutstandingPacket(fields);
    }());

    // build event with writeCount = 9
    const auto event = SocketObserverInterface::PacketsWrittenEvent::Builder()
                           .setOutstandingPackets(outstandingPackets)
                           .setWriteCount(9)
                           .setLastPacketSentTime(TimePoint())
                           .setCwndInBytes(folly::none)
                           .setWritableBytes(folly::none)
                           .setNumPacketsWritten(1)
                           .setNumAckElicitingPacketsWritten(1)
                           .setNumBytesWritten(0)
                           .build();

    // call invokeForEachNewOutstandingPacketOrdered and store in invoke order
    std::vector<InvokedOutstandingPacketFields> outstandingPacketsDuringInvoke;
    event.invokeForEachNewOutstandingPacketOrdered(
        [&outstandingPacketsDuringInvoke](
            const OutstandingPacket& outstandingPacket) {
          outstandingPacketsDuringInvoke.emplace_back(
              InvokedOutstandingPacketFields{
                  outstandingPacket.packet.header.getPacketNumberSpace(),
                  outstandingPacket.packet.header.getPacketSequenceNum()});
        });
    EXPECT_THAT(
        outstandingPacketsDuringInvoke,
        ::testing::ElementsAre(::testing::AllOf(
            ::testing::Field(
                &InvokedOutstandingPacketFields::pnSpace,
                PacketNumberSpace::AppData),
            ::testing::Field(&InvokedOutstandingPacketFields::packetNum, 13))));
  }
}

} // namespace quic::test
