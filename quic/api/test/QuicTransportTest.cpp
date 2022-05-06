/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <folly/Random.h>
#include <folly/io/Cursor.h>
#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <quic/QuicConstants.h>
#include <quic/api/QuicTransportBase.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/Mocks.h>
#include <quic/api/test/TestQuicTransport.h>
#include <quic/common/BufUtil.h>
#include <quic/common/Timers.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/StaticCwndCongestionController.h>
#include <quic/dsr/Types.h>
#include <quic/dsr/test/Mocks.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/logging/test/Mocks.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/test/Mocks.h>

using namespace folly;
using namespace folly::test;
using namespace testing;

namespace quic {
namespace test {

/**
 * A DeliveryCallback that closes your transport when it's canceled, or when
 * the targetOffset is delivered. Booyah!
 */
class TransportClosingDeliveryCallback : public QuicSocket::DeliveryCallback {
 public:
  explicit TransportClosingDeliveryCallback(
      TestQuicTransport* transport,
      uint64_t targetOffset)
      : transport_(transport), targetOffset_(targetOffset) {}

  void onDeliveryAck(StreamId, uint64_t offset, std::chrono::microseconds)
      override {
    if (offset >= targetOffset_) {
      transport_->close(folly::none);
    }
  }

  void onCanceled(StreamId, uint64_t) override {
    transport_->close(folly::none);
  }

 private:
  TestQuicTransport* transport_{nullptr};
  uint64_t targetOffset_;
};

class QuicTransportTest : public Test {
 public:
  ~QuicTransportTest() override = default;

  void SetUp() override {
    std::unique_ptr<MockAsyncUDPSocket> sock =
        std::make_unique<NiceMock<MockAsyncUDPSocket>>(&evb_);
    socket_ = sock.get();
    transport_.reset(new TestQuicTransport(
        &evb_, std::move(sock), &connSetupCallback_, &connCallback_));
    // Set the write handshake state to tell the client that the handshake has
    // a cipher.
    auto aead = std::make_unique<NiceMock<MockAead>>();
    aead_ = aead.get();
    EXPECT_CALL(*aead_, _inplaceEncrypt(_, _, _))
        .WillRepeatedly(
            Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
    EXPECT_CALL(*aead_, _decrypt(_, _, _))
        .WillRepeatedly(
            Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
    headerCipher_ = test::createNoOpHeaderCipher();
    transport_->getConnectionState().oneRttWriteCipher = std::move(aead);
    transport_->getConnectionState()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    transport_->getConnectionState()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    transport_->getConnectionState()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    transport_->getConnectionState().flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    transport_->getConnectionState()
        .streamManager->setMaxLocalBidirectionalStreams(
            kDefaultMaxStreamsBidirectional);
    transport_->getConnectionState()
        .streamManager->setMaxLocalUnidirectionalStreams(
            kDefaultMaxStreamsUnidirectional);
  }

  void loopForWrites() {
    // loop once to allow writes to take effect.
    evb_.loopOnce(EVLOOP_NONBLOCK);
  }

  auto getTxMatcher(StreamId id, uint64_t offset) {
    return MockByteEventCallback::getTxMatcher(id, offset);
  }

 protected:
  folly::EventBase evb_;
  MockAsyncUDPSocket* socket_;
  NiceMock<MockConnectionSetupCallback> connSetupCallback_;
  NiceMock<MockConnectionCallback> connCallback_;
  NiceMock<MockWriteCallback> writeCallback_;
  MockAead* aead_;
  std::unique_ptr<PacketNumberCipher> headerCipher_;
  std::shared_ptr<TestQuicTransport> transport_;
};

RegularQuicWritePacket stripPaddingFrames(RegularQuicWritePacket packet) {
  RegularQuicWritePacket::Vec trimmedFrames{};
  for (auto frame : packet.frames) {
    if (!frame.asPaddingFrame()) {
      trimmedFrames.push_back(frame);
    }
  }
  packet.frames = trimmedFrames;
  return packet;
}

size_t bufLength(
    const SocketAddress&,
    const std::unique_ptr<folly::IOBuf>& buf) {
  return buf->computeChainDataLength();
}

void dropPackets(QuicServerConnectionState& conn) {
  for (const auto& packet : conn.outstandings.packets) {
    for (const auto& frame : packet.packet.frames) {
      const WriteStreamFrame* streamFrame = frame.asWriteStreamFrame();
      if (!streamFrame) {
        continue;
      }
      auto stream = conn.streamManager->findStream(streamFrame->streamId);
      ASSERT_TRUE(stream);
      auto itr = stream->retransmissionBuffer.find(streamFrame->offset);
      ASSERT_TRUE(itr != stream->retransmissionBuffer.end());
      stream->lossBuffer.insert(
          std::upper_bound(
              stream->lossBuffer.begin(),
              stream->lossBuffer.end(),
              itr->second->offset,
              [](const auto& offset, const auto& buffer) {
                return offset < buffer.offset;
              }),
          std::move(*itr->second));
      stream->retransmissionBuffer.erase(itr);
      conn.streamManager->updateWritableStreams(*stream);
      conn.streamManager->updateLossStreams(*stream);
    }
  }
  conn.outstandings.reset();
}

// Helper function to verify the data of buffer is written to outstanding
// packets
void verifyCorrectness(
    const QuicServerConnectionState& conn,
    size_t originalWriteOffset,
    StreamId id,
    const folly::IOBuf& expected,
    bool finExpected = false,
    bool writeAll = true) {
  uint64_t endOffset = 0;
  size_t totalLen = 0;
  bool finSet = false;
  std::vector<uint64_t> offsets;
  for (const auto& packet : conn.outstandings.packets) {
    for (const auto& frame : packet.packet.frames) {
      auto streamFrame = frame.asWriteStreamFrame();
      if (!streamFrame) {
        continue;
      }
      if (streamFrame->streamId != id) {
        continue;
      }
      offsets.push_back(streamFrame->offset);
      endOffset = std::max(endOffset, streamFrame->offset + streamFrame->len);
      totalLen += streamFrame->len;
      finSet |= streamFrame->fin;
    }
  }
  auto stream = conn.streamManager->findStream(id);
  ASSERT_TRUE(stream);
  if (writeAll) {
    EXPECT_TRUE(stream->writeBuffer.empty());
  }
  EXPECT_EQ(stream->currentWriteOffset, endOffset + (finSet ? 1 : 0));
  EXPECT_EQ(
      stream->currentWriteOffset,
      originalWriteOffset + totalLen + (finSet ? 1 : 0));
  EXPECT_EQ(totalLen, expected.computeChainDataLength());
  EXPECT_EQ(finExpected, finSet);
  // Verify retransmissionBuffer:
  EXPECT_FALSE(stream->retransmissionBuffer.empty());
  BufQueue retxBufCombined;
  std::vector<StreamBuffer> rtxCopy;
  for (auto& itr : stream->retransmissionBuffer) {
    rtxCopy.push_back(StreamBuffer(
        itr.second->data.front()->clone(),
        itr.second->offset,
        itr.second->eof));
  }
  std::sort(rtxCopy.begin(), rtxCopy.end(), [](auto& s1, auto& s2) {
    return s1.offset < s2.offset;
  });
  for (auto& s : rtxCopy) {
    retxBufCombined.append(s.data.move());
  }
  EXPECT_TRUE(IOBufEqualTo()(expected, *retxBufCombined.move()));
  EXPECT_EQ(finExpected, stream->retransmissionBuffer.at(offsets.back())->eof);
  std::vector<uint64_t> retxBufOffsets;
  for (const auto& b : stream->retransmissionBuffer) {
    retxBufOffsets.push_back(b.second->offset);
  }
  std::sort(retxBufOffsets.begin(), retxBufOffsets.end());
  EXPECT_EQ(offsets, retxBufOffsets);
}

TEST_F(QuicTransportTest, WriteDataWithProbing) {
  auto& conn = transport_->getConnectionState();
  // Replace with MockConnectionCallback:
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(kDefaultUDPSendPacketLen * 2);
  conn.pendingEvents.numProbePackets[PacketNumberSpace::AppData] = 1;
  // Probing won't ask about getWritableBytes. Then regular write may ask
  // multiple times:
  int getWritableBytesCounter = 0;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        getWritableBytesCounter++;
        return kDefaultUDPSendPacketLen;
      }));
  // Probing will invoke onPacketSent once. Then regular write may invoke
  // multiple times:
  int onPacketSentCounter = 0;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(
          Invoke([&](const auto& /* packet */) { onPacketSentCounter++; }));
  // Probing will send out one. Then regular write may send out multiple ones:
  int socketWriteCounter = 0;
  EXPECT_CALL(*socket_, write(_, _))
      .WillRepeatedly(Invoke([&](const SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& iobuf) {
        socketWriteCounter++;
        return iobuf->computeChainDataLength();
      }));
  transport_->writeChain(streamId, buf->clone(), true);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, NotAppLimitedWithLoss) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  auto stream = transport_->createBidirectionalStream().value();
  auto lossStream = transport_->createBidirectionalStream().value();
  auto lossStreamState = conn.streamManager->findStream(lossStream);
  ASSERT_TRUE(lossStreamState);
  auto largeBuf = folly::IOBuf::createChain(conn.udpSendPacketLen * 20, 4096);
  auto curBuf = largeBuf.get();
  do {
    curBuf->append(curBuf->capacity());
    curBuf = curBuf->next();
  } while (curBuf != largeBuf.get());
  lossStreamState->lossBuffer.emplace_back(std::move(largeBuf), 31, false);
  conn.streamManager->updateWritableStreams(*lossStreamState);
  conn.streamManager->updateLossStreams(*lossStreamState);
  transport_->writeChain(
      stream, IOBuf::copyBuffer("An elephant sitting still"), false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(0);
  EXPECT_CALL(connCallback_, onAppRateLimited()).Times(0);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, NotAppLimitedWithNoWritableBytes) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        if (conn.outstandings.packets.empty()) {
          return 5000;
        }
        return 0;
      }));

  auto stream = transport_->createBidirectionalStream().value();
  transport_->writeChain(
      stream, IOBuf::copyBuffer("An elephant sitting still"), false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(0);
  EXPECT_CALL(connCallback_, onAppRateLimited()).Times(0);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, NotAppLimitedWithLargeBuffer) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100 * 2000);
  transport_->writeChain(stream, buf->clone(), false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(0);
  EXPECT_CALL(connCallback_, onAppRateLimited()).Times(0);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, AppLimited) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  transport_->setTransportReadyNotified(true);
  auto stream = transport_->createBidirectionalStream().value();
  transport_->writeChain(
      stream, IOBuf::copyBuffer("An elephant sitting still"), false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(1);
  EXPECT_CALL(connCallback_, onAppRateLimited()).Times(1);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, ObserverNotAppLimitedWithNoWritableBytes) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        if (conn.outstandings.packets.empty()) {
          return 5000;
        }
        return 0;
      }));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::packetsWrittenEvents,
      SocketObserverInterface::Events::appRateLimitedEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  EXPECT_CALL(*cb3, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  transport_->addObserver(cb2.get());
  transport_->addObserver(cb3.get());

  auto stream = transport_->createBidirectionalStream().value();
  transport_->writeChain(
      stream, IOBuf::copyBuffer("An elephant sitting still"), false, nullptr);
  EXPECT_CALL(*cb1, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb1, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb1, appRateLimited(transport_.get(), _)).Times(0);
  EXPECT_CALL(*cb2, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb2, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb2, appRateLimited(transport_.get(), _)).Times(0);
  loopForWrites();
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_CALL(*cb1, close(transport_.get(), _));
  EXPECT_CALL(*cb2, close(transport_.get(), _));
  EXPECT_CALL(*cb3, close(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  EXPECT_CALL(*cb3, destroy(transport_.get()));
  transport_->close(folly::none);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverNotAppLimitedWithLargeBuffer) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::packetsWrittenEvents,
      SocketObserverInterface::Events::appRateLimitedEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  EXPECT_CALL(*cb3, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  transport_->addObserver(cb2.get());
  transport_->addObserver(cb3.get());

  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100 * 2000);
  transport_->writeChain(stream, buf->clone(), false, nullptr);
  EXPECT_CALL(*cb1, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb1, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb1, appRateLimited(transport_.get(), _)).Times(0);
  EXPECT_CALL(*cb2, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb2, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb2, appRateLimited(transport_.get(), _)).Times(0);
  loopForWrites();
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_CALL(*cb1, close(transport_.get(), _));
  EXPECT_CALL(*cb2, close(transport_.get(), _));
  EXPECT_CALL(*cb3, close(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  EXPECT_CALL(*cb3, destroy(transport_.get()));
  transport_->close(folly::none);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverAppLimited) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::packetsWrittenEvents,
      SocketObserverInterface::Events::appRateLimitedEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  EXPECT_CALL(*cb3, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  transport_->addObserver(cb2.get());
  transport_->addObserver(cb3.get());

  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  auto stream = transport_->createBidirectionalStream().value();
  transport_->writeChain(
      stream, IOBuf::copyBuffer("An elephant sitting still"), false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(1);
  EXPECT_CALL(*cb1, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb1, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb1, appRateLimited(transport_.get(), _));
  EXPECT_CALL(*cb2, startWritingFromAppLimited(transport_.get(), _));
  EXPECT_CALL(*cb2, packetsWritten(transport_.get(), _));
  EXPECT_CALL(*cb2, appRateLimited(transport_.get(), _));
  loopForWrites();
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
  Mock::VerifyAndClearExpectations(cb3.get());
  EXPECT_CALL(*cb1, close(transport_.get(), _));
  EXPECT_CALL(*cb2, close(transport_.get(), _));
  EXPECT_CALL(*cb3, close(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  EXPECT_CALL(*cb3, destroy(transport_.get()));
  transport_->close(folly::none);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverPacketsWrittenCycleCheckDetails) {
  InSequence s;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::packetsWrittenEvents,
      SocketObserverInterface::Events::appRateLimitedEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  const auto invokeForAllObservers =
      [&cb1, &cb2, &cb3](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
        fn(*cb3);
      };
  const auto invokeForEachObserverWithTestEvents =
      [&cb1, &cb2](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
      };

  // install observers
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, observerAttach(transport_.get()));
    transport_->addObserver(&observer);
  }));
  EXPECT_THAT(
      transport_->getObservers(),
      UnorderedElementsAre(cb1.get(), cb2.get(), cb3.get()));

  auto& conn = transport_->getConnectionState();
  uint64_t writeNum = 1;

  /**
   * part 1: write of non-ACK eliciting packet triggered by scheduled ACK.
   */

  // expectations:
  //   - write number is 1.
  //   - one packet sent, zero ACK eliciting packets sent.
  //   - no outstanding packets from this write or previous writes.
  {
    const auto writeEventMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(0)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)));
    const auto packetsWrittenEventMatcher = AllOf(
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(0)));

    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              startWritingFromAppLimited(transport_.get(), writeEventMatcher));
        }));
    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher, &packetsWrittenEventMatcher](
             MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              packetsWritten(
                  transport_.get(),
                  AllOf(writeEventMatcher, packetsWrittenEventMatcher)));
        }));
    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer, appRateLimited(transport_.get(), writeEventMatcher));
        }));
  }

  // schedule the ACK
  {
    PacketNum start = 10;
    PacketNum end = 15;
    addAckStatesWithCurrentTimestamps(
        conn.ackStates.appDataAckState, start, end);
    conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
    conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
  }

  // loop
  transport_->updateWriteLooper(true);
  loopForWrites();

  /**
   * part 2: write of ACK eliciting packets triggered by stream write.
   *
   * multiple writes back to back.
   */

  // expectations:
  //   - two writes will be triggered, write numbers 2 and 3
  //   - five ACK eliciting packets sent first write, two sent on second write
  //   - total of seven outstanding packets
  {
    // part 2.1, we go from app limited to writing, no outstandings yet
    writeNum++;
    EXPECT_EQ(2, writeNum);
    {
      const auto writeEventMatcher = AllOf(
          testing::Property(
              &SocketObserverInterface::WriteEvent::getOutstandingPackets,
              testing::SizeIs(0)),
          testing::Field(
              &SocketObserverInterface::WriteEvent::writeCount,
              testing::Eq(writeNum)));

      invokeForEachObserverWithTestEvents(([this, &writeEventMatcher](
                                               MockLegacyObserver& observer) {
        EXPECT_CALL(
            observer,
            startWritingFromAppLimited(transport_.get(), writeEventMatcher));
      }));
    }

    // part 2.2, we write five ACK eliciting packets
    {
      const auto writeEventMatcher = AllOf(
          testing::Property(
              &SocketObserverInterface::WriteEvent::getOutstandingPackets,
              testing::SizeIs(5)),
          testing::Field(
              &SocketObserverInterface::WriteEvent::writeCount,
              testing::Eq(writeNum)));
      const auto packetsWrittenEventMatcher = AllOf(
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
              testing::Eq(5)),
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::
                  numAckElicitingPacketsWritten,
              testing::Eq(5)));

      invokeForEachObserverWithTestEvents(
          ([this, &writeEventMatcher, &packetsWrittenEventMatcher](
               MockLegacyObserver& observer) {
            EXPECT_CALL(
                observer,
                packetsWritten(
                    transport_.get(),
                    AllOf(writeEventMatcher, packetsWrittenEventMatcher)));
          }));
    }

    // part 2.3, we write two ACK eliciting packets, then become app limited
    writeNum++;
    EXPECT_EQ(3, writeNum);
    {
      const auto writeEventMatcher = AllOf(
          testing::Property(
              &SocketObserverInterface::WriteEvent::getOutstandingPackets,
              testing::SizeIs(7)),
          testing::Field(
              &SocketObserverInterface::WriteEvent::writeCount,
              testing::Eq(writeNum)));
      const auto packetsWrittenEventMatcher = AllOf(
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
              testing::Eq(2)),
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::
                  numAckElicitingPacketsWritten,
              testing::Eq(2)));

      invokeForEachObserverWithTestEvents(
          ([this, &writeEventMatcher, &packetsWrittenEventMatcher](
               MockLegacyObserver& observer) {
            EXPECT_CALL(
                observer,
                packetsWritten(
                    transport_.get(),
                    AllOf(writeEventMatcher, packetsWrittenEventMatcher)));
          }));
      invokeForEachObserverWithTestEvents(
          ([this, &writeEventMatcher](MockLegacyObserver& observer) {
            EXPECT_CALL(
                observer, appRateLimited(transport_.get(), writeEventMatcher));
          }));
    }
  }

  // write some data
  auto stream = transport_->createBidirectionalStream().value();
  transport_->writeChain(stream, buildRandomInputData(8000), false, nullptr);

  // loop twice to get all packets cleared out
  transport_->updateWriteLooper(true);
  loopForWrites();
  loopForWrites();

  /**
   * part 3: write of ACK eliciting frames with non-ACK eliciting frames.
   *   - ACK eliciting frames triggered by stream write.
   *   - non-ACK eliciting frames triggered by pending ACK.
   *   - all packets will be ACK eliciting.
   */

  // expectations:
  //   - write number is 4.
  //   - two ACK eliciting packets written.
  //   - total of nine outstanding packets.
  {
    writeNum++;
    EXPECT_EQ(4, writeNum);

    // part 3.1, we go from app limited to writing, previous outstandings
    {
      const auto writeEventMatcher = AllOf(
          testing::Property(
              &SocketObserverInterface::WriteEvent::getOutstandingPackets,
              testing::SizeIs(7)),
          testing::Field(
              &SocketObserverInterface::WriteEvent::writeCount,
              testing::Eq(writeNum)));

      invokeForEachObserverWithTestEvents(([this, &writeEventMatcher](
                                               MockLegacyObserver& observer) {
        EXPECT_CALL(
            observer,
            startWritingFromAppLimited(transport_.get(), writeEventMatcher));
      }));
    }

    // part 3.2, we write two ACK eliciting packets, then become app limited
    // one of the ACK eliciting packets contains an ACK frame
    {
      // older versions of gtest do not seem to accept lambdas for ResultOf
      // matcher, so define an std::function
      std::function<uint64_t(const SocketObserverInterface::WriteEvent&)>
          countPacketsWithAckFrames =
              [](const SocketObserverInterface::WriteEvent& event) -> uint64_t {
        uint64_t packetsWithAckFrames = 0;
        for (auto& outstandingPacket : event.outstandingPackets) {
          bool hasAckFrame = false;
          for (auto& frame : outstandingPacket.packet.frames) {
            if (frame.asWriteAckFrame()) {
              hasAckFrame = true;
            }
          }

          if (hasAckFrame) {
            packetsWithAckFrames++;
          }
        }
        return packetsWithAckFrames;
      };

      const auto writeEventMatcher = AllOf(
          testing::ResultOf(countPacketsWithAckFrames, 1),
          testing::Property(
              &SocketObserverInterface::WriteEvent::getOutstandingPackets,
              testing::SizeIs(9)),
          testing::Field(
              &SocketObserverInterface::WriteEvent::writeCount,
              testing::Eq(writeNum)));
      const auto packetsWrittenEventMatcher = AllOf(
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
              testing::Eq(2)),
          testing::Field(
              &SocketObserverInterface::PacketsWrittenEvent::
                  numAckElicitingPacketsWritten,
              testing::Eq(2)));

      invokeForEachObserverWithTestEvents(
          ([this, &writeEventMatcher, &packetsWrittenEventMatcher](
               MockLegacyObserver& observer) {
            EXPECT_CALL(
                observer,
                packetsWritten(
                    transport_.get(),
                    AllOf(writeEventMatcher, packetsWrittenEventMatcher)));
          }));
      invokeForEachObserverWithTestEvents(
          ([this, &writeEventMatcher](MockLegacyObserver& observer) {
            EXPECT_CALL(
                observer, appRateLimited(transport_.get(), writeEventMatcher));
          }));
    }
  }

  // schedule the ACK
  {
    PacketNum start = 20;
    PacketNum end = 25;
    addAckStatesWithCurrentTimestamps(
        conn.ackStates.appDataAckState, start, end);
    conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
    conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
  }

  // write some more data
  transport_->writeChain(stream, buildRandomInputData(2000), false, nullptr);

  // loop
  transport_->updateWriteLooper(true);
  loopForWrites();

  /**
   * part 4: write of non-ACK eliciting packet triggered by scheduled ACK.
   *
   * (repeat of part 1, writing only non-ACK eliciting packets)
   */

  // expectations:
  //   - write number is 5.
  //   - one packet sent, zero ACK eliciting packets sent.
  //   - outstanding packets from previous write remain
  {
    writeNum++;
    EXPECT_EQ(5, writeNum);

    const auto writeEventMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(9)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)));
    const auto packetsWrittenEventMatcher = AllOf(
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(0)));

    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              startWritingFromAppLimited(transport_.get(), writeEventMatcher));
        }));
    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher, &packetsWrittenEventMatcher](
             MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              packetsWritten(
                  transport_.get(),
                  AllOf(writeEventMatcher, packetsWrittenEventMatcher)));
        }));
    invokeForEachObserverWithTestEvents(
        ([this, &writeEventMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer, appRateLimited(transport_.get(), writeEventMatcher));
        }));
  }

  // schedule the ACK
  {
    PacketNum start = 30;
    PacketNum end = 35;
    addAckStatesWithCurrentTimestamps(
        conn.ackStates.appDataAckState, start, end);
    conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
    conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
  }

  // loop
  transport_->updateWriteLooper(true);
  loopForWrites();

  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, close(transport_.get(), _));
  }));
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, destroy(transport_.get()));
  }));
  transport_->close(folly::none);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverPacketsWrittenCheckBytesSent) {
  InSequence s;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::packetsWrittenEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  const auto invokeForAllObservers =
      [&cb1, &cb2, &cb3](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
        fn(*cb3);
      };
  const auto invokeForEachObserverWithTestEvents =
      [&cb1, &cb2](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
      };

  // install observers
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, observerAttach(transport_.get()));
    transport_->addObserver(&observer);
  }));
  EXPECT_THAT(
      transport_->getObservers(),
      UnorderedElementsAre(cb1.get(), cb2.get(), cb3.get()));

  auto& conn = transport_->getConnectionState();
  uint64_t writeNum = 1;

  // write of 4000 stream bytes
  {
    // matcher
    const auto matcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(4)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(4)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(4)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(4000)));

    invokeForEachObserverWithTestEvents(
        ([this, &matcher, oldTInfo = transport_->getTransportInfo()](
             MockLegacyObserver& observer) {
          EXPECT_CALL(observer, packetsWritten(transport_.get(), matcher))
              .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
                EXPECT_EQ(
                    socket->getTransportInfo().bytesSent - oldTInfo.bytesSent,
                    event.numBytesWritten);
              }));
        }));

    auto stream = transport_->createBidirectionalStream().value();
    transport_->writeChain(stream, buildRandomInputData(4000), false, nullptr);
    transport_->updateWriteLooper(true);
    loopForWrites();
    loopForWrites();
  }

  // another write of 1000 stream bytes
  {
    writeNum++;

    // matcher
    const auto matcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(5)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(1000)));

    invokeForEachObserverWithTestEvents(
        ([this, &matcher, oldTInfo = transport_->getTransportInfo()](
             MockLegacyObserver& observer) {
          EXPECT_CALL(observer, packetsWritten(transport_.get(), matcher))
              .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
                EXPECT_EQ(
                    socket->getTransportInfo().bytesSent - oldTInfo.bytesSent,
                    event.numBytesWritten);
              }));
        }));

    auto stream = transport_->createBidirectionalStream().value();
    transport_->writeChain(stream, buildRandomInputData(1000), false, nullptr);
    transport_->updateWriteLooper(true);
    loopForWrites();
  }

  // send an ACK
  {
    writeNum++;

    // matcher
    const auto matcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(5)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(0)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(0)));

    invokeForEachObserverWithTestEvents(
        ([this, &matcher, oldTInfo = transport_->getTransportInfo()](
             MockLegacyObserver& observer) {
          EXPECT_CALL(observer, packetsWritten(transport_.get(), matcher))
              .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
                EXPECT_EQ(
                    socket->getTransportInfo().bytesSent - oldTInfo.bytesSent,
                    event.numBytesWritten);
              }));
        }));

    PacketNum start = 20;
    PacketNum end = 25;
    addAckStatesWithCurrentTimestamps(
        conn.ackStates.appDataAckState, start, end);
    conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
    conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
    transport_->updateWriteLooper(true);
    loopForWrites();
  }

  // another write of 1000 stream bytes AND some ACKs in same packet
  {
    writeNum++;

    // matcher
    const auto matcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(6)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(1000)));

    invokeForEachObserverWithTestEvents(
        ([this, &matcher, oldTInfo = transport_->getTransportInfo()](
             MockLegacyObserver& observer) {
          EXPECT_CALL(observer, packetsWritten(transport_.get(), matcher))
              .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
                EXPECT_EQ(
                    socket->getTransportInfo().bytesSent - oldTInfo.bytesSent,
                    event.numBytesWritten);
              }));
        }));

    PacketNum start = 30;
    PacketNum end = 35;
    addAckStatesWithCurrentTimestamps(
        conn.ackStates.appDataAckState, start, end);
    conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
    conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
    auto stream = transport_->createBidirectionalStream().value();
    transport_->writeChain(stream, buildRandomInputData(1000), false, nullptr);

    transport_->updateWriteLooper(true);
    loopForWrites();
  }

  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, close(transport_.get(), _));
  }));
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, destroy(transport_.get()));
  }));
  transport_->close(folly::none);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverWriteEventsCheckCwndPacketsWritable) {
  InSequence s;
  LegacyObserver::EventSet eventSet;
  eventSet.enable(
      SocketObserverInterface::Events::packetsWrittenEvents,
      SocketObserverInterface::Events::appRateLimitedEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb3 = std::make_unique<StrictMock<MockLegacyObserver>>();

  const auto invokeForAllObservers =
      [&cb1, &cb2, &cb3](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
        fn(*cb3);
      };
  const auto invokeForEachObserverWithTestEvents =
      [&cb1, &cb2](const std::function<void(MockLegacyObserver&)>& fn) {
        fn(*cb1);
        fn(*cb2);
      };

  // install observers
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, observerAttach(transport_.get()));
    transport_->addObserver(&observer);
  }));
  EXPECT_THAT(
      transport_->getObservers(),
      UnorderedElementsAre(cb1.get(), cb2.get(), cb3.get()));

  auto& conn = transport_->getConnectionState();

  // install StaticCwndCongestionController
  const auto cwndInBytes = 10000;
  conn.congestionController = std::make_unique<StaticCwndCongestionController>(
      StaticCwndCongestionController::CwndInBytes(cwndInBytes));

  // update writeNum and upperBoundCurrentBytesWritable after each write/ACK
  uint64_t writeNum = 1;
  uint64_t upperBoundCurrentBytesWritable = cwndInBytes;

  // write of 4000 stream bytes
  {
    const auto bytesToWrite = 4000;

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::IsEmpty()),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(4)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(
                upperBoundCurrentBytesWritable - bytesToWrite))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(4)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(4)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(bytesToWrite)));

    // matcher for event from appRateLimited
    const auto appRateLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(4)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(
                upperBoundCurrentBytesWritable - bytesToWrite))));

    invokeForEachObserverWithTestEvents(
        ([this,
          &startWritingFromAppLimitedMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              startWritingFromAppLimited(
                  transport_.get(), startWritingFromAppLimitedMatcher));
        }));

    invokeForEachObserverWithTestEvents(
        ([this,
          &packetsWrittenMatcher,
          cwndInBytes,
          oldTInfo =
              transport_->getTransportInfo()](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer, packetsWritten(transport_.get(), packetsWrittenMatcher))
              .WillOnce(([cwndInBytes, oldTInfo](
                             const auto& socket, const auto& event) {
                EXPECT_EQ(
                    cwndInBytes - socket->getTransportInfo().bytesSent -
                        oldTInfo.bytesSent,
                    event.maybeWritableBytes);
              }));
        }));

    invokeForEachObserverWithTestEvents(
        ([this,
          &appRateLimitedMatcher,
          cwndInBytes,
          oldTInfo =
              transport_->getTransportInfo()](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer, appRateLimited(transport_.get(), appRateLimitedMatcher))
              .WillOnce(([cwndInBytes, oldTInfo](
                             const auto& socket, const auto& event) {
                EXPECT_EQ(
                    cwndInBytes - socket->getTransportInfo().bytesSent -
                        oldTInfo.bytesSent,
                    event.maybeWritableBytes);
              }));
        }));

    auto stream = transport_->createBidirectionalStream().value();
    transport_->writeChain(
        stream, buildRandomInputData(bytesToWrite), false, nullptr);
    transport_->updateWriteLooper(true);
    loopForWrites();
    loopForWrites();

    // remove bytesToWrite from upperBoundCurrentBytesWritable
    upperBoundCurrentBytesWritable -= bytesToWrite;
    writeNum++;
  }

  // another write of 1000 stream bytes
  {
    const auto bytesToWrite = 1000;

    // matcher for event from startWritingFromAppLimited
    const auto startWritingFromAppLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(4)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(
                folly::Optional<uint64_t>(upperBoundCurrentBytesWritable))));

    // matcher for event from packetsWritten
    const auto packetsWrittenMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(5)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(
                upperBoundCurrentBytesWritable - bytesToWrite))),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::
                numAckElicitingPacketsWritten,
            testing::Eq(1)),
        testing::Field(
            &SocketObserverInterface::PacketsWrittenEvent::numBytesWritten,
            testing::Gt(bytesToWrite)));

    // matcher for event from appRateLimited
    const auto appRateLimitedMatcher = AllOf(
        testing::Property(
            &SocketObserverInterface::WriteEvent::getOutstandingPackets,
            testing::SizeIs(5)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::writeCount,
            testing::Eq(writeNum)),
        testing::Field(
            &SocketObserverInterface::WriteEvent::maybeCwndInBytes,
            testing::Eq(folly::Optional<uint64_t>(cwndInBytes))),
        testing::Field( // precise check below
            &SocketObserverInterface::WriteEvent::maybeWritableBytes,
            testing::Lt(folly::Optional<uint64_t>(
                upperBoundCurrentBytesWritable - bytesToWrite))));

    invokeForEachObserverWithTestEvents(
        ([this,
          &startWritingFromAppLimitedMatcher](MockLegacyObserver& observer) {
          EXPECT_CALL(
              observer,
              startWritingFromAppLimited(
                  transport_.get(), startWritingFromAppLimitedMatcher));
        }));

    invokeForEachObserverWithTestEvents(([this,
                                          &packetsWrittenMatcher,
                                          oldTInfo =
                                              transport_->getTransportInfo()](
                                             MockLegacyObserver& observer) {
      EXPECT_CALL(
          observer, packetsWritten(transport_.get(), packetsWrittenMatcher))
          .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
            EXPECT_EQ(
                oldTInfo.writableBytes -
                    (socket->getTransportInfo().bytesSent - oldTInfo.bytesSent),
                event.maybeWritableBytes);
          }));
    }));

    invokeForEachObserverWithTestEvents(([this,
                                          &appRateLimitedMatcher,
                                          oldTInfo =
                                              transport_->getTransportInfo()](
                                             MockLegacyObserver& observer) {
      EXPECT_CALL(
          observer, appRateLimited(transport_.get(), appRateLimitedMatcher))
          .WillOnce(([oldTInfo](const auto& socket, const auto& event) {
            EXPECT_EQ(
                oldTInfo.writableBytes -
                    (socket->getTransportInfo().bytesSent - oldTInfo.bytesSent),
                event.maybeWritableBytes);
          }));
    }));

    auto stream = transport_->createBidirectionalStream().value();
    transport_->writeChain(
        stream, buildRandomInputData(bytesToWrite), false, nullptr);
    transport_->updateWriteLooper(true);
    loopForWrites();
    loopForWrites();

    // remove bytesToWrite from upperBoundCurrentBytesWritable
    upperBoundCurrentBytesWritable -= bytesToWrite;
    writeNum++;
  }

  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, close(transport_.get(), _));
  }));
  invokeForAllObservers(([this](MockLegacyObserver& observer) {
    EXPECT_CALL(observer, destroy(transport_.get()));
  }));
  transport_->close(folly::none);
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverStreamEventBidirectionalLocalOpenClose) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  transport_->addObserver(cb2.get());
  EXPECT_THAT(
      transport_->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  const auto id = 0x01;
  const auto streamEventMatcher = MockLegacyObserver::getStreamEventMatcher(
      id, StreamInitiator::Local, StreamDirectionality::Bidirectional);

  EXPECT_CALL(*cb1, streamOpened(transport_.get(), streamEventMatcher));
  EXPECT_EQ(id, transport_->createBidirectionalStream().value());

  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Local, transport_->getStreamInitiator(id));

  EXPECT_CALL(*cb1, streamClosed(transport_.get(), streamEventMatcher));
  auto stream = CHECK_NOTNULL(
      transport_->getConnectionState().streamManager->getStream(id));
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  transport_->getConnectionState().streamManager->addClosed(id);
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  EXPECT_CALL(*cb1, close(transport_.get(), _));
  EXPECT_CALL(*cb2, close(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverStreamEventBidirectionalRemoteOpenClose) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  transport_->addObserver(cb2.get());
  EXPECT_THAT(
      transport_->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  const auto id = 0x00;
  const auto streamEventMatcher = MockLegacyObserver::getStreamEventMatcher(
      id, StreamInitiator::Remote, StreamDirectionality::Bidirectional);

  EXPECT_CALL(*cb1, streamOpened(transport_.get(), streamEventMatcher));
  auto stream = CHECK_NOTNULL(
      transport_->getConnectionState().streamManager->getStream(id));
  EXPECT_THAT(stream, NotNull());

  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Remote, transport_->getStreamInitiator(id));

  EXPECT_CALL(*cb1, streamClosed(transport_.get(), streamEventMatcher));
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  transport_->getConnectionState().streamManager->addClosed(id);
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  EXPECT_CALL(*cb1, close(transport_.get(), _));
  EXPECT_CALL(*cb2, close(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverStreamEventUnidirectionalLocalOpenClose) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  transport_->addObserver(cb2.get());
  EXPECT_THAT(
      transport_->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  const auto id = 0x03;
  const auto streamEventMatcher = MockLegacyObserver::getStreamEventMatcher(
      id, StreamInitiator::Local, StreamDirectionality::Unidirectional);

  EXPECT_CALL(*cb1, streamOpened(transport_.get(), streamEventMatcher));
  EXPECT_EQ(id, transport_->createUnidirectionalStream().value());

  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Local, transport_->getStreamInitiator(id));

  EXPECT_CALL(*cb1, streamClosed(transport_.get(), streamEventMatcher));
  auto stream = CHECK_NOTNULL(
      transport_->getConnectionState().streamManager->getStream(id));
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  transport_->getConnectionState().streamManager->addClosed(id);
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  EXPECT_CALL(*cb1, close(transport_.get(), _));
  EXPECT_CALL(*cb2, close(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, ObserverStreamEventUnidirectionalRemoteOpenClose) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::streamEvents);
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>(eventSet);
  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();

  EXPECT_CALL(*cb1, observerAttach(transport_.get()));
  transport_->addObserver(cb1.get());
  EXPECT_CALL(*cb2, observerAttach(transport_.get()));
  transport_->addObserver(cb2.get());
  EXPECT_THAT(
      transport_->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  const auto id = 0x02;
  const auto streamEventMatcher = MockLegacyObserver::getStreamEventMatcher(
      id, StreamInitiator::Remote, StreamDirectionality::Unidirectional);

  EXPECT_CALL(*cb1, streamOpened(transport_.get(), streamEventMatcher));
  auto stream = CHECK_NOTNULL(
      transport_->getConnectionState().streamManager->getStream(id));

  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Remote, transport_->getStreamInitiator(id));

  EXPECT_CALL(*cb1, streamClosed(transport_.get(), streamEventMatcher));
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  transport_->getConnectionState().streamManager->addClosed(id);
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  EXPECT_CALL(*cb1, close(transport_.get(), _));
  EXPECT_CALL(*cb2, close(transport_.get(), _));
  EXPECT_CALL(*cb1, destroy(transport_.get()));
  EXPECT_CALL(*cb2, destroy(transport_.get()));
  transport_ = nullptr;
}

TEST_F(QuicTransportTest, StreamBidirectionalLocal) {
  const auto id = 0x01;
  EXPECT_EQ(id, transport_->createBidirectionalStream().value());

  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Local, transport_->getStreamInitiator(id));
}

TEST_F(QuicTransportTest, StreamBidirectionalRemote) {
  const auto id = 0x00;
  // trigger tracking of new remote stream via getStream()
  CHECK_NOTNULL(transport_->getConnectionState().streamManager->getStream(id));

  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Remote, transport_->getStreamInitiator(id));
}

TEST_F(QuicTransportTest, StreamUnidirectionalLocal) {
  const auto id = 0x03;
  EXPECT_EQ(id, transport_->createUnidirectionalStream().value());

  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Local, transport_->getStreamInitiator(id));
}

TEST_F(QuicTransportTest, StreamUnidirectionalRemote) {
  const auto id = 0x02;
  // trigger tracking of new remote stream via getStream()
  CHECK_NOTNULL(transport_->getConnectionState().streamManager->getStream(id));

  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      transport_->getStreamDirectionality(id));
  EXPECT_EQ(StreamInitiator::Remote, transport_->getStreamInitiator(id));
}

TEST_F(QuicTransportTest, WriteSmall) {
  // Testing writing a small buffer that could be fit in a single packet
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);

  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false);
  transport_->setStreamPriority(stream, 0, false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);

  verifyCorrectness(conn, 0, stream, *buf);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteLarge) {
  // Testing writing a large buffer that would span multiple packets
  constexpr int NumFullPackets = 3;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf =
      buildRandomInputData(NumFullPackets * kDefaultUDPSendPacketLen + 20);
  folly::IOBuf passedIn;
  EXPECT_CALL(*socket_, write(_, _))
      .Times(NumFullPackets + 1)
      .WillRepeatedly(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(NumFullPackets + 1, conn.outstandings.packets.size());
  verifyCorrectness(conn, 0, stream, *buf);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _))
      .Times(NumFullPackets + 1)
      .WillRepeatedly(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(NumFullPackets + 1, conn.outstandings.packets.size());
  verifyCorrectness(conn, 0, stream, *buf);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteMultipleTimes) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  size_t originalWriteOffset =
      conn.streamManager->findStream(stream)->currentWriteOffset;
  verifyCorrectness(conn, 0, stream, *buf);

  conn.outstandings.reset();
  conn.streamManager->findStream(stream)->retransmissionBuffer.clear();
  buf = buildRandomInputData(50);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  verifyCorrectness(conn, originalWriteOffset, stream, *buf);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteMultipleStreams) {
  // Testing writing to multiple streams
  auto s1 = transport_->createBidirectionalStream().value();
  auto s2 = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(s1, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, s1, *buf);

  auto buf2 = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(s2, buf2->clone(), false);
  loopForWrites();
  verifyCorrectness(conn, 0, s2, *buf2);

  dropPackets(conn);

  // Should retransmit lost streams in a single packet
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  verifyCorrectness(conn, 0, s1, *buf);
  verifyCorrectness(conn, 0, s2, *buf2);
}

TEST_F(QuicTransportTest, WriteFlowControl) {
  auto& conn = transport_->getConnectionState();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Server);
  conn.qLogger = mockQLogger;

  auto streamId = transport_->createBidirectionalStream().value();
  auto stream = conn.streamManager->getStream(streamId);
  stream->flowControlState.peerAdvertisedMaxOffset = 100;
  stream->currentWriteOffset = 100;
  stream->conn.flowControlState.sumCurWriteOffset = 100;
  stream->conn.flowControlState.peerAdvertisedMaxOffset = 220;
  EXPECT_CALL(*mockQLogger, addTransportStateUpdate(getFlowControlEvent(100)));
  EXPECT_CALL(*mockQLogger, addTransportStateUpdate(getFlowControlEvent(220)));

  auto buf = buildRandomInputData(150);
  folly::IOBuf passedIn;
  // Write stream blocked frame
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(streamId, buf->clone(), false);

  loopForWrites();
  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  const auto& packet =
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  bool blockedFound = false;
  bool dataBlockedFound = false;
  for (auto& frame : packet.frames) {
    auto blocked = frame.asStreamDataBlockedFrame();
    auto dataBlocked = frame.asDataBlockedFrame();
    if (!blocked && !dataBlocked) {
      continue;
    }
    if (blocked) {
      EXPECT_EQ(blocked->streamId, streamId);
      blockedFound = true;
    }
  }
  EXPECT_TRUE(blockedFound);
  EXPECT_FALSE(dataBlockedFound);
  conn.outstandings.reset();

  // Stream flow control
  auto buf1 = buf->clone();
  buf1->trimEnd(50);
  stream->flowControlState.peerAdvertisedMaxOffset = 200;
  EXPECT_CALL(*mockQLogger, addTransportStateUpdate(getFlowControlEvent(200)));
  conn.streamManager->updateWritableStreams(*stream);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  verifyCorrectness(conn, 100, streamId, *buf1, false, false);

  // Connection flow controled
  auto num_outstandings = conn.outstandings.packets.size();
  stream->flowControlState.peerAdvertisedMaxOffset = 300;
  conn.streamManager->updateWritableStreams(*stream);
  EXPECT_CALL(*socket_, write(_, _)).Times(2).WillRepeatedly(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  auto buf2 = buf->clone();
  buf2->trimEnd(30);
  verifyCorrectness(conn, 100, streamId, *buf2, false, false);

  // Verify that there is one Data Blocked frame emitted.
  EXPECT_EQ(conn.outstandings.packets.size(), num_outstandings + 2);
  const auto& packet2 =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  dataBlockedFound = false;
  for (auto& frame : packet2.frames) {
    auto dataBlocked = frame.asDataBlockedFrame();
    if (!dataBlocked) {
      continue;
    }
    EXPECT_FALSE(dataBlockedFound);
    EXPECT_EQ(dataBlocked->dataLimit, 220);
    dataBlockedFound = true;
  }
  EXPECT_TRUE(dataBlockedFound);

  // Try again, verify that there should not be any Data blocked frame emitted
  // again.
  EXPECT_CALL(*socket_, write(_, _)).Times(0);
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);

  // Flow control lifted
  stream->conn.flowControlState.peerAdvertisedMaxOffset = 300;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  verifyCorrectness(conn, 100, streamId, *buf, false, false);
}

TEST_F(QuicTransportTest, WriteErrorEagain) {
  // Test network error
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(SetErrnoAndReturn(EAGAIN, -1));
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
}

TEST_F(QuicTransportTest, WriteErrorBad) {
  // Test network error
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(SetErrnoAndReturn(EBADF, -1));
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  EXPECT_TRUE(transport_->closed);
}

TEST_F(QuicTransportTest, WriteInvalid) {
  // Test writing to invalid stream
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  auto res = transport_->writeChain(stream + 2, buf->clone(), false);
  loopForWrites();
  EXPECT_EQ(LocalErrorCode::STREAM_NOT_EXISTS, res.error());
}

TEST_F(QuicTransportTest, WriteFin) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), true);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf, true);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  verifyCorrectness(conn, 0, stream, *buf, true);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteOnlyFin) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, nullptr, true);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf, true);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  verifyCorrectness(conn, 0, stream, *buf, true);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteDataWithRetransmission) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf);

  dropPackets(conn);
  auto buf2 = buildRandomInputData(50);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf2->clone(), false);
  loopForWrites();
  // The first packet was lost. We should expect this packet contains both
  // lost data and new data
  buf->appendChain(std::move(buf2));
  verifyCorrectness(conn, 0, stream, *buf);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteImmediateAcks) {
  auto& conn = transport_->getConnectionState();
  PacketNum start = 10;
  PacketNum end = 15;
  conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
  addAckStatesWithCurrentTimestamps(conn.ackStates.appDataAckState, start, end);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_TRUE(conn.outstandings.packets.empty());
  EXPECT_EQ(conn.ackStates.appDataAckState.largestAckScheduled, end);
  EXPECT_FALSE(conn.ackStates.appDataAckState.needsToSendAckImmediately);
  EXPECT_EQ(0, conn.ackStates.appDataAckState.numNonRxPacketsRecvd);
  EXPECT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WritePendingAckIfHavingData) {
  auto& conn = transport_->getConnectionState();
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  PacketNum start = 10;
  PacketNum end = 15;
  addAckStatesWithCurrentTimestamps(conn.ackStates.appDataAckState, start, end);
  conn.ackStates.appDataAckState.needsToSendAckImmediately = false;
  conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  // We should write acks if there is data pending
  transport_->writeChain(streamId, buf->clone(), true);
  loopForWrites();
  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  auto& packet =
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  EXPECT_GE(packet.frames.size(), 2);

  bool ackFound = false;
  for (auto& frame : packet.frames) {
    auto ackFrame = frame.asWriteAckFrame();
    if (!ackFrame) {
      continue;
    }
    EXPECT_EQ(ackFrame->ackBlocks.size(), 1);
    EXPECT_EQ(ackFrame->ackBlocks.front().start, start);
    EXPECT_EQ(ackFrame->ackBlocks.front().end, end);
    ackFound = true;
  }
  EXPECT_TRUE(ackFound);
  EXPECT_EQ(conn.ackStates.appDataAckState.largestAckScheduled, end);

  // Verify ack state after writing
  auto pnSpace = packet.header.getPacketNumberSpace();
  auto ackState = getAckState(conn, pnSpace);
  EXPECT_EQ(ackState.largestAckScheduled, end);
  EXPECT_FALSE(ackState.needsToSendAckImmediately);
  EXPECT_EQ(0, ackState.numNonRxPacketsRecvd);
}

TEST_F(QuicTransportTest, RstStream) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_GE(packet.frames.size(), 1);
  bool rstFound = false;
  for (auto& frame : packet.frames) {
    auto rstFrame = frame.asRstStreamFrame();
    if (!rstFrame) {
      continue;
    }
    EXPECT_EQ(streamId, rstFrame->streamId);
    EXPECT_EQ(0, rstFrame->offset);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, rstFrame->errorCode);
    rstFound = true;
  }
  EXPECT_TRUE(rstFound);

  auto stream =
      transport_->getConnectionState().streamManager->findStream(streamId);
  ASSERT_TRUE(stream);
  EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->writeBuffer.empty());
  EXPECT_FALSE(stream->writable());
  EXPECT_TRUE(stream->writeBuffer.empty());
  EXPECT_FALSE(writableContains(
      *transport_->getConnectionState().streamManager, stream->id));
}

TEST_F(QuicTransportTest, StopSending) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->stopSending(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_EQ(1, stripPaddingFrames(packet).frames.size());
  bool foundStopSending = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const StopSendingFrame* stopSending = simpleFrame->asStopSendingFrame();
    if (!stopSending) {
      continue;
    }
    EXPECT_EQ(streamId, stopSending->streamId);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, stopSending->errorCode);
    foundStopSending = true;
  }
  EXPECT_TRUE(foundStopSending);
}

TEST_F(QuicTransportTest, StopSendingReadCallbackDefault) {
  auto streamId = transport_->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->setReadCallback(streamId, &readCb);
  transport_->setReadCallback(streamId, nullptr);
  loopForWrites();
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_EQ(1, stripPaddingFrames(packet).frames.size());
  bool foundStopSending = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const StopSendingFrame* stopSending = simpleFrame->asStopSendingFrame();
    if (!stopSending) {
      continue;
    }
    EXPECT_EQ(streamId, stopSending->streamId);
    EXPECT_EQ(GenericApplicationErrorCode::NO_ERROR, stopSending->errorCode);
    foundStopSending = true;
  }
  EXPECT_TRUE(foundStopSending);
}

TEST_F(QuicTransportTest, StopSendingReadCallback) {
  auto streamId = transport_->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->setReadCallback(streamId, &readCb);
  transport_->setReadCallback(
      streamId, nullptr, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_EQ(1, stripPaddingFrames(packet).frames.size());
  bool foundStopSending = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const StopSendingFrame* stopSending = simpleFrame->asStopSendingFrame();
    if (!stopSending) {
      continue;
    }
    EXPECT_EQ(streamId, stopSending->streamId);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, stopSending->errorCode);
    foundStopSending = true;
  }
  EXPECT_TRUE(foundStopSending);
}

TEST_F(QuicTransportTest, StopSendingReadCallbackNone) {
  auto streamId = transport_->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb;
  transport_->setReadCallback(streamId, &readCb);
  transport_->setReadCallback(streamId, nullptr, folly::none);
  loopForWrites();
  EXPECT_EQ(0, transport_->getConnectionState().outstandings.packets.size());
}

TEST_F(QuicTransportTest, NoStopSendingReadCallback) {
  auto streamId = transport_->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb;
  transport_->setReadCallback(streamId, &readCb);
  loopForWrites();
  EXPECT_EQ(0, transport_->getConnectionState().outstandings.packets.size());
  transport_->setReadCallback(streamId, nullptr, folly::none);
}

TEST_F(QuicTransportTest, SendPathChallenge) {
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  conn.pathValidationLimiter =
      std::make_unique<PendingPathRateLimiter>(conn.udpSendPacketLen);
  transport_->updateWriteLooper(true);

  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(conn.outstandingPathValidation);
  EXPECT_FALSE(transport_->getPathValidationTimeout().isScheduled());
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(conn.outstandingPathValidation);
  EXPECT_EQ(conn.outstandingPathValidation, pathChallenge);
  EXPECT_TRUE(transport_->getPathValidationTimeout().isScheduled());

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  bool foundPathChallenge = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const PathChallengeFrame* pathChallengeFrame =
        simpleFrame->asPathChallengeFrame();
    if (!pathChallengeFrame) {
      continue;
    }
    EXPECT_EQ(*pathChallengeFrame, pathChallenge);
    foundPathChallenge = true;
  }
  EXPECT_TRUE(foundPathChallenge);
}

TEST_F(QuicTransportTest, PathValidationTimeoutExpired) {
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  conn.pathValidationLimiter =
      std::make_unique<PendingPathRateLimiter>(conn.udpSendPacketLen);
  transport_->updateWriteLooper(true);

  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(conn.outstandingPathValidation);
  EXPECT_FALSE(transport_->getPathValidationTimeout().isScheduled());
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(conn.outstandingPathValidation);
  EXPECT_EQ(conn.outstandingPathValidation, pathChallenge);
  EXPECT_TRUE(transport_->getPathValidationTimeout().isScheduled());

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());

  transport_->getPathValidationTimeout().cancelTimeout();
  transport_->getPathValidationTimeout().timeoutExpired();
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(conn.outstandingPathValidation);
  EXPECT_EQ(transport_->closeState(), CloseState::CLOSED);
  EXPECT_TRUE(conn.localConnectionError);
  EXPECT_EQ(
      conn.localConnectionError->code,
      QuicErrorCode(TransportErrorCode::INVALID_MIGRATION));
  EXPECT_EQ(conn.localConnectionError->message, "Path validation timed out");
}

TEST_F(QuicTransportTest, SendPathValidationWhileThereIsOutstandingOne) {
  auto& conn = transport_->getConnectionState();
  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  conn.pathValidationLimiter =
      std::make_unique<PendingPathRateLimiter>(conn.udpSendPacketLen);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(conn.outstandingPathValidation);
  EXPECT_EQ(conn.outstandingPathValidation, pathChallenge);
  EXPECT_TRUE(transport_->getPathValidationTimeout().isScheduled());

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());

  PathChallengeFrame pathChallenge2(456);
  transport_->getPathValidationTimeout().cancelTimeout();
  conn.pendingEvents.schedulePathValidationTimeout = false;
  conn.outstandingPathValidation = folly::none;
  conn.pendingEvents.pathChallenge = pathChallenge2;
  EXPECT_EQ(conn.pendingEvents.pathChallenge, pathChallenge2);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(conn.outstandingPathValidation);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_EQ(conn.outstandingPathValidation, pathChallenge2);
  EXPECT_TRUE(transport_->getPathValidationTimeout().isScheduled());

  EXPECT_EQ(2, transport_->getConnectionState().outstandings.packets.size());
}

TEST_F(QuicTransportTest, ClonePathChallenge) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandings.reset();
  for (auto& t : conn.lossState.lossTimes) {
    t.reset();
  }

  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  conn.pathValidationLimiter =
      std::make_unique<PendingPathRateLimiter>(conn.udpSendPacketLen);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  auto numPathChallengePackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathChallengeFrame>());
  EXPECT_EQ(numPathChallengePackets, 1);

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  EXPECT_EQ(conn.outstandings.packets.size(), 2);
  numPathChallengePackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathChallengeFrame>());

  EXPECT_EQ(numPathChallengePackets, 2);
}

TEST_F(QuicTransportTest, OnlyClonePathValidationIfOutstanding) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandings.reset();
  for (auto& t : conn.lossState.lossTimes) {
    t.reset();
  }

  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  conn.pathValidationLimiter =
      std::make_unique<PendingPathRateLimiter>(conn.udpSendPacketLen);
  transport_->updateWriteLooper(true);
  loopForWrites();

  auto numPathChallengePackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathChallengeFrame>());
  EXPECT_EQ(numPathChallengePackets, 1);

  // Reset outstandingPathValidation
  // This could happen when an endpoint migrates to an unvalidated address, and
  // then migrates back to a validated address before timer expires
  conn.outstandingPathValidation = folly::none;

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  numPathChallengePackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathChallengeFrame>());
  EXPECT_EQ(numPathChallengePackets, 1);
}

TEST_F(QuicTransportTest, ResendPathChallengeOnLoss) {
  auto& conn = transport_->getConnectionState();

  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  conn.pathValidationLimiter =
      std::make_unique<PendingPathRateLimiter>(conn.udpSendPacketLen);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;

  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  markPacketLoss(conn, packet, false);
  EXPECT_EQ(*conn.pendingEvents.pathChallenge, pathChallenge);
}

TEST_F(QuicTransportTest, DoNotResendLostPathChallengeIfNotOutstanding) {
  auto& conn = transport_->getConnectionState();

  PathChallengeFrame pathChallenge(123);
  conn.pathValidationLimiter =
      std::make_unique<PendingPathRateLimiter>(conn.udpSendPacketLen);
  conn.pendingEvents.pathChallenge = pathChallenge;
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;

  // Fire path validation timer
  transport_->getPathValidationTimeout().cancelTimeout();
  transport_->getPathValidationTimeout().timeoutExpired();

  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  markPacketLoss(conn, packet, false);
  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
}

TEST_F(QuicTransportTest, SendPathResponse) {
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  PathResponseFrame pathResponse(123);
  sendSimpleFrame(conn, pathResponse);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);

  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  bool foundPathResponse = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const PathResponseFrame* response = simpleFrame->asPathResponseFrame();
    if (!response) {
      continue;
    }
    EXPECT_EQ(*response, pathResponse);
    foundPathResponse = true;
  }
  EXPECT_TRUE(foundPathResponse);
}

TEST_F(QuicTransportTest, CloneAfterRecvReset) {
  auto& conn = transport_->getConnectionState();
  auto streamId = transport_->createBidirectionalStream().value();
  transport_->writeChain(streamId, IOBuf::create(0), true);
  loopForWrites();
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto stream = conn.streamManager->getStream(streamId);
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(0, stream->retransmissionBuffer.at(0)->data.chainLength());
  EXPECT_TRUE(stream->retransmissionBuffer.at(0)->eof);
  EXPECT_TRUE(stream->lossBuffer.empty());
  EXPECT_EQ(0, stream->writeBuffer.chainLength());
  EXPECT_EQ(1, stream->currentWriteOffset);
  EXPECT_EQ(0, *stream->finalWriteOffset);

  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  receiveRstStreamSMHandler(*stream, std::move(rstFrame));

  // This will clone twice. :/ Maybe we should change this to clone only once in
  // the future, thus the EXPECT were written with LT and LE. But it will clone
  // for sure and we shouldn't crash.
  transport_->lossTimeout().timeoutExpired();
  EXPECT_LT(1, conn.outstandings.packets.size());
  size_t cloneCounter = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      [](const auto& packet) { return packet.associatedEvent.hasValue(); });
  EXPECT_LE(1, cloneCounter);
}

TEST_F(QuicTransportTest, ClonePathResponse) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandings.reset();
  for (auto& t : conn.lossState.lossTimes) {
    t.reset();
  }

  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  PathResponseFrame pathResponse(123);
  sendSimpleFrame(conn, pathResponse);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);

  auto numPathResponsePackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathResponseFrame>());
  EXPECT_EQ(numPathResponsePackets, 1);

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  numPathResponsePackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::PathResponseFrame>());
  EXPECT_EQ(numPathResponsePackets, 1);
}

TEST_F(QuicTransportTest, DoNotResendPathResponseOnLoss) {
  auto& conn = transport_->getConnectionState();

  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  PathResponseFrame pathResponse(123);
  sendSimpleFrame(conn, pathResponse);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);

  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;

  markPacketLoss(conn, packet, false);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
}

TEST_F(QuicTransportTest, SendNewConnectionIdFrame) {
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  NewConnectionIdFrame newConnId(
      1, 0, ConnectionId({2, 4, 2, 3}), StatelessResetToken());
  sendSimpleFrame(conn, newConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  bool foundNewConnectionId = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const NewConnectionIdFrame* connIdFrame =
        simpleFrame->asNewConnectionIdFrame();
    if (!connIdFrame) {
      continue;
    }
    EXPECT_EQ(*connIdFrame, newConnId);
    foundNewConnectionId = true;
  }
  EXPECT_TRUE(foundNewConnectionId);
}

TEST_F(QuicTransportTest, CloneNewConnectionIdFrame) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandings.reset();
  for (auto& t : conn.lossState.lossTimes) {
    t.reset();
  }

  NewConnectionIdFrame newConnId(
      1, 0, ConnectionId({2, 4, 2, 3}), StatelessResetToken());
  sendSimpleFrame(conn, newConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  auto numNewConnIdPackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::NewConnectionIdFrame>());
  EXPECT_EQ(numNewConnIdPackets, 1);

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  EXPECT_EQ(conn.outstandings.packets.size(), 2);
  numNewConnIdPackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::NewConnectionIdFrame>());
  EXPECT_EQ(numNewConnIdPackets, 2);
}

TEST_F(QuicTransportTest, BusyWriteLoopDetection) {
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.writeConnectionDataPacketsLimit = 1;
  auto mockLoopDetectorCallback = std::make_unique<MockLoopDetectorCallback>();
  auto rawLoopDetectorCallback = mockLoopDetectorCallback.get();
  conn.loopDetectorCallback = std::move(mockLoopDetectorCallback);
  ASSERT_FALSE(conn.writeDebugState.needsWriteLoopDetect);
  ASSERT_EQ(0, conn.writeDebugState.currentEmptyLoopCount);
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1000));

  // There should be no data to send at this point
  transport_->updateWriteLooper(true);
  EXPECT_FALSE(conn.writeDebugState.needsWriteLoopDetect);
  EXPECT_EQ(WriteDataReason::NO_WRITE, conn.writeDebugState.writeDataReason);
  EXPECT_EQ(0, conn.writeDebugState.currentEmptyLoopCount);
  loopForWrites();

  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  transport_->writeChain(stream, buf->clone(), true);
  transport_->updateWriteLooper(true);
  EXPECT_TRUE(conn.writeDebugState.needsWriteLoopDetect);
  EXPECT_EQ(0, conn.writeDebugState.currentEmptyLoopCount);
  EXPECT_EQ(WriteDataReason::STREAM, conn.writeDebugState.writeDataReason);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Return(1000));
  loopForWrites();
  EXPECT_EQ(1, conn.outstandings.packets.size());
  EXPECT_EQ(0, conn.writeDebugState.currentEmptyLoopCount);

  // Queue a window update for a stream doesn't exist
  conn.streamManager->queueWindowUpdate(stream + 1);
  transport_->updateWriteLooper(true);
  EXPECT_TRUE(
      WriteDataReason::STREAM_WINDOW_UPDATE ==
      conn.writeDebugState.writeDataReason);
  EXPECT_CALL(*socket_, write(_, _)).Times(0);
  EXPECT_CALL(
      *rawLoopDetectorCallback,
      onSuspiciousWriteLoops(1, WriteDataReason::STREAM_WINDOW_UPDATE, _, _))
      .Times(1);
  loopForWrites();
  EXPECT_EQ(1, conn.outstandings.packets.size());
  EXPECT_EQ(1, conn.writeDebugState.currentEmptyLoopCount);

  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, ResendNewConnectionIdOnLoss) {
  auto& conn = transport_->getConnectionState();

  NewConnectionIdFrame newConnId(
      1, 0, ConnectionId({2, 4, 2, 3}), StatelessResetToken());
  sendSimpleFrame(conn, newConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  markPacketLoss(conn, packet, false);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  NewConnectionIdFrame* connIdFrame =
      conn.pendingEvents.frames.front().asNewConnectionIdFrame();
  ASSERT_NE(connIdFrame, nullptr);
  EXPECT_EQ(*connIdFrame, newConnId);
}

TEST_F(QuicTransportTest, SendRetireConnectionIdFrame) {
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  RetireConnectionIdFrame retireConnId(1);
  sendSimpleFrame(conn, retireConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  bool foundRetireConnectionId = false;
  for (auto& frame : packet.frames) {
    const QuicSimpleFrame* simpleFrame = frame.asQuicSimpleFrame();
    if (!simpleFrame) {
      continue;
    }
    const RetireConnectionIdFrame* retireFrame =
        simpleFrame->asRetireConnectionIdFrame();
    if (!retireFrame) {
      continue;
    }
    EXPECT_EQ(*retireFrame, retireConnId);
    foundRetireConnectionId = true;
  }
  EXPECT_TRUE(foundRetireConnectionId);
}

TEST_F(QuicTransportTest, CloneRetireConnectionIdFrame) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandings.reset();
  for (auto& t : conn.lossState.lossTimes) {
    t.reset();
  }

  RetireConnectionIdFrame retireConnId(1);
  sendSimpleFrame(conn, retireConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(conn.outstandings.packets.size(), 1);
  auto numRetireConnIdPackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::RetireConnectionIdFrame>());
  EXPECT_EQ(numRetireConnIdPackets, 1);

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  EXPECT_EQ(conn.outstandings.packets.size(), 2);
  numRetireConnIdPackets = std::count_if(
      conn.outstandings.packets.begin(),
      conn.outstandings.packets.end(),
      findFrameInPacketFunc<QuicSimpleFrame::Type::RetireConnectionIdFrame>());
  EXPECT_EQ(numRetireConnIdPackets, 2);
}

TEST_F(QuicTransportTest, ResendRetireConnectionIdOnLoss) {
  auto& conn = transport_->getConnectionState();

  RetireConnectionIdFrame retireConnId(1);
  sendSimpleFrame(conn, retireConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  markPacketLoss(conn, packet, false);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  RetireConnectionIdFrame* retireFrame =
      conn.pendingEvents.frames.front().asRetireConnectionIdFrame();
  ASSERT_NE(retireFrame, nullptr);
  EXPECT_EQ(*retireFrame, retireConnId);
}

TEST_F(QuicTransportTest, NonWritableStreamAPI) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  auto streamState = conn.streamManager->getStream(streamId);

  // write EOF
  transport_->writeChain(streamId, buf->clone(), true);
  loopForWrites();
  EXPECT_FALSE(streamState->writable());

  // add a streamFlowControl event
  conn.streamManager->queueFlowControlUpdated(streamState->id);
  // check that no flow control update or onConnectionWriteReady callback gets
  // called on the stream after this
  EXPECT_CALL(connCallback_, onFlowControlUpdate(streamState->id)).Times(0);
  EXPECT_CALL(writeCallback_, onStreamWriteReady(streamState->id, _)).Times(0);
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  // Check that write-side APIs return an error
  auto res2 = transport_->notifyPendingWriteOnStream(streamId, &writeCallback_);
  EXPECT_EQ(LocalErrorCode::STREAM_CLOSED, res2.error());
  auto res3 = transport_->setStreamPriority(streamId, 0, false);
  EXPECT_FALSE(res3.hasError());
}

TEST_F(QuicTransportTest, RstWrittenStream) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  transport_->writeChain(streamId, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->findStream(streamId);
  ASSERT_TRUE(stream);
  auto currentWriteOffset = stream->currentWriteOffset;

  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  // 2 packets are outstanding: one for Stream frame one for RstStream frame:
  EXPECT_EQ(2, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : packet.frames) {
    auto rstStream = frame.asRstStreamFrame();
    if (!rstStream) {
      continue;
    }
    EXPECT_EQ(streamId, rstStream->streamId);
    EXPECT_EQ(currentWriteOffset, rstStream->offset);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, rstStream->errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);

  EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->writeBuffer.empty());
  EXPECT_FALSE(stream->writable());
  EXPECT_FALSE(writableContains(
      *transport_->getConnectionState().streamManager, stream->id));
}

TEST_F(QuicTransportTest, RstStreamUDPWriteFailNonFatal) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(SetErrnoAndReturn(EAGAIN, -1));
  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : packet.frames) {
    auto rstStream = frame.asRstStreamFrame();
    if (!rstStream) {
      continue;
    }
    EXPECT_EQ(streamId, rstStream->streamId);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, rstStream->errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);

  auto stream =
      transport_->getConnectionState().streamManager->findStream(streamId);
  ASSERT_TRUE(stream);

  // Though fail to write RstStream frame to the socket, we still should mark
  // this steam unwriable and drop current writeBuffer and
  // retransmissionBuffer:
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->writeBuffer.empty());
  EXPECT_FALSE(stream->writable());
}

TEST_F(QuicTransportTest, RstStreamUDPWriteFailFatal) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _))
      .WillRepeatedly(SetErrnoAndReturn(EBADF, -1));
  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_TRUE(transport_->getConnectionState().outstandings.packets.empty());

  // Streams should be empty now since the connection will be closed.
  EXPECT_EQ(transport_->getConnectionState().streamManager->streamCount(), 0);
}

TEST_F(QuicTransportTest, WriteAfterSendRst) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  transport_->writeChain(streamId, buf->clone(), false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->findStream(streamId);
  ASSERT_TRUE(stream);
  auto currentWriteOffset = stream->currentWriteOffset;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();

  EXPECT_EQ(stream->sendState, StreamSendState::ResetSent);
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->writeBuffer.empty());
  EXPECT_FALSE(stream->writable());
  EXPECT_FALSE(writableContains(
      *transport_->getConnectionState().streamManager, stream->id));

  // Write again:
  buf = buildRandomInputData(50);
  // This shall fail:
  auto res = transport_->writeChain(streamId, buf->clone(), false);
  loopForWrites();
  EXPECT_EQ(LocalErrorCode::STREAM_CLOSED, res.error());

  // only 2 packets are outstanding: one for Stream frame one for RstStream
  // frame. The 2nd writeChain won't write anything.
  EXPECT_EQ(2, conn.outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : packet.frames) {
    auto rstFrame = frame.asRstStreamFrame();
    if (!rstFrame) {
      continue;
    }
    EXPECT_EQ(streamId, rstFrame->streamId);
    EXPECT_EQ(currentWriteOffset, rstFrame->offset);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, rstFrame->errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);

  // writeOffset isn't moved by the 2nd write:
  EXPECT_EQ(currentWriteOffset, stream->currentWriteOffset);
}

TEST_F(QuicTransportTest, DoubleReset) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  EXPECT_FALSE(
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
  loopForWrites();

  // Then reset again, which is a no-op:
  EXPECT_FALSE(
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
}

TEST_F(QuicTransportTest, WriteStreamDataSetLossAlarm) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(1);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  EXPECT_TRUE(transport_->isLossTimeoutScheduled());
}

TEST_F(QuicTransportTest, WriteAckNotSetLossAlarm) {
  auto& conn = transport_->getConnectionState();
  addAckStatesWithCurrentTimestamps(
      conn.ackStates.appDataAckState, 0 /* start */, 100 /* ind */);
  conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto res = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, res.packetsWritten); // Write one packet out
  EXPECT_FALSE(transport_->isLossTimeoutScheduled()); // no alarm scheduled
}

TEST_F(QuicTransportTest, WriteWindowUpdate) {
  auto& conn = transport_->getConnectionState();
  conn.flowControlState.windowSize = 100;
  conn.flowControlState.advertisedMaxOffset = 0;
  conn.pendingEvents.connWindowUpdate = true;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto res = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, res.packetsWritten); // Write one packet out
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  EXPECT_GE(packet.frames.size(), 1);
  bool connWindowFound = false;
  for (auto& frame : packet.frames) {
    auto connWindowUpdate = frame.asMaxDataFrame();
    if (!connWindowUpdate) {
      continue;
    }
    EXPECT_EQ(100, connWindowUpdate->maximumData);
    connWindowFound = true;
  }

  EXPECT_TRUE(connWindowFound);

  EXPECT_EQ(conn.flowControlState.advertisedMaxOffset, 100);
  conn.outstandings.reset();

  auto stream = transport_->createBidirectionalStream().value();
  auto streamState = conn.streamManager->getStream(stream);
  streamState->flowControlState.windowSize = 100;
  streamState->flowControlState.advertisedMaxOffset = 0;
  MaxStreamDataFrame frame(stream, 100);
  conn.streamManager->queueWindowUpdate(stream);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  res = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, res.packetsWritten); // Write one packet out
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto packet1 =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  const MaxStreamDataFrame* streamWindowUpdate =
      packet1.frames.front().asMaxStreamDataFrame();
  EXPECT_TRUE(streamWindowUpdate);
}

TEST_F(QuicTransportTest, FlowControlCallbacks) {
  auto stream = transport_->createBidirectionalStream().value();
  auto stream2 = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto streamState = conn.streamManager->getStream(stream);
  auto streamState2 = conn.streamManager->getStream(stream2);

  conn.streamManager->queueFlowControlUpdated(streamState->id);
  conn.streamManager->queueFlowControlUpdated(streamState2->id);
  EXPECT_CALL(connCallback_, onFlowControlUpdate(streamState->id));
  // We should be able to create streams from this callback.
  EXPECT_CALL(connCallback_, onFlowControlUpdate(streamState2->id))
      .WillOnce(Invoke([&](auto) { transport_->createBidirectionalStream(); }));
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  EXPECT_FALSE(conn.streamManager->popFlowControlUpdated().has_value());
}

TEST_F(QuicTransportTest, DeliveryCallbackClosesClosedTransport) {
  auto stream1 = transport_->createBidirectionalStream().value();
  auto buf1 = buildRandomInputData(20);
  TransportClosingDeliveryCallback dc(transport_.get(), 20);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->writeChain(stream1, buf1->clone(), true, &dc);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, DeliveryCallbackClosesTransportOnDelivered) {
  auto stream1 = transport_->createBidirectionalStream().value();
  auto buf1 = buildRandomInputData(20);
  TransportClosingDeliveryCallback dc(transport_.get(), 0);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream1, 0, &dc);
  transport_->writeChain(stream1, buf1->clone(), true);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  auto streamState = conn.streamManager->getStream(stream1);
  conn.streamManager->addDeliverable(stream1);
  folly::SocketAddress addr;
  NetworkData emptyData;
  streamState->ackedIntervals.insert(0, 19);
  // This will invoke the DeliveryClalback::onDelivered
  transport_->onNetworkData(addr, std::move(emptyData));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksNothingDelivered) {
  NiceMock<MockDeliveryCallback> mockedDeliveryCallback;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream, 1, &mockedDeliveryCallback);
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  auto streamState = conn.streamManager->getStream(stream);

  folly::SocketAddress addr;
  NetworkData emptyData;
  transport_->onNetworkData(addr, std::move(emptyData));
  streamState->ackedIntervals.insert(0, 19);

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  transport_->writeChain(stream, buf2->clone(), true);
  streamState->ackedIntervals.insert(20, 99);
  loopForWrites();

  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  NetworkData emptyData2;
  EXPECT_CALL(mockedDeliveryCallback, onDeliveryAck(stream, 1, 100us)).Times(1);
  transport_->onNetworkData(addr, std::move(emptyData2));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksAllDelivered) {
  NiceMock<MockDeliveryCallback> mockedDeliveryCallback;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream, 1, &mockedDeliveryCallback);
  transport_->writeChain(stream, buf->clone(), true);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  // Faking a delivery:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->retransmissionBuffer.clear();
  streamState->ackedIntervals.insert(0, 1);

  folly::SocketAddress addr;
  NetworkData emptyData;
  EXPECT_CALL(mockedDeliveryCallback, onDeliveryAck(stream, 1, 100us)).Times(1);
  transport_->onNetworkData(addr, std::move(emptyData));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksPartialDelivered) {
  NiceMock<MockDeliveryCallback> mockedDeliveryCallback1,
      mockedDeliveryCallback2;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream, 50, &mockedDeliveryCallback1);
  transport_->registerDeliveryCallback(stream, 150, &mockedDeliveryCallback2);
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  // Faking a delivery:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->retransmissionBuffer.clear();

  folly::SocketAddress addr;
  NetworkData emptyData;
  streamState->ackedIntervals.insert(0, 99);
  EXPECT_CALL(mockedDeliveryCallback1, onDeliveryAck(stream, 50, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData));

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  transport_->writeChain(stream, buf2->clone(), true);
  loopForWrites();
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  NetworkData emptyData2;
  streamState->ackedIntervals.insert(100, 199);
  EXPECT_CALL(mockedDeliveryCallback2, onDeliveryAck(stream, 150, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData2));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksRetxBuffer) {
  NiceMock<MockDeliveryCallback> mockedDeliveryCallback1,
      mockedDeliveryCallback2;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream, 50, &mockedDeliveryCallback1);
  transport_->registerDeliveryCallback(stream, 150, &mockedDeliveryCallback2);
  transport_->writeChain(stream, buf->clone(), false);

  loopForWrites();
  auto& conn = transport_->getConnectionState();
  // Faking a delivery and retx:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->retransmissionBuffer.clear();
  streamState->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(51),
      std::forward_as_tuple(std::make_unique<StreamBuffer>(
          folly::IOBuf::copyBuffer("But i'm not delivered yet"), 51, false)));

  folly::SocketAddress addr;
  NetworkData emptyData;
  streamState->ackedIntervals.insert(0, 49);
  EXPECT_CALL(mockedDeliveryCallback1, onDeliveryAck(stream, 50, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData));

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  transport_->writeChain(stream, buf2->clone(), true);
  loopForWrites();
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  NetworkData emptyData2;
  streamState->ackedIntervals.insert(50, 199);
  EXPECT_CALL(mockedDeliveryCallback2, onDeliveryAck(stream, 150, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData2));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksLossAndRetxBuffer) {
  NiceMock<MockDeliveryCallback> mockedDeliveryCallback1,
      mockedDeliveryCallback2, mockedDeliveryCallback3;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream, 30, &mockedDeliveryCallback1);
  transport_->registerDeliveryCallback(stream, 50, &mockedDeliveryCallback2);
  transport_->registerDeliveryCallback(stream, 150, &mockedDeliveryCallback3);
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  // Faking a delivery, retx and loss:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  streamState->retransmissionBuffer.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(51),
      std::forward_as_tuple(std::make_unique<StreamBuffer>(
          folly::IOBuf::copyBuffer("But i'm not delivered yet"), 51, false)));
  streamState->lossBuffer.emplace_back(
      folly::IOBuf::copyBuffer("And I'm lost"), 31, false);
  streamState->ackedIntervals.insert(0, 30);

  folly::SocketAddress addr;
  NetworkData emptyData;
  EXPECT_CALL(mockedDeliveryCallback1, onDeliveryAck(stream, 30, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData));

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  transport_->writeChain(stream, buf2->clone(), true);
  loopForWrites();
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  NetworkData emptyData2;
  streamState->ackedIntervals.insert(31, 199);
  EXPECT_CALL(mockedDeliveryCallback2, onDeliveryAck(stream, 50, 100us))
      .Times(1);
  EXPECT_CALL(mockedDeliveryCallback3, onDeliveryAck(stream, 150, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData2));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksSingleByte) {
  // register all possible ways to get a DeliveryCb
  //
  // applications built atop QUIC may capture both first and last byte timings,
  // which in this test are the same byte
  StrictMock<MockDeliveryCallback> writeChainDeliveryCb;
  StrictMock<MockDeliveryCallback> firstByteDeliveryCb;
  StrictMock<MockDeliveryCallback> lastByteDeliveryCb;
  StrictMock<MockDeliveryCallback> unsentByteDeliveryCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(1);
  transport_->writeChain(
      stream, buf->clone(), false /* eof */, &writeChainDeliveryCb);
  transport_->registerDeliveryCallback(stream, 0, &firstByteDeliveryCb);
  transport_->registerDeliveryCallback(stream, 0, &lastByteDeliveryCb);
  transport_->registerDeliveryCallback(stream, 1, &unsentByteDeliveryCb);

  // writeChain, first, last byte callbacks triggered after delivery
  auto& conn = transport_->getConnectionState();
  folly::SocketAddress addr;
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  NetworkData networkData;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->ackedIntervals.insert(0, 0);
  EXPECT_CALL(writeChainDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  EXPECT_CALL(firstByteDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  EXPECT_CALL(lastByteDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  transport_->onNetworkData(addr, std::move(networkData));
  Mock::VerifyAndClearExpectations(&writeChainDeliveryCb);
  Mock::VerifyAndClearExpectations(&firstByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&lastByteDeliveryCb);

  // try to set both offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteDeliveryCb, onDeliveryAck(stream, 0, _)).Times(1);
  EXPECT_CALL(lastByteDeliveryCb, onDeliveryAck(stream, 0, _)).Times(1);
  transport_->registerDeliveryCallback(stream, 0, &firstByteDeliveryCb);
  transport_->registerDeliveryCallback(stream, 0, &lastByteDeliveryCb);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&lastByteDeliveryCb);

  // unsentByteDeliveryCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(unsentByteDeliveryCb, onCanceled(stream, 1)).Times(1);
  transport_->close(folly::none);
  Mock::VerifyAndClearExpectations(&unsentByteDeliveryCb);
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksSingleByteWithFin) {
  // register all possible ways to get a DeliveryCb
  //
  // applications built atop QUIC may capture both first and last byte timings,
  // which in this test are the same byte
  StrictMock<MockDeliveryCallback> writeChainDeliveryCb;
  StrictMock<MockDeliveryCallback> firstByteDeliveryCb;
  StrictMock<MockDeliveryCallback> lastByteDeliveryCb;
  StrictMock<MockDeliveryCallback> finDeliveryCb;
  StrictMock<MockDeliveryCallback> unsentByteDeliveryCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(1);
  transport_->writeChain(
      stream, buf->clone(), true /* eof */, &writeChainDeliveryCb);
  transport_->registerDeliveryCallback(stream, 0, &firstByteDeliveryCb);
  transport_->registerDeliveryCallback(stream, 0, &lastByteDeliveryCb);
  transport_->registerDeliveryCallback(stream, 1, &finDeliveryCb);
  transport_->registerDeliveryCallback(stream, 2, &unsentByteDeliveryCb);

  // writeChain, first, last byte, fin callbacks triggered after delivery
  auto& conn = transport_->getConnectionState();
  folly::SocketAddress addr;
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  NetworkData networkData;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->ackedIntervals.insert(0, 1);
  EXPECT_CALL(writeChainDeliveryCb, onDeliveryAck(stream, 1, 100us)).Times(1);
  EXPECT_CALL(firstByteDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  EXPECT_CALL(lastByteDeliveryCb, onDeliveryAck(stream, 0, 100us)).Times(1);
  EXPECT_CALL(finDeliveryCb, onDeliveryAck(stream, 1, 100us)).Times(1);
  transport_->onNetworkData(addr, std::move(networkData));
  Mock::VerifyAndClearExpectations(&writeChainDeliveryCb);
  Mock::VerifyAndClearExpectations(&firstByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&lastByteDeliveryCb);

  // try to set all three offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteDeliveryCb, onDeliveryAck(stream, 0, _)).Times(1);
  EXPECT_CALL(lastByteDeliveryCb, onDeliveryAck(stream, 0, _)).Times(1);
  EXPECT_CALL(finDeliveryCb, onDeliveryAck(stream, 1, _)).Times(1);
  transport_->registerDeliveryCallback(stream, 0, &firstByteDeliveryCb);
  transport_->registerDeliveryCallback(stream, 0, &lastByteDeliveryCb);
  transport_->registerDeliveryCallback(stream, 1, &finDeliveryCb);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&lastByteDeliveryCb);
  Mock::VerifyAndClearExpectations(&finDeliveryCb);

  // unsentByteDeliveryCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(unsentByteDeliveryCb, onCanceled(stream, 2)).Times(1);
  transport_->close(folly::none);
  Mock::VerifyAndClearExpectations(&unsentByteDeliveryCb);
}

TEST_F(QuicTransportTest, InvokeTxCallbacksSingleByte) {
  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  StrictMock<MockByteEventCallback> pastlastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(1);
  transport_->writeChain(stream, buf->clone(), false /* eof */);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(pastlastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 1)))
      .Times(1);
  transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  transport_->registerTxCallback(stream, 0, &lastByteTxCb);
  transport_->registerTxCallback(stream, 1, &pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // first and last byte TX callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // try to set the first and last byte offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  transport_->registerTxCallback(stream, 0, &lastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  loopForWrites(); // have to loop since processed async
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // Even if we register pastlastByte again, it shouldn't trigger
  // onByteEventRegistered because this is a duplicate registration.
  EXPECT_CALL(pastlastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 1)))
      .Times(0);
  auto ret = transport_->registerTxCallback(stream, 1, &pastlastByteTxCb);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // pastlastByteTxCb::onByteEvent will never get called
  // cancel gets called instead
  // Even though we attempted to register the ByteEvent twice,  it resulted in
  // an error. So, onByteEventCanceled should be called only once.
  EXPECT_CALL(pastlastByteTxCb, onByteEventCanceled(getTxMatcher(stream, 1)))
      .Times(1);
  transport_->close(folly::none);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
}

TEST_F(QuicTransportTest, InvokeTxCallbacksSingleByteWithFin) {
  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  StrictMock<MockByteEventCallback> finTxCb;
  StrictMock<MockByteEventCallback> pastlastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(1);
  transport_->writeChain(stream, buf->clone(), true /* eof */);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(finTxCb, onByteEventRegistered(getTxMatcher(stream, 1))).Times(1);
  EXPECT_CALL(pastlastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 2)))
      .Times(1);
  transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  transport_->registerTxCallback(stream, 0, &lastByteTxCb);
  transport_->registerTxCallback(stream, 1, &finTxCb);
  transport_->registerTxCallback(stream, 2, &pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&finTxCb);

  // first, last byte, and fin TX callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(finTxCb, onByteEvent(getTxMatcher(stream, 1))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&finTxCb);

  // try to set all three offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(finTxCb, onByteEvent(getTxMatcher(stream, 1))).Times(1);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(finTxCb, onByteEventRegistered(getTxMatcher(stream, 1))).Times(1);
  transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  transport_->registerTxCallback(stream, 0, &lastByteTxCb);
  transport_->registerTxCallback(stream, 1, &finTxCb);
  loopForWrites(); // have to loop since processed async
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&finTxCb);

  // pastlastByteTxCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(pastlastByteTxCb, onByteEventCanceled(getTxMatcher(stream, 2)))
      .Times(1);
  transport_->close(folly::none);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
}

TEST_F(QuicTransportTest, InvokeTxCallbacksMultipleBytes) {
  const uint64_t streamBytes = 10;
  const uint64_t lastByte = streamBytes - 1;

  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  StrictMock<MockByteEventCallback> pastlastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(streamBytes);
  CHECK_EQ(streamBytes, buf->length());
  transport_->writeChain(stream, buf->clone(), false /* eof */);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(
      lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, lastByte)))
      .Times(1);
  EXPECT_CALL(
      pastlastByteTxCb,
      onByteEventRegistered(getTxMatcher(stream, lastByte + 1)))
      .Times(1);
  transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  transport_->registerTxCallback(stream, lastByte, &lastByteTxCb);
  transport_->registerTxCallback(stream, lastByte + 1, &pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // first and last byte TX callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, lastByte)))
      .Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // try to set the first and last byte offsets again
  // callbacks should be triggered immediately
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(
      lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, lastByte)))
      .Times(1);
  transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  transport_->registerTxCallback(stream, lastByte, &lastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, lastByte)))
      .Times(1);
  loopForWrites(); // have to loop since processed async
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // pastlastByteTxCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(
      pastlastByteTxCb, onByteEventCanceled(getTxMatcher(stream, lastByte + 1)))
      .Times(1);
  transport_->close(folly::none);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
}

TEST_F(QuicTransportTest, InvokeTxCallbacksMultipleBytesWriteRateLimited) {
  // configure connection to write one packet each round
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.writeConnectionDataPacketsLimit = 1;

  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> secondPacketByteOffsetTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  StrictMock<MockByteEventCallback> pastlastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  const uint64_t streamBytes = kDefaultUDPSendPacketLen * 4;
  const uint64_t lastByte = streamBytes - 1;
  auto buf = buildRandomInputData(streamBytes);
  CHECK_EQ(streamBytes, buf->length());
  transport_->writeChain(stream, buf->clone(), false /* eof */);

  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(
      secondPacketByteOffsetTxCb,
      onByteEventRegistered(getTxMatcher(stream, kDefaultUDPSendPacketLen * 2)))
      .Times(1);
  EXPECT_CALL(
      lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, lastByte)))
      .Times(1);
  EXPECT_CALL(
      pastlastByteTxCb,
      onByteEventRegistered(getTxMatcher(stream, lastByte + 1)))
      .Times(1);
  transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  transport_->registerTxCallback(
      stream, kDefaultUDPSendPacketLen * 2, &secondPacketByteOffsetTxCb);
  transport_->registerTxCallback(stream, lastByte, &lastByteTxCb);
  transport_->registerTxCallback(stream, lastByte + 1, &pastlastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&secondPacketByteOffsetTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);

  // first byte gets TXed on first call to loopForWrites
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);

  // second packet byte offset gets TXed on second call to loopForWrites
  EXPECT_CALL(
      secondPacketByteOffsetTxCb,
      onByteEvent(getTxMatcher(stream, kDefaultUDPSendPacketLen * 2)))
      .Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // nothing happens on third or fourth call to loopForWrites
  loopForWrites();
  loopForWrites();

  // due to overhead, last byte gets TXed on fifth call to loopForWrites
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, lastByte)))
      .Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // pastlastByteTxCb::onByteEvent will never get called
  // cancel gets called instead
  EXPECT_CALL(
      pastlastByteTxCb, onByteEventCanceled(getTxMatcher(stream, lastByte + 1)))
      .Times(1);
  transport_->close(folly::none);
  Mock::VerifyAndClearExpectations(&pastlastByteTxCb);
}

TEST_F(QuicTransportTest, InvokeTxCallbacksMultipleBytesMultipleWrites) {
  // configure connection to write one packet each round
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.writeConnectionDataPacketsLimit = 1;

  StrictMock<MockByteEventCallback> txCb1;
  StrictMock<MockByteEventCallback> txCb2;
  StrictMock<MockByteEventCallback> txCb3;
  auto stream = transport_->createBidirectionalStream().value();

  // call writeChain, writing 10 bytes
  {
    auto buf = buildRandomInputData(10);
    transport_->writeChain(stream, buf->clone(), false /* eof */);
  }
  EXPECT_CALL(txCb1, onByteEventRegistered(getTxMatcher(stream, 0))).Times(1);
  transport_->registerTxCallback(stream, 0, &txCb1);
  Mock::VerifyAndClearExpectations(&txCb1);
  EXPECT_CALL(txCb1, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb1);

  // call writeChain and write another 10 bytes
  {
    auto buf = buildRandomInputData(10);
    transport_->writeChain(stream, buf->clone(), false /* eof */);
  }
  EXPECT_CALL(txCb2, onByteEventRegistered(getTxMatcher(stream, 10))).Times(1);
  transport_->registerTxCallback(stream, 10, &txCb2);
  Mock::VerifyAndClearExpectations(&txCb2);
  EXPECT_CALL(txCb2, onByteEvent(getTxMatcher(stream, 10))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb2);

  // write the fin
  {
    auto buf = buildRandomInputData(0);
    transport_->writeChain(stream, buf->clone(), true /* eof */);
  }
  EXPECT_CALL(txCb3, onByteEventRegistered(getTxMatcher(stream, 20))).Times(1);
  transport_->registerTxCallback(stream, 20, &txCb3);
  Mock::VerifyAndClearExpectations(&txCb3);
  EXPECT_CALL(txCb3, onByteEvent(getTxMatcher(stream, 20))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb3);
}

TEST_F(
    QuicTransportTest,
    InvokeTxAndDeliveryCallbacksMultipleBytesMultipleWrites) {
  // configure connection to write one packet each round
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.writeConnectionDataPacketsLimit = 1;

  StrictMock<MockByteEventCallback> txCb1;
  StrictMock<MockByteEventCallback> txCb2;
  StrictMock<MockByteEventCallback> txCb3;

  StrictMock<MockDeliveryCallback> deliveryCb1;
  StrictMock<MockDeliveryCallback> deliveryCb2;
  StrictMock<MockDeliveryCallback> deliveryCb3;
  auto stream = transport_->createBidirectionalStream().value();

  // call writeChain, writing 10 bytes
  {
    auto buf = buildRandomInputData(10);
    transport_->writeChain(stream, buf->clone(), false /* eof */, &deliveryCb1);
  }
  EXPECT_CALL(txCb1, onByteEventRegistered(getTxMatcher(stream, 0))).Times(1);
  transport_->registerTxCallback(stream, 0, &txCb1);
  Mock::VerifyAndClearExpectations(&txCb1);
  EXPECT_CALL(txCb1, onByteEvent(getTxMatcher(stream, 0))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb1);

  // call writeChain and write another 10 bytes
  {
    auto buf = buildRandomInputData(10);
    transport_->writeChain(stream, buf->clone(), false /* eof */, &deliveryCb2);
  }
  EXPECT_CALL(txCb2, onByteEventRegistered(getTxMatcher(stream, 10))).Times(1);
  transport_->registerTxCallback(stream, 10, &txCb2);
  Mock::VerifyAndClearExpectations(&txCb2);
  EXPECT_CALL(txCb2, onByteEvent(getTxMatcher(stream, 10))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb2);

  // write the fin
  {
    auto buf = buildRandomInputData(0);
    transport_->writeChain(stream, buf->clone(), true /* eof */, &deliveryCb3);
  }
  EXPECT_CALL(txCb3, onByteEventRegistered(getTxMatcher(stream, 20))).Times(1);
  transport_->registerTxCallback(stream, 20, &txCb3);
  Mock::VerifyAndClearExpectations(&txCb3);
  EXPECT_CALL(txCb3, onByteEvent(getTxMatcher(stream, 20))).Times(1);
  loopForWrites();
  Mock::VerifyAndClearExpectations(&txCb3);

  folly::SocketAddress addr;
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  NetworkData networkData;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->ackedIntervals.insert(0, 20);
  EXPECT_CALL(deliveryCb1, onDeliveryAck(stream, 9, 100us)).Times(1);
  EXPECT_CALL(deliveryCb2, onDeliveryAck(stream, 19, 100us)).Times(1);
  EXPECT_CALL(deliveryCb3, onDeliveryAck(stream, 20, 100us)).Times(1);
  transport_->onNetworkData(addr, std::move(networkData));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnImmediate) {
  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));
  transport_->notifyPendingWriteOnConnection(&writeCallback_);
  evb_.loop();
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamImmediate) {
  auto stream = transport_->createBidirectionalStream().value();
  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream, _));
  transport_->notifyPendingWriteOnStream(stream, &writeCallback_);
  evb_.loop();

  StreamId nonExistentStream = 3;
  EXPECT_TRUE(
      transport_->notifyPendingWriteOnStream(nonExistentStream, &writeCallback_)
          .hasError());
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnAsync) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the conn flow control to have no bytes remaining.
  updateFlowControlOnWriteToStream(
      *stream, conn.flowControlState.peerAdvertisedMaxOffset);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);
  transport_->notifyPendingWriteOnConnection(&writeCallback_);
  evb_.loop();

  PacketNum num = 10;
  // Give the conn some headroom.
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnBufferFreeUpSpace) {
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable = 100;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->getStream(streamId);

  // Fill up the buffer to its limit
  updateFlowControlOnWriteToStream(*stream, 100);
  transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  // Write 10 bytes to the socket to free up space
  updateFlowControlOnWriteToSocket(*stream, 10);
  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NoPacingTimerNoPacing) {
  TransportSettings transportSettings;
  transportSettings.pacingEnabled = true;
  transport_->setTransportSettings(transportSettings);
  transport_->getConnectionState().canBePaced = true;
  EXPECT_FALSE(isConnectionPaced(transport_->getConnectionState()));
}

TEST_F(QuicTransportTest, SetPacingTimerThenEnablesPacing) {
  TransportSettings transportSettings;
  transportSettings.pacingEnabled = true;
  transport_->setPacingTimer(
      TimerHighRes::newTimer(&evb_, transportSettings.pacingTimerTickInterval));
  transport_->setTransportSettings(transportSettings);
  transport_->getConnectionState().canBePaced = true;
  EXPECT_TRUE(isConnectionPaced(transport_->getConnectionState()));
}

TEST_F(QuicTransportTest, NoPacingNoBbr) {
  TransportSettings transportSettings;
  transportSettings.defaultCongestionController = CongestionControlType::BBR;
  transportSettings.pacingEnabled = false;
  auto ccFactory = std::make_shared<DefaultCongestionControllerFactory>();
  transport_->setCongestionControllerFactory(ccFactory);
  transport_->setTransportSettings(transportSettings);
  EXPECT_FALSE(isConnectionPaced(transport_->getConnectionState()));
  EXPECT_NE(
      CongestionControlType::BBR,
      transport_->getTransportInfo().congestionControlType);
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnBufferUseTotalSpace) {
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable = 100;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->getStream(streamId);

  // Fill up the buffer to its limit
  updateFlowControlOnWriteToStream(*stream, 100);
  transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnBufferOveruseSpace) {
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable = 100;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->getStream(streamId);

  // Fill up the buffer to its limit
  updateFlowControlOnWriteToStream(*stream, 1000);
  transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(
    QuicTransportTest,
    NotifyPendingWriteConnBufferGreaterThanConnFlowWindow) {
  auto& conn = transport_->getConnectionState();
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable =
      conn.flowControlState.peerAdvertisedMaxOffset + 1;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto stream = conn.streamManager->getStream(streamId);

  // Use up the entire flow control (but not the buffer space)
  updateFlowControlOnWriteToStream(
      *stream, conn.flowControlState.peerAdvertisedMaxOffset);
  transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  // Give the conn some headroom, but don't free up any buffer space
  PacketNum num = 10;
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamAsyncConnBlocked) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the conn flow control to have no bytes remaining.
  updateFlowControlOnWriteToStream(
      *stream, conn.flowControlState.peerAdvertisedMaxOffset);

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _)).Times(0);
  transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  evb_.loop();

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _));

  PacketNum num = 10;
  // Give the conn some headroom.
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamAsyncStreamBlocked) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the stream flow control to have no bytes remaining.
  stream->currentWriteOffset = stream->flowControlState.peerAdvertisedMaxOffset;

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _)).Times(0);
  transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  evb_.loop();

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  PacketNum num = 10;
  handleStreamWindowUpdate(
      *stream, stream->flowControlState.peerAdvertisedMaxOffset + 1000, num);
  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _));
  EXPECT_CALL(connCallback_, onFlowControlUpdate(stream->id));

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnTwice) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the conn flow control to have no bytes remaining.
  updateFlowControlOnWriteToStream(
      *stream, conn.flowControlState.peerAdvertisedMaxOffset);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);
  EXPECT_FALSE(
      transport_->notifyPendingWriteOnConnection(&writeCallback_).hasError());
  evb_.loop();
  EXPECT_TRUE(
      transport_->notifyPendingWriteOnConnection(&writeCallback_).hasError());
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamTwice) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the stream flow control to have no bytes remaining.
  stream->currentWriteOffset = stream->flowControlState.peerAdvertisedMaxOffset;

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _)).Times(0);
  EXPECT_FALSE(
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_)
          .hasError());
  evb_.loop();
  EXPECT_TRUE(
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_)
          .hasError());
  evb_.loop();
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnDuringClose) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamId2 = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the conn flow control to have no bytes remaining.
  updateFlowControlOnWriteToStream(
      *stream, conn.flowControlState.peerAdvertisedMaxOffset);

  transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  transport_->notifyPendingWriteOnStream(streamId2, &writeCallback_);
  evb_.loop();

  EXPECT_CALL(writeCallback_, onStreamWriteReady(_, _))
      .WillOnce(Invoke([&](auto id, auto) {
        if (id == streamId) {
          EXPECT_CALL(writeCallback_, onStreamWriteError(streamId2, _));
        } else {
          EXPECT_CALL(writeCallback_, onStreamWriteError(streamId, _));
        }
        transport_->close(folly::none);
      }));
  PacketNum num = 10;
  // Give the conn some headroom.
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamDuringClose) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamId2 = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  auto stream2 = conn.streamManager->getStream(streamId2);
  // Artificially restrict the stream flow control to have no bytes remaining.
  stream->currentWriteOffset = stream->flowControlState.peerAdvertisedMaxOffset;
  stream2->currentWriteOffset =
      stream2->flowControlState.peerAdvertisedMaxOffset;

  transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  transport_->notifyPendingWriteOnStream(streamId2, &writeCallback_);
  evb_.loop();

  PacketNum num = 10;
  handleStreamWindowUpdate(
      *stream, stream->flowControlState.peerAdvertisedMaxOffset + 1000, num);

  EXPECT_CALL(connCallback_, onFlowControlUpdate(stream->id));
  EXPECT_CALL(writeCallback_, onStreamWriteError(streamId2, _));
  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _))
      .WillOnce(Invoke([&](auto, auto) { transport_->close(folly::none); }));
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, WriteStreamFromMiddleOfMap) {
  // Testing writing to multiple streams
  auto& conn = transport_->getConnectionState();
  auto s1 = transport_->createBidirectionalStream().value();
  auto s2 = transport_->createBidirectionalStream().value();

  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  uint64_t writableBytes = kDefaultUDPSendPacketLen - 100;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        auto res = writableBytes;
        writableBytes = 0;
        return res;
      }));

  auto stream1 = conn.streamManager->getStream(s1);
  auto buf1 = buildRandomInputData(kDefaultUDPSendPacketLen);
  writeDataToQuicStream(*stream1, buf1->clone(), false);

  auto buf2 = buildRandomInputData(kDefaultUDPSendPacketLen);
  auto stream2 = conn.streamManager->getStream(s2);
  writeDataToQuicStream(*stream2, buf2->clone(), false);

  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto& packet = *getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  EXPECT_EQ(1, packet.packet.frames.size());
  auto& frame = packet.packet.frames.front();
  const WriteStreamFrame* streamFrame = frame.asWriteStreamFrame();
  EXPECT_TRUE(streamFrame);
  EXPECT_EQ(streamFrame->streamId, s1);
  conn.outstandings.reset();

  // Start from stream2 instead of stream1
  conn.streamManager->writableStreams().setNextScheduledStream(s2);
  writableBytes = kDefaultUDPSendPacketLen - 100;

  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto& outstandingPacket2 =
      *getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  auto packet2 = stripPaddingFrames(outstandingPacket2.packet);
  EXPECT_EQ(1, packet2.frames.size());
  auto& frame2 = packet2.frames.front();
  const WriteStreamFrame* streamFrame2 = frame2.asWriteStreamFrame();
  EXPECT_TRUE(streamFrame2);
  EXPECT_EQ(streamFrame2->streamId, s2);
  conn.outstandings.reset();

  // Test wrap around
  conn.streamManager->writableStreams().setNextScheduledStream(s2);
  writableBytes = kDefaultUDPSendPacketLen;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, conn.outstandings.packets.size());
  auto& outstandingPacket3 =
      *getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  auto packet3 = stripPaddingFrames(outstandingPacket3.packet);
  EXPECT_EQ(2, packet3.frames.size());
  auto& frame3 = packet3.frames.front();
  auto& frame4 = packet3.frames.back();
  const WriteStreamFrame* streamFrame3 = frame3.asWriteStreamFrame();
  EXPECT_TRUE(streamFrame3);
  EXPECT_EQ(streamFrame3->streamId, s2);
  const WriteStreamFrame* streamFrame4 = frame4.asWriteStreamFrame();
  EXPECT_TRUE(streamFrame4);
  EXPECT_EQ(streamFrame4->streamId, s1);
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, NoStream) {
  auto& conn = transport_->getConnectionState();
  EventBase evb;
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_TRUE(conn.outstandings.packets.empty());
}

TEST_F(QuicTransportTest, CancelAckTimeout) {
  transport_->getTimer()->scheduleTimeout(
      transport_->getAckTimeout(), 1000000ms);
  EXPECT_TRUE(transport_->getAckTimeout()->isScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = false;
  transport_->onNetworkData(
      SocketAddress("::1", 10128),
      NetworkData(IOBuf::copyBuffer("MTA New York Service"), Clock::now()));
  EXPECT_FALSE(transport_->getAckTimeout()->isScheduled());
}

TEST_F(QuicTransportTest, ScheduleAckTimeout) {
  // Make srtt large so we will use kMinAckTimeout
  transport_->getConnectionState().lossState.srtt = 25000000us;
  EXPECT_FALSE(transport_->getAckTimeout()->isScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = true;
  transport_->onNetworkData(
      SocketAddress("::1", 10003),
      NetworkData(
          IOBuf::copyBuffer("Never on time, always timeout"), Clock::now()));
  EXPECT_TRUE(transport_->getAckTimeout()->isScheduled());
  EXPECT_NEAR(transport_->getAckTimeout()->getTimeRemaining().count(), 25, 5);
}

TEST_F(QuicTransportTest, ScheduleAckTimeoutFromMaxAckDelay) {
  // Make srtt large so we will use maxAckDelay
  transport_->getConnectionState().lossState.srtt = 25000000us;
  transport_->getConnectionState().ackStates.maxAckDelay = 10ms;
  EXPECT_FALSE(transport_->getAckTimeout()->isScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = true;
  transport_->onNetworkData(
      SocketAddress("::1", 10003),
      NetworkData(
          IOBuf::copyBuffer("Never on time, always timeout"), Clock::now()));
  EXPECT_TRUE(transport_->getAckTimeout()->isScheduled());
  EXPECT_NEAR(transport_->getAckTimeout()->getTimeRemaining().count(), 10, 5);
}

TEST_F(QuicTransportTest, CloseTransportCancelsAckTimeout) {
  transport_->getConnectionState().lossState.srtt = 25000000us;
  EXPECT_FALSE(transport_->getAckTimeout()->isScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = true;
  transport_->onNetworkData(
      SocketAddress("::1", 10003),
      NetworkData(
          IOBuf::copyBuffer("Never on time, always timeout"), Clock::now()));
  EXPECT_TRUE(transport_->getAckTimeout()->isScheduled());
  // We need to send some packets, otherwise loss timer won't be scheduled
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(kDefaultUDPSendPacketLen + 20);
  folly::IOBuf passedIn;
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false);
  loopForWrites();
  transport_->scheduleLossTimeout(500ms);
  EXPECT_TRUE(transport_->isLossTimeoutScheduled());

  transport_->closeNow(folly::none);
  EXPECT_FALSE(transport_->getAckTimeout()->isScheduled());
  EXPECT_FALSE(transport_->isLossTimeoutScheduled());
}

TEST_F(QuicTransportTest, DrainTimeoutExpired) {
  EXPECT_CALL(*socket_, pauseRead()).Times(1);
  EXPECT_CALL(*socket_, close()).Times(1);
  transport_->drainImmediately();
}

TEST_F(QuicTransportTest, CloseWithDrainWillKeepSocketAround) {
  EXPECT_CALL(*socket_, pauseRead()).Times(0);
  EXPECT_CALL(*socket_, close()).Times(0);
  transport_->close(folly::none);

  // Manual shut it, otherwise transport_'s dtor will shut the socket and mess
  // up the EXPECT_CALLs above
  EXPECT_CALL(*socket_, pauseRead()).Times(1);
  EXPECT_CALL(*socket_, close()).Times(1);
  transport_->drainImmediately();
}

TEST_F(QuicTransportTest, IdleTimeoutMin) {
  transport_->getConnectionState().transportSettings.idleTimeout = 60s;
  transport_->getConnectionState().peerIdleTimeout = 15s;
  transport_->setIdleTimerNow();
  EXPECT_NEAR(
      transport_->idleTimeout().getTimeRemaining().count(), 15000, 1000);
}

TEST_F(QuicTransportTest, IdleTimeoutLocalDisabled) {
  transport_->getConnectionState().transportSettings.idleTimeout = 0s;
  transport_->getConnectionState().peerIdleTimeout = 15s;
  transport_->setIdleTimerNow();
  EXPECT_FALSE(transport_->idleTimeout().isScheduled());
}

TEST_F(QuicTransportTest, IdleTimeoutPeerDisabled) {
  transport_->getConnectionState().transportSettings.idleTimeout = 60s;
  transport_->getConnectionState().peerIdleTimeout = 0s;
  transport_->setIdleTimerNow();
  ASSERT_TRUE(transport_->idleTimeout().isScheduled());
  EXPECT_NEAR(
      transport_->idleTimeout().getTimeRemaining().count(), 60000, 1000);
}

TEST_F(QuicTransportTest, PacedWriteNoDataToWrite) {
  ASSERT_EQ(
      WriteDataReason::NO_WRITE,
      shouldWriteData(transport_->getConnectionState()));
  EXPECT_CALL(*socket_, write(_, _)).Times(0);
  transport_->pacedWrite(true);
}

TEST_F(QuicTransportTest, PacingWillBurstFirst) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  conn.transportSettings.pacingEnabled = true;
  conn.canBePaced = true;
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(100));

  auto buf = buildRandomInputData(200);
  auto streamId = transport_->createBidirectionalStream().value();
  transport_->writeChain(streamId, buf->clone(), false);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Return(0));
  EXPECT_CALL(*rawPacer, updateAndGetWriteBatchSize(_))
      .WillRepeatedly(Return(1));
  transport_->pacedWrite(true);
}

TEST_F(QuicTransportTest, AlreadyScheduledPacingNoWrite) {
  transport_->setPacingTimer(TimerHighRes::newTimer(&evb_, 1ms));
  auto& conn = transport_->getConnectionState();
  conn.udpSendPacketLen = 100;
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  conn.transportSettings.pacingEnabled = true;
  conn.canBePaced = true;
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(100));

  auto buf = buildRandomInputData(200);
  auto streamId = transport_->createBidirectionalStream().value();
  transport_->writeChain(streamId, buf->clone(), false);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Return(0));
  EXPECT_CALL(*rawPacer, updateAndGetWriteBatchSize(_))
      .WillRepeatedly(Return(1));
  EXPECT_CALL(*rawPacer, getTimeUntilNextWrite(_))
      .WillRepeatedly(Return(3600000ms));
  // This will write out 100 bytes, leave 100 bytes behind. FunctionLooper will
  // schedule a pacing timeout.
  loopForWrites();

  ASSERT_NE(WriteDataReason::NO_WRITE, shouldWriteData(conn));
  EXPECT_TRUE(transport_->isPacingScheduled());
  EXPECT_CALL(*socket_, write(_, _)).Times(0);
  transport_->pacedWrite(true);
}

TEST_F(QuicTransportTest, NoScheduleIfNoNewData) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  conn.transportSettings.pacingEnabled = true;
  conn.canBePaced = true;
  auto mockPacer = std::make_unique<NiceMock<MockPacer>>();
  auto rawPacer = mockPacer.get();
  conn.pacer = std::move(mockPacer);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1000));

  auto buf = buildRandomInputData(200);
  auto streamId = transport_->createBidirectionalStream().value();
  transport_->writeChain(streamId, buf->clone(), false);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Return(0));
  EXPECT_CALL(*rawPacer, updateAndGetWriteBatchSize(_))
      .WillRepeatedly(Return(1));
  // This will write out everything. After that because there is no new data,
  // FunctionLooper won't schedule a pacing timeout.
  transport_->pacedWrite(true);

  ASSERT_EQ(WriteDataReason::NO_WRITE, shouldWriteData(conn));
  EXPECT_FALSE(transport_->isPacingScheduled());
}

TEST_F(QuicTransportTest, SaneCwndSettings) {
  TransportSettings transportSettings;
  transportSettings.minCwndInMss = 1;
  transportSettings.initCwndInMss = 0;
  transportSettings.defaultCongestionController = CongestionControlType::BBR;
  auto ccFactory = std::make_shared<DefaultCongestionControllerFactory>();
  transport_->setCongestionControllerFactory(ccFactory);
  transport_->setTransportSettings(transportSettings);
  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(
      conn.udpSendPacketLen * kInitCwndInMss,
      conn.congestionController->getCongestionWindow());
}

TEST_F(QuicTransportTest, GetStreamPackestTxedSingleByte) {
  StrictMock<MockByteEventCallback> firstByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(1);
  transport_->writeChain(stream, buf->clone(), false /* eof */);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);

  // when first byte TX callback gets invoked, numPacketsTxWithNewData should be
  // one
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0)))
      .Times(1)
      .WillOnce(Invoke([&](QuicSocket::ByteEvent /* event */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 1);
      }));
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
}

TEST_F(QuicTransportTest, GetStreamPacketsTxedMultipleBytes) {
  const uint64_t streamBytes = 10;
  const uint64_t lastByte = streamBytes - 1;

  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();

  auto buf = buildRandomInputData(streamBytes);
  CHECK_EQ(streamBytes, buf->length());
  transport_->writeChain(stream, buf->clone(), false /* eof */);
  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(
      lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, lastByte)))
      .Times(1);
  transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  transport_->registerTxCallback(stream, lastByte, &lastByteTxCb);
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // when first and last byte TX callbacsk fired, numPacketsTxWithNewData should
  // be 1
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0)))
      .Times(1)
      .WillOnce(Invoke([&](QuicSocket::ByteEvent /* event */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 1);
      }));
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, lastByte)))
      .Times(1)
      .WillOnce(Invoke([&](QuicSocket::ByteEvent /* event */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 1);
      }));
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
}

TEST_F(QuicTransportTest, GetStreamPacketsTxedMultiplePackets) {
  auto& conn = transport_->getConnectionState();
  conn.transportSettings.writeConnectionDataPacketsLimit = 1;

  const uint64_t streamBytes = kDefaultUDPSendPacketLen * 4;
  const uint64_t lastByte = streamBytes - 1;

  // 20 bytes overhead per packet should be more than enough
  const uint64_t firstPacketNearTailByte = kDefaultUDPSendPacketLen - 20;
  const uint64_t secondPacketNearHeadByte = kDefaultUDPSendPacketLen;
  const uint64_t secondPacketNearTailByte = kDefaultUDPSendPacketLen * 2 - 40;

  StrictMock<MockByteEventCallback> firstByteTxCb;
  StrictMock<MockByteEventCallback> firstPacketNearTailByteTxCb;
  StrictMock<MockByteEventCallback> secondPacketNearHeadByteTxCb;
  StrictMock<MockByteEventCallback> secondPacketNearTailByteTxCb;
  StrictMock<MockByteEventCallback> lastByteTxCb;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(streamBytes);
  CHECK_EQ(streamBytes, buf->length());
  transport_->writeChain(stream, buf->clone(), false /* eof */);

  EXPECT_CALL(firstByteTxCb, onByteEventRegistered(getTxMatcher(stream, 0)))
      .Times(1);
  EXPECT_CALL(
      firstPacketNearTailByteTxCb,
      onByteEventRegistered(getTxMatcher(stream, firstPacketNearTailByte)))
      .Times(1);
  EXPECT_CALL(
      secondPacketNearHeadByteTxCb,
      onByteEventRegistered(getTxMatcher(stream, secondPacketNearHeadByte)))
      .Times(1);
  EXPECT_CALL(
      secondPacketNearTailByteTxCb,
      onByteEventRegistered(getTxMatcher(stream, secondPacketNearTailByte)))
      .Times(1);
  EXPECT_CALL(
      lastByteTxCb, onByteEventRegistered(getTxMatcher(stream, lastByte)))
      .Times(1);
  transport_->registerTxCallback(stream, 0, &firstByteTxCb);
  transport_->registerTxCallback(
      stream, firstPacketNearTailByte, &firstPacketNearTailByteTxCb);
  transport_->registerTxCallback(
      stream, secondPacketNearHeadByte, &secondPacketNearHeadByteTxCb);
  transport_->registerTxCallback(
      stream, secondPacketNearTailByte, &secondPacketNearTailByteTxCb);
  transport_->registerTxCallback(stream, lastByte, &lastByteTxCb);

  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&firstPacketNearTailByteTxCb);
  Mock::VerifyAndClearExpectations(&secondPacketNearHeadByteTxCb);
  Mock::VerifyAndClearExpectations(&secondPacketNearTailByteTxCb);
  Mock::VerifyAndClearExpectations(&lastByteTxCb);

  // first byte and first packet last bytes get Txed on first loopForWrites
  EXPECT_CALL(firstByteTxCb, onByteEvent(getTxMatcher(stream, 0)))
      .Times(1)
      .WillOnce(Invoke([&](QuicSocket::ByteEvent /* event */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 1);
      }));
  EXPECT_CALL(
      firstPacketNearTailByteTxCb,
      onByteEvent(getTxMatcher(stream, firstPacketNearTailByte)))
      .Times(1)
      .WillOnce(Invoke([&](QuicSocket::ByteEvent /* even */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 1);
      }));
  loopForWrites();
  Mock::VerifyAndClearExpectations(&firstByteTxCb);
  Mock::VerifyAndClearExpectations(&firstPacketNearTailByteTxCb);

  // second packet should be send on the second loopForWrites
  EXPECT_CALL(
      secondPacketNearHeadByteTxCb,
      onByteEvent(getTxMatcher(stream, secondPacketNearHeadByte)))
      .Times(1)
      .WillOnce(Invoke([&](QuicSocket::ByteEvent /* even */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 2);
      }));
  EXPECT_CALL(
      secondPacketNearTailByteTxCb,
      onByteEvent(getTxMatcher(stream, secondPacketNearTailByte)))
      .Times(1)
      .WillOnce(Invoke([&](QuicSocket::ByteEvent /* even */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 2);
      }));
  loopForWrites();
  Mock::VerifyAndClearExpectations(&secondPacketNearHeadByteTxCb);
  Mock::VerifyAndClearExpectations(&secondPacketNearTailByteTxCb);

  // last byte will be sent on the fifth loopForWrites
  EXPECT_CALL(lastByteTxCb, onByteEvent(getTxMatcher(stream, lastByte)))
      .Times(1)
      .WillOnce(Invoke([&](QuicSocket::ByteEvent /* event */) {
        auto info = *transport_->getStreamTransportInfo(stream);
        EXPECT_EQ(info.numPacketsTxWithNewData, 5);
      }));
  loopForWrites();
  loopForWrites();
  loopForWrites();
  Mock::VerifyAndClearExpectations(&lastByteTxCb);
}

TEST_F(QuicTransportTest, PrioritySetAndGet) {
  auto stream = transport_->createBidirectionalStream().value();
  EXPECT_EQ(kDefaultPriority, transport_->getStreamPriority(stream).value());
  transport_->setStreamPriority(stream, 0, false);
  EXPECT_EQ(Priority(0, false), transport_->getStreamPriority(stream).value());
  auto nonExistStreamPri = transport_->getStreamPriority(stream + 4);
  EXPECT_TRUE(nonExistStreamPri.hasError());
  EXPECT_EQ(LocalErrorCode::STREAM_NOT_EXISTS, nonExistStreamPri.error());
  transport_->close(folly::none);
  auto closedConnStreamPri = transport_->getStreamPriority(stream);
  EXPECT_TRUE(closedConnStreamPri.hasError());
  EXPECT_EQ(LocalErrorCode::CONNECTION_CLOSED, closedConnStreamPri.error());
}

TEST_F(QuicTransportTest, SetDSRSenderAndWriteBufMetaIntoStream) {
  auto streamId = transport_->createBidirectionalStream().value();
  size_t bufferLength = 2000;
  BufferMeta meta(bufferLength);
  auto buf = buildRandomInputData(20);
  auto dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  transport_->setDSRPacketizationRequestSender(streamId, std::move(dsrSender));
  // Some amount of real data needs to be written first:
  transport_->writeChain(streamId, std::move(buf), false);
  transport_->writeBufMeta(streamId, meta, true);
  auto& stream =
      *transport_->getConnectionState().streamManager->findStream(streamId);
  EXPECT_GE(stream.writeBufMeta.offset, 20);
  EXPECT_EQ(stream.writeBufMeta.length, bufferLength);
  EXPECT_TRUE(stream.writeBufMeta.eof);
  EXPECT_EQ(
      *stream.finalWriteOffset,
      stream.writeBufMeta.offset + stream.writeBufMeta.length);
}

TEST_F(QuicTransportTest, WriteBufMetaWithoutRealData) {
  auto streamId = transport_->createBidirectionalStream().value();
  size_t bufferLength = 2000;
  BufferMeta meta(bufferLength);
  auto result = transport_->writeBufMeta(streamId, meta, true);
  EXPECT_TRUE(result.hasError());
}

TEST_F(QuicTransportTest, WriteBufferThenBufMetaThenEOM) {
  auto streamId = transport_->createBidirectionalStream().value();
  BufferMeta meta(500);
  auto buf = buildRandomInputData(20);
  auto dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  transport_->setDSRPacketizationRequestSender(streamId, std::move(dsrSender));
  EXPECT_TRUE(
      transport_->writeChain(streamId, std::move(buf), false).hasValue());
  EXPECT_TRUE(transport_->writeBufMeta(streamId, meta, false).hasValue());
  EXPECT_TRUE(transport_->writeChain(streamId, nullptr, true).hasValue());
}

TEST_F(QuicTransportTest, ResetDSRStream) {
  auto& conn = transport_->getConnectionState();
  auto streamId = transport_->createBidirectionalStream().value();
  BufferMeta meta(conn.udpSendPacketLen * 5);
  auto buf = buildRandomInputData(200);
  auto dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  EXPECT_CALL(*dsrSender, release()).Times(1);
  transport_->setDSRPacketizationRequestSender(streamId, std::move(dsrSender));
  EXPECT_TRUE(
      transport_->writeChain(streamId, std::move(buf), false).hasValue());
  EXPECT_TRUE(transport_->writeBufMeta(streamId, meta, false).hasValue());
  loopForWrites();
  conn.streamManager->getStream(streamId)->writeBufMeta.split(
      conn.udpSendPacketLen - 200);

  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : packet.frames) {
    auto rstStream = frame.asRstStreamFrame();
    if (!rstStream) {
      continue;
    }
    EXPECT_EQ(streamId, rstStream->streamId);
    EXPECT_GT(rstStream->offset, 200);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, rstStream->errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);
}

TEST_F(QuicTransportTest, GetSetReceiveWindowOnIncomingUnidirectionalStream) {
  auto& conn = transport_->getConnectionState();
  // Stream ID is for a peer-initiated unidirectional stream
  StreamId id = 0b110;
  uint64_t windowSize = 1500;
  auto stream = conn.streamManager->getStream(id);
  EXPECT_FALSE(stream->writable());
  EXPECT_TRUE(stream->shouldSendFlowControl());
  auto res1 = transport_->setStreamFlowControlWindow(id, windowSize);
  EXPECT_FALSE(res1.hasError());
  EXPECT_EQ(windowSize, stream->flowControlState.windowSize);
  auto res2 = transport_->getStreamFlowControl(id);
  EXPECT_FALSE(res2.hasError());
}

TEST_F(QuicTransportTest, SetMaxPacingRateWithAndWithoutPacing) {
  auto settings = transport_->getTransportSettings();
  EXPECT_FALSE(settings.pacingEnabled);
  auto res1 = transport_->setMaxPacingRate(125000);
  EXPECT_TRUE(res1.hasError());
  EXPECT_EQ(LocalErrorCode::PACER_NOT_AVAILABLE, res1.error());
  settings.pacingEnabled = true;
  transport_->setPacingTimer(
      TimerHighRes::newTimer(&evb_, settings.pacingTimerTickInterval));
  transport_->setTransportSettings(settings);
  auto res2 = transport_->setMaxPacingRate(125000);
  EXPECT_FALSE(res2.hasError());
}

} // namespace test
} // namespace quic
