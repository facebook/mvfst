/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/codec/Types.h>
#include <quic/state/AckEvent.h>

#include <folly/io/async/test/MockTimeoutManager.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <quic/dsr/test/Mocks.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/logging/test/Mocks.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <quic/state/test/MockQuicStats.h>
#include <quic/state/test/Mocks.h>

using namespace folly::test;
using namespace testing;
using namespace folly;

namespace {
auto getOutstandingPacketMatcher(
    quic::PacketNum packetNum,
    bool lostByReorder,
    bool lostByTimeout) {
  return AllOf(
      testing::Field(
          &quic::OutstandingPacketWrapper::metadata,
          testing::Field(
              &quic::OutstandingPacketMetadata::lossReorderDistance,
              testing::Property(
                  &quic::OptionalIntegral<uint16_t>::has_value,
                  testing::Eq(lostByReorder)))),
      testing::Field(
          &quic::OutstandingPacketWrapper::metadata,
          testing::Field(
              &quic::OutstandingPacketMetadata::lossTimeoutDividend,
              testing::Property(
                  &quic::OptionalIntegral<quic::DurationRep>::has_value,
                  testing::Eq(lostByTimeout)))),
      testing::Field(
          &quic::OutstandingPacketWrapper::packet,
          testing::Field(
              &quic::RegularPacket::header,
              testing::Property(
                  &quic::PacketHeader::getPacketSequenceNum, packetNum))));
}
} // namespace

namespace quic::test {

class MockLossTimeout {
 public:
  MOCK_METHOD(void, cancelLossTimeout, ());
  MOCK_METHOD(void, scheduleLossTimeout, (std::chrono::milliseconds));
  MOCK_METHOD(bool, isLossTimeoutScheduled, ());
};

enum class PacketType {
  Initial,
  Handshake,
  ZeroRtt,
  OneRtt,
};

class QuicLossFunctionsTest : public TestWithParam<PacketNumberSpace> {
 public:
  void SetUp() override {
    aead = createNoOpAead();
    headerCipher = createNoOpHeaderCipher().value();
    quicStats_ = std::make_unique<MockQuicStats>();
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
    socket_ = std::make_unique<MockQuicSocket>();
    observerContainer_ =
        std::make_shared<SocketObserverContainer>(socket_.get());
  }

  PacketNum sendPacket(
      QuicConnectionStateBase& conn,
      TimePoint time,
      Optional<ClonedPacketIdentifier> maybeClonedPacketIdentifier,
      PacketType packetType,
      Optional<uint16_t> forcedSize = std::nullopt,
      bool isDsr = false);

  std::unique_ptr<QuicServerConnectionState> createConn() {
    auto conn = std::make_unique<QuicServerConnectionState>(
        FizzServerQuicHandshakeContext::Builder().build());
    conn->clientConnectionId = getTestConnectionId();
    conn->version = QuicVersion::MVFST;
    conn->ackStates.initialAckState->nextPacketNum = 1;
    conn->ackStates.initialAckState->nonDsrPacketSequenceNumber = 1;
    conn->ackStates.handshakeAckState->nextPacketNum = 1;
    conn->ackStates.handshakeAckState->nonDsrPacketSequenceNumber = 1;
    conn->ackStates.appDataAckState.nextPacketNum = 1;
    conn->ackStates.appDataAckState.nonDsrPacketSequenceNumber = 1;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow;
    conn->flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow;
    CHECK(
        !conn->streamManager
             ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
             .hasError());
    CHECK(!conn->streamManager
               ->setMaxLocalUnidirectionalStreams(
                   kDefaultMaxStreamsUnidirectional)
               .hasError());
    conn->statsCallback = quicStats_.get();
    // create a serverConnectionId that is different from the client connId
    // with bits for processId and workerId set to 0
    ServerConnectionIdParams params(0, 0, 0);
    conn->connIdAlgo = connIdAlgo_.get();
    conn->serverConnectionId = *connIdAlgo_->encodeConnectionId(params);
    // for canSetLossTimerForAppData()
    conn->oneRttWriteCipher = createNoOpAead();
    conn->observerContainer = observerContainer_;
    return conn;
  }

  std::unique_ptr<QuicClientConnectionState> createClientConn() {
    auto conn = std::make_unique<QuicClientConnectionState>(
        FizzClientQuicHandshakeContext::Builder().build());
    conn->clientConnectionId = getTestConnectionId();
    conn->version = QuicVersion::MVFST;
    conn->ackStates.initialAckState->nextPacketNum = 1;
    conn->ackStates.handshakeAckState->nextPacketNum = 1;
    conn->ackStates.appDataAckState.nextPacketNum = 1;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow;
    conn->flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow;
    conn->statsCallback = quicStats_.get();
    // create a serverConnectionId that is different from the client connId
    // with bits for processId and workerId set to 0
    ServerConnectionIdParams params(0, 0, 0);
    conn->serverConnectionId = *connIdAlgo_.get()->encodeConnectionId(params);
    return conn;
  }

  EventBase evb;
  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
  MockLossTimeout timeout;
  std::unique_ptr<MockQuicStats> quicStats_;
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  std::unique_ptr<MockQuicSocket> socket_;
  std::shared_ptr<SocketObserverContainer> observerContainer_;

  auto getLossPacketMatcher(
      PacketNum packetNum,
      bool lossByReorder,
      bool lossByTimeout) {
    return MockLegacyObserver::getLossPacketMatcher(
        packetNum, lossByReorder, lossByTimeout);
  }

  StreamId writeQueueContains(QuicConnectionStateBase& conn, StreamId id) {
    auto oldWriteQueue = conn.streamManager->oldWriteQueue();
    if (oldWriteQueue) {
      return oldWriteQueue->count(id);
    }
    return conn.streamManager->writeQueue().contains(
        PriorityQueue::Identifier::fromStreamID(id));
  }
};

LossVisitor testingLossMarkFunc(std::vector<PacketNum>& lostPackets) {
  return [&lostPackets](auto& /* conn */, auto& packet, bool processed)
             -> quic::Expected<void, QuicError> {
    if (!processed) {
      auto packetNum = packet.header.getPacketSequenceNum();
      lostPackets.push_back(packetNum);
    }
    return {};
  };
}

PacketNum QuicLossFunctionsTest::sendPacket(
    QuicConnectionStateBase& conn,
    TimePoint time,
    Optional<ClonedPacketIdentifier> maybeClonedPacketIdentifier,
    PacketType packetType,
    Optional<uint16_t> forcedSize,
    bool isDsr) {
  Optional<PacketHeader> header;
  switch (packetType) {
    case PacketType::Initial:
      header = LongHeader(
          LongHeader::Types::Initial,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.initialAckState->nextPacketNum,
          *conn.version);
      break;
    case PacketType::Handshake:
      header = LongHeader(
          LongHeader::Types::Handshake,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.handshakeAckState->nextPacketNum,
          *conn.version);
      break;
    case PacketType::ZeroRtt:
      header = LongHeader(
          LongHeader::Types::ZeroRtt,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.appDataAckState.nextPacketNum,
          *conn.version);
      break;
    case PacketType::OneRtt:
      header = ShortHeader(
          ProtectionType::KeyPhaseZero,
          *conn.serverConnectionId,
          conn.ackStates.appDataAckState.nextPacketNum);
      break;
  }
  PacketNumberSpace packetNumberSpace;
  auto shortHeader = header->asShort();
  if (shortHeader) {
    packetNumberSpace = shortHeader->getPacketNumberSpace();
  } else {
    packetNumberSpace = header->asLong()->getPacketNumberSpace();
  }
  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(*header),
      getAckState(conn, packetNumberSpace).largestAckedByPeer.value_or(0));
  CHECK(!builder.encodePacketHeader().hasError());
  EXPECT_TRUE(builder.canBuildPacket());
  auto packet = std::move(builder).buildPacket();
  if (forcedSize) {
    RegularSizeEnforcedPacketBuilder sizeEnforcedBuilder(
        std::move(packet), *forcedSize, aead->getCipherOverhead());
    EXPECT_TRUE(sizeEnforcedBuilder.canBuildPacket());
    packet = std::move(sizeEnforcedBuilder).buildPacket();
  }
  uint32_t encodedSize = 0;
  uint32_t encodedBodySize = 0;
  if (!packet.header.empty()) {
    encodedSize += packet.header.computeChainDataLength();
  }
  if (!packet.body.empty()) {
    encodedSize += packet.body.computeChainDataLength();
    encodedBodySize += packet.body.computeChainDataLength();
  }
  auto outstandingPacket = OutstandingPacketWrapper(
      packet.packet,
      time,
      encodedSize,
      encodedBodySize,
      encodedSize,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  outstandingPacket.maybeClonedPacketIdentifier = maybeClonedPacketIdentifier;
  conn.lossState.lastRetransmittablePacketSentTime = time;
  if (conn.congestionController) {
    conn.congestionController->onPacketSent(outstandingPacket);
  }
  if (maybeClonedPacketIdentifier) {
    conn.outstandings.clonedPacketCount[packetNumberSpace]++;
    // Simulates what the real writer does.
    auto it = std::find_if(
        conn.outstandings.packets.begin(),
        conn.outstandings.packets.end(),
        [&maybeClonedPacketIdentifier](const auto& packet) {
          auto packetNum = packet.packet.header.getPacketSequenceNum();
          auto packetNumSpace = packet.packet.header.getPacketNumberSpace();
          return packetNum == maybeClonedPacketIdentifier->packetNumber &&
              packetNumSpace == maybeClonedPacketIdentifier->packetNumberSpace;
        });
    if (it != conn.outstandings.packets.end()) {
      if (!it->maybeClonedPacketIdentifier) {
        conn.outstandings.clonedPacketIdentifiers.emplace(
            *maybeClonedPacketIdentifier);
        conn.outstandings.clonedPacketCount[packetNumberSpace]++;
        it->maybeClonedPacketIdentifier = *maybeClonedPacketIdentifier;
      }
    }
  } else {
    conn.outstandings.packetCount[packetNumberSpace]++;
  }
  conn.outstandings.packets.emplace_back(std::move(outstandingPacket));
  conn.lossState.largestSent = getNextPacketNum(conn, packetNumberSpace);
  increaseNextPacketNum(conn, packetNumberSpace, isDsr);
  conn.outstandings.packets.back().isDSRPacket = isDsr;
  if (!isDsr) {
    conn.outstandings.packets.back().nonDsrPacketSequenceNumber =
        getAckState(conn, packetNumberSpace).nonDsrPacketSequenceNumber - 1;
  }
  conn.pendingEvents.setLossDetectionAlarm = true;
  return conn.lossState.largestSent.value();
}

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

TEST_F(QuicLossFunctionsTest, AllPacketsProcessed) {
  auto conn = createConn();
  EXPECT_CALL(*quicStats_, onPTO()).Times(0);
  ClonedPacketIdentifier clonedPacketIdentifier1(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  sendPacket(*conn, Clock::now(), clonedPacketIdentifier1, PacketType::OneRtt);
  ClonedPacketIdentifier clonedPacketIdentifier2(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  sendPacket(*conn, Clock::now(), clonedPacketIdentifier2, PacketType::OneRtt);
  ClonedPacketIdentifier clonedPacketIdentifier3(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  sendPacket(*conn, Clock::now(), clonedPacketIdentifier3, PacketType::OneRtt);
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicLossFunctionsTest, HasDataToWrite) {
  auto conn = createConn();
  // There needs to be at least one outstanding packet.
  sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  conn->streamManager->addLoss(1);
  conn->pendingEvents.setLossDetectionAlarm = true;
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(2);
  EXPECT_CALL(timeout, scheduleLossTimeout(_)).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicLossFunctionsTest, ClearEarlyRetranTimer) {
  auto conn = createConn();
  // make delayUntilLoss relatively large
  conn->lossState.srtt = 1s;
  conn->lossState.lrtt = 1s;
  auto currentTime = Clock::now();
  auto firstPacketNum =
      sendPacket(*conn, currentTime, std::nullopt, PacketType::Initial);
  auto secondPacketNum =
      sendPacket(*conn, currentTime, std::nullopt, PacketType::Initial);
  ASSERT_GT(secondPacketNum, firstPacketNum);
  ASSERT_EQ(2, conn->outstandings.packets.size());
  // detectLossPackets will set lossTime on Initial space.
  auto lossVisitor = [](auto&, auto&, bool) -> quic::Expected<void, QuicError> {
    EXPECT_FALSE(true) << "Shouldn't call lossVisitor";
    return {};
  };
  auto& ackState = getAckState(*conn, PacketNumberSpace::Initial);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = secondPacketNum;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   lossVisitor,
                   Clock::now(),
                   PacketNumberSpace::Initial)
                   .hasError());
  ASSERT_TRUE(earliestLossTimer(*conn).first.has_value());
  ASSERT_EQ(PacketNumberSpace::Initial, earliestLossTimer(*conn).second);
  conn->pendingEvents.setLossDetectionAlarm = true;

  // Schedule a loss timer
  EXPECT_CALL(timeout, isLossTimeoutScheduled()).WillRepeatedly(Return(false));
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  EXPECT_CALL(timeout, scheduleLossTimeout(_)).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_EQ(
      LossState::AlarmMethod::EarlyRetransmitOrReordering,
      conn->lossState.currentAlarmMethod);

  // Ack the initial packets
  ReadAckFrame ackFrame;
  ackFrame.largestAcked = secondPacketNum;
  ackFrame.ackBlocks.emplace_back(firstPacketNum, secondPacketNum);
  // Ack won't cancel loss timer
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(0);
  ASSERT_FALSE(
      processAckFrame(
          *conn,
          PacketNumberSpace::Initial,
          ackFrame,
          [](auto&) -> quic::Expected<void, quic::QuicError> { return {}; },
          [&](auto&, auto&) -> quic::Expected<void, quic::QuicError> {
            return {};
          },
          lossVisitor,
          Clock::now())
          .hasError());

  // Send out a AppData packet that isn't retransmittable
  sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  conn->pendingEvents.setLossDetectionAlarm = false;

  // setLossDetectionAlarm will cancel loss timer, and not schedule another one.
  EXPECT_CALL(timeout, isLossTimeoutScheduled())
      .Times(1)
      .WillOnce(Return(false));
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  EXPECT_CALL(timeout, scheduleLossTimeout(_)).Times(0);
  setLossDetectionAlarm(*conn, timeout);
}

TEST_F(QuicLossFunctionsTest, TestOnLossDetectionAlarm) {
  auto conn = createConn();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  MockClock::mockNow = []() { return TimePoint(123ms); };
  std::vector<PacketNum> lostPacket;
  MockClock::mockNow = []() { return TimePoint(23ms); };
  EXPECT_CALL(*quicStats_, onPTO());
  setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
  EXPECT_EQ(LossState::AlarmMethod::PTO, conn->lossState.currentAlarmMethod);
  ASSERT_FALSE(
      onLossDetectionAlarm<MockClock>(*conn, testingLossMarkFunc(lostPacket))
          .hasError());
  EXPECT_EQ(conn->lossState.ptoCount, 1);
  EXPECT_TRUE(conn->pendingEvents.setLossDetectionAlarm);
  // PTO shouldn't mark loss
  EXPECT_TRUE(lostPacket.empty());

  MockClock::mockNow = []() { return TimePoint(3ms); };
  EXPECT_CALL(*quicStats_, onPTO());
  sendPacket(*conn, TimePoint(), std::nullopt, PacketType::OneRtt);
  setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _)).Times(0);
  ASSERT_FALSE(
      onLossDetectionAlarm<MockClock>(*conn, testingLossMarkFunc(lostPacket))
          .hasError());
  EXPECT_EQ(conn->lossState.ptoCount, 2);
  // PTO doesn't take anything out of outstandings.packets
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_TRUE(conn->pendingEvents.setLossDetectionAlarm);
  // PTO shouldn't mark loss
  EXPECT_TRUE(lostPacket.empty());
}

TEST_F(QuicLossFunctionsTest, TestOnPTOSkipProcessed) {
  auto conn = createConn();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());
  // By adding an maybeClonedPacketIdentifier that doesn't exist in the
  // outstandings.clonedPacketIdentifiers, they are all processed and will skip
  // lossVisitor
  for (auto i = 0; i < 10; i++) {
    ClonedPacketIdentifier clonedPacketIdentifier(
        PacketNumberSpace::AppData, i);
    sendPacket(*conn, TimePoint(), clonedPacketIdentifier, PacketType::OneRtt);
  }
  EXPECT_EQ(10, conn->outstandings.packets.size());
  std::vector<PacketNum> lostPackets;
  EXPECT_CALL(*rawCongestionController, onRemoveBytesFromInflight(_)).Times(0);
  EXPECT_CALL(*quicStats_, onPTO());
  auto ret = onPTOAlarm(*conn);
  EXPECT_FALSE(ret.hasError());
  EXPECT_EQ(10, conn->outstandings.packets.size());
  EXPECT_TRUE(lostPackets.empty());
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLoss) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(2);
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto buf = buildRandomInputData(20);
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());
  ASSERT_FALSE(writeDataToQuicStream(*stream2, buf->clone(), true).hasError());

  auto packetSeqNum = conn->ackStates.handshakeAckState->nextPacketNum;
  LongHeader header(
      LongHeader::Types::Handshake,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      packetSeqNum,
      *conn->version);
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());

  EXPECT_EQ(1, conn->outstandings.packets.size());
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet, false).hasError());
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream2->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream1->lossBuffer.size(), 1);
  EXPECT_EQ(stream2->lossBuffer.size(), 1);
  EXPECT_EQ(stream1->streamLossCount, 1);
  EXPECT_EQ(stream2->streamLossCount, 1);

  auto& buffer = stream1->lossBuffer.front();
  EXPECT_EQ(buffer.offset, 0);
  EXPECT_EQ(
      ByteRange(buf->data(), buf->length()), buffer.data.getHead()->getRange());
}

bool areEqual(folly::IOBuf* ptr, ChainedByteRangeHead* rch) {
  if (ptr->computeChainDataLength() != rch->chainLength()) {
    return false;
  }

  auto* chainedByteRange = rch->getHead();

  const uint8_t* currentIOBufDataPtr = ptr->data();
  const uint8_t* currentRchDataPtr = chainedByteRange->getRange().data();

  uint32_t remainingLenIOBuf = ptr->length();
  uint32_t remainingLenRch = chainedByteRange->getRange().size();

  for (uint32_t i = 0; i < rch->chainLength(); i++) {
    while (remainingLenIOBuf == 0) {
      ptr = ptr->next();
      remainingLenIOBuf = ptr->length();
      currentIOBufDataPtr = ptr->data();
    }

    while (remainingLenRch == 0) {
      chainedByteRange = chainedByteRange->getNext();
      remainingLenRch = chainedByteRange->getRange().size();
      currentRchDataPtr = chainedByteRange->getRange().data();
    }

    if (*currentIOBufDataPtr != *currentRchDataPtr) {
      return false;
    }

    remainingLenIOBuf--;
    remainingLenRch--;

    currentIOBufDataPtr++;
    currentRchDataPtr++;
  }

  return true;
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossMerge) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);

  auto buf1 = buildRandomInputData(20);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream1, buf1->clone(), false).hasError());
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(1, conn->outstandings.packets.size());

  auto buf2 = buildRandomInputData(20);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream1, buf2->clone(), false).hasError());
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(2, conn->outstandings.packets.size());

  auto& packet1 =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet1, false).hasError());
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  EXPECT_EQ(stream1->lossBuffer.size(), 1);
  EXPECT_EQ(stream1->streamLossCount, 1);
  auto& packet2 =
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet2, false).hasError());
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream1->lossBuffer.size(), 1);
  EXPECT_EQ(stream1->streamLossCount, 2);

  auto combined = buf1->clone();
  combined->appendToChain(buf2->clone());
  auto& buffer = stream1->lossBuffer.front();
  EXPECT_EQ(buffer.offset, 0);
  EXPECT_TRUE(areEqual(combined.get(), &buffer.data));
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossNoMerge) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);

  auto buf1 = buildRandomInputData(20);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream1, buf1->clone(), false).hasError());
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(1, conn->outstandings.packets.size());

  auto buf2 = buildRandomInputData(20);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream1, buf2->clone(), false).hasError());
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(2, conn->outstandings.packets.size());

  auto buf3 = buildRandomInputData(20);
  ASSERT_FALSE(
      writeDataToQuicStream(*stream1, buf3->clone(), false).hasError());
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_EQ(3, conn->outstandings.packets.size());

  auto& packet1 =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet1, false).hasError());
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 2);
  EXPECT_EQ(stream1->lossBuffer.size(), 1);
  EXPECT_EQ(stream1->streamLossCount, 1);
  auto& packet3 =
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet3, false).hasError());
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  EXPECT_EQ(stream1->lossBuffer.size(), 2);
  EXPECT_EQ(stream1->streamLossCount, 2);

  auto& buffer1 = stream1->lossBuffer[0];
  EXPECT_EQ(buffer1.offset, 0);
  EXPECT_EQ(
      ByteRange(buf1->data(), buf1->length()),
      buffer1.data.getHead()->getRange());

  auto& buffer3 = stream1->lossBuffer[1];
  EXPECT_EQ(buffer3.offset, 40);
  EXPECT_EQ(
      ByteRange(buf3->data(), buf3->length()),
      buffer3.data.getHead()->getRange());
}

TEST_F(QuicLossFunctionsTest, RetxBufferSortedAfterLoss) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();
  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto buf1 = IOBuf::copyBuffer("Worse case scenario");
  auto buf2 = IOBuf::copyBuffer("The hard problem");
  auto buf3 = IOBuf::copyBuffer("And then we had a flash of insight...");
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      socket,
      *stream,
      *buf1);
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      socket,
      *stream,
      *buf2);
  writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      socket,
      *stream,
      *buf3);
  EXPECT_EQ(3, stream->retransmissionBuffer.size());
  EXPECT_EQ(3, conn->outstandings.packets.size());
  auto& packet = conn->outstandings.packets[folly::Random::rand32() % 3];
  ASSERT_FALSE(markPacketLoss(*conn, packet.packet, false).hasError());
  EXPECT_EQ(1, stream->streamLossCount);
  EXPECT_EQ(2, stream->retransmissionBuffer.size());
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossAfterStreamReset) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(20);

  auto packet = writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      socket,
      *stream1,
      *buf,
      true);
  ASSERT_FALSE(sendRstSMHandler(*stream1, GenericApplicationErrorCode::UNKNOWN)
                   .hasError());

  ASSERT_FALSE(markPacketLoss(*conn, packet, false).hasError());

  EXPECT_TRUE(stream1->lossBuffer.empty());
  EXPECT_TRUE(stream1->retransmissionBuffer.empty());
  EXPECT_TRUE(stream1->pendingWrites.empty());
}

TEST_F(QuicLossFunctionsTest, TestReorderingThreshold) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  auto testingLossMarkFunc = [&lostPacket](auto& /*conn*/, auto& packet, bool)
      -> quic::Expected<void, quic::QuicError> {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPacket.push_back(packetNum);
    return {};
  };
  for (int i = 0; i < 6; ++i) {
    sendPacket(*conn, Clock::now(), std::nullopt, PacketType::Handshake);
  }
  EXPECT_EQ(6, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  // Assume some packets are already acked
  for (auto iter =
           getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake) + 2;
       iter <
       getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake) + 5;
       iter++) {
    conn->outstandings.packetCount[PacketNumberSpace::Handshake]--;
  }
  auto firstHandshakeOpIter =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake);
  conn->outstandings.packets.erase(
      firstHandshakeOpIter + 2, firstHandshakeOpIter + 5);
  // Ack for packet 9 arrives
  auto& ackState = getAckState(*conn, PacketNumberSpace::Handshake);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = 9;
  auto lossResult = detectLossPackets(
      *conn,
      ackState,
      testingLossMarkFunc,
      TimePoint(90ms),
      PacketNumberSpace::Handshake);
  ASSERT_FALSE(lossResult.hasError());
  auto& lossEvent = lossResult.value();
  EXPECT_EQ(2, lossEvent->largestLostPacketNum.value());
  EXPECT_EQ(TimePoint(90ms), lossEvent->lossTime);
  // Packet 1,2 should be marked as loss
  EXPECT_EQ(lostPacket.size(), 2);
  EXPECT_EQ(lostPacket.front(), 1);
  EXPECT_EQ(lostPacket.back(), 2);

  // Packet 6 is the only thing remaining inflight, it is a handshake pkt
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);

  // Packet 6 should remain in packet as the delta is less than threshold
  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(conn->outstandings.packets.size(), 1 + numDeclaredLost);
  auto first = getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake);
  auto packetNum = first->packet.header.getPacketSequenceNum();
  EXPECT_EQ(packetNum, 6);
}

TEST_F(QuicLossFunctionsTest, TestReorderingThresholdWithSkippedPacket) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  auto testingLossMarkFunc = [&lostPacket](auto& /*conn*/, auto& packet, bool)
      -> quic::Expected<void, quic::QuicError> {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPacket.push_back(packetNum);
    return {};
  };

  // Send 7 packets, with numbers 1,2,3,4,6,7,8
  // Packet sequence number 5 is skipped
  for (int i = 1; i <= 7; i++) {
    if (i == 5) {
      conn->ackStates.handshakeAckState->skippedPacketNum =
          conn->ackStates.handshakeAckState->nextPacketNum;
      increaseNextPacketNum(*conn, PacketNumberSpace::Handshake);
    }
    sendPacket(*conn, Clock::now(), std::nullopt, PacketType::Handshake);
  }

  EXPECT_EQ(7, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  // Ack for packet 8 arrives
  auto& ackState = getAckState(*conn, PacketNumberSpace::Handshake);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = 8;
  auto lossResult = detectLossPackets(
      *conn,
      ackState,
      testingLossMarkFunc,
      TimePoint(90ms),
      PacketNumberSpace::Handshake);
  ASSERT_FALSE(lossResult.hasError());
  auto& lossEvent = lossResult.value();
  EXPECT_EQ(3, lossEvent->largestLostPacketNum.value());
  EXPECT_EQ(TimePoint(90ms), lossEvent->lossTime);
  // Packets 1,2,3 should be marked as loss
  EXPECT_EQ(lostPacket.size(), 3);
  EXPECT_EQ(lostPacket.front(), 1);
  EXPECT_EQ(lostPacket.back(), 3);
  // The reorder threshold is 3. Packet 4 would have been marked lost by reorder
  // (8-3 > 4), but there is a skipped packet number in between (5), so the
  // threshold is adjusted to 4 and that means Packet 4 does not exceed the
  // reorder threshold anymore
}

TEST_F(QuicLossFunctionsTest, TestHandleAckForLoss) {
  auto conn = createConn();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Server);
  conn->qLogger = mockQLogger;
  conn->lossState.ptoCount = 100;
  conn->lossState.reorderingThreshold = 10;

  LongHeader longHeader(
      LongHeader::Types::Handshake,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      conn->ackStates.handshakeAckState->nextPacketNum++,
      conn->version.value());
  RegularQuicWritePacket outstandingRegularPacket(std::move(longHeader));
  auto now = Clock::now();
  conn->outstandings.packets.emplace_back(
      outstandingRegularPacket,
      now,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn->outstandings.packetCount[PacketNumberSpace::Handshake]++;

  bool testLossMarkFuncCalled = false;
  auto testLossMarkFunc = [&](auto& /* conn */,
                              auto&,
                              bool) -> quic::Expected<void, quic::QuicError> {
    testLossMarkFuncCalled = true;
    return {};
  };
  EXPECT_CALL(*mockQLogger, addPacketsLost(1, 0, 1));

  auto ackTime = Clock::now();
  auto ackEvent = AckEvent::Builder()
                      .setAckTime(ackTime)
                      .setAdjustedAckTime(ackTime)
                      .setAckDelay(0us)
                      .setPacketNumberSpace(PacketNumberSpace::AppData)
                      .setLargestAckedPacket(1000)
                      .build();
  ackEvent.largestNewlyAckedPacket = 1000;
  ASSERT_FALSE(
      handleAckForLoss(
          *conn, testLossMarkFunc, ackEvent, PacketNumberSpace::Handshake)
          .hasError());

  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(1, numDeclaredLost);
  EXPECT_EQ(0, conn->lossState.ptoCount);
  EXPECT_EQ(numDeclaredLost, conn->outstandings.packets.size());
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
  EXPECT_TRUE(testLossMarkFuncCalled);
}

TEST_F(QuicLossFunctionsTest, TestHandleAckedPacket) {
  auto conn = createConn();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Server);
  conn->qLogger = mockQLogger;
  conn->lossState.ptoCount = 10;
  conn->lossState.reorderingThreshold = 10;

  sendPacket(*conn, TimePoint(), std::nullopt, PacketType::OneRtt);

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = conn->lossState.largestSent.value_or(0);
  ackFrame.ackBlocks.emplace_back(
      conn->lossState.largestSent.value_or(0),
      conn->lossState.largestSent.value_or(0));

  bool testLossMarkFuncCalled = false;
  auto testLossMarkFunc = [&](auto& /* conn */,
                              auto&,
                              bool) -> quic::Expected<void, quic::QuicError> {
    testLossMarkFuncCalled = true;
    return {};
  };

  auto ackPacketVisitor = [](auto&) -> quic::Expected<void, quic::QuicError> {
    return {};
  };
  auto ackFrameVisitor =
      [&](auto&, auto&) -> quic::Expected<void, quic::QuicError> { return {}; };

  // process and remove the acked packet.
  ASSERT_FALSE(processAckFrame(
                   *conn,
                   PacketNumberSpace::AppData,
                   ackFrame,
                   ackPacketVisitor,
                   ackFrameVisitor,
                   testLossMarkFunc,
                   Clock::now())
                   .hasError());

  EXPECT_EQ(0, conn->lossState.ptoCount);
  EXPECT_TRUE(conn->outstandings.packets.empty());
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
  EXPECT_FALSE(testLossMarkFuncCalled);
  ASSERT_TRUE(conn->outstandings.packets.empty());

  setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicLossFunctionsTest, TestMarkRstLoss) {
  auto conn = createConn();
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto currentOffset = stream->currentWriteOffset;
  RstStreamFrame rstFrame(
      stream->id, GenericApplicationErrorCode::UNKNOWN, currentOffset);
  conn->pendingEvents.resets.insert({stream->id, rstFrame});
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());

  EXPECT_EQ(conn->outstandings.packets.size(), 1);
  EXPECT_TRUE(conn->pendingEvents.resets.empty());
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet, false).hasError());

  EXPECT_EQ(1, conn->pendingEvents.resets.size());
  EXPECT_TRUE(conn->pendingEvents.resets.contains(stream->id));
  auto& retxRstFrame = conn->pendingEvents.resets.at(stream->id);
  EXPECT_EQ(stream->id, retxRstFrame.streamId);
  EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, retxRstFrame.errorCode);
  EXPECT_EQ(currentOffset, retxRstFrame.finalSize);

  // write again:
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_TRUE(conn->pendingEvents.resets.empty());
  auto& packet2 =
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  bool rstFound = false;
  for (auto& frame : packet2.frames) {
    auto resetFrame = frame.asRstStreamFrame();
    if (!resetFrame) {
      continue;
    }
    EXPECT_EQ(stream->id, resetFrame->streamId);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, resetFrame->errorCode);
    EXPECT_EQ(currentOffset, resetFrame->finalSize);
    rstFound = true;
  }
  EXPECT_TRUE(rstFound);
}

TEST_F(QuicLossFunctionsTest, ReorderingThresholdChecksSamePacketNumberSpace) {
  auto conn = createConn();
  uint16_t lossVisitorCount = 0;
  auto countingLossVisitor =
      [&](auto& /* conn */,
          auto& /* packet */,
          bool processed) -> quic::Expected<void, quic::QuicError> {
    if (!processed) {
      lossVisitorCount++;
    }
    return {};
  };
  PacketNum latestSent = 0;
  for (size_t i = 0; i < conn->lossState.reorderingThreshold + 1; i++) {
    latestSent =
        sendPacket(*conn, Clock::now(), std::nullopt, PacketType::Handshake);
  }

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = latestSent + 1;

  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   countingLossVisitor,
                   Clock::now(),
                   PacketNumberSpace::AppData)
                   .hasError());
  EXPECT_EQ(0, lossVisitorCount);

  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   countingLossVisitor,
                   Clock::now(),
                   PacketNumberSpace::Handshake)
                   .hasError());
  EXPECT_GT(lossVisitorCount, 0);
}

TEST_F(QuicLossFunctionsTest, TestMarkWindowUpdateLoss) {
  auto conn = createConn();
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  conn->streamManager->queueWindowUpdate(stream->id);
  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());
  EXPECT_FALSE(conn->streamManager->hasWindowUpdates());

  EXPECT_EQ(1, conn->outstandings.packets.size());
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;

  ASSERT_FALSE(markPacketLoss(*conn, packet, false).hasError());
  EXPECT_TRUE(conn->streamManager->pendingWindowUpdate(stream->id));
}

TEST_F(QuicLossFunctionsTest, TestTimeReordering) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent = sendPacket(
        *conn, TimePoint(i * 100ms), std::nullopt, PacketType::OneRtt);
  }
  // Some packets are already acked
  conn->lossState.srtt = 400ms;
  conn->lossState.lrtt = 350ms;
  conn->outstandings.packets.erase(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5);

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent;
  auto lossEventResult = detectLossPackets(
      *conn,
      ackState,
      testingLossMarkFunc(lostPacket),
      TimePoint(900ms),
      PacketNumberSpace::AppData);
  ASSERT_FALSE(lossEventResult.hasError());
  auto& lossEvent = lossEventResult.value();
  EXPECT_EQ(2, lossEvent->largestLostPacketNum.value());
  EXPECT_EQ(TimePoint(900ms), lossEvent->lossTime);
  // Packet 1,2 should be marked as loss
  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(lostPacket.size(), 2);
  EXPECT_EQ(numDeclaredLost, lostPacket.size());
  EXPECT_EQ(lostPacket.front(), 1);
  EXPECT_EQ(lostPacket.back(), 2);

  // Packet 6, 7 should remain in outstanding packet list
  EXPECT_EQ(2 + numDeclaredLost, conn->outstandings.packets.size());
  auto packetNum = getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
                       ->packet.header.getPacketSequenceNum();
  EXPECT_EQ(packetNum, 6);
  EXPECT_TRUE(conn->lossState.lossTimes[PacketNumberSpace::AppData]);
}

TEST_F(QuicLossFunctionsTest, LossTimePreemptsCryptoTimer) {
  std::vector<PacketNum> lostPackets;
  auto conn = createConn();
  conn->lossState.srtt = 100ms;
  conn->lossState.lrtt = 100ms;
  auto expectedDelayUntilLost =
      500ms / conn->transportSettings.timeReorderingThreshDivisor;
  auto sendTime = Clock::now();
  // Send two:
  sendPacket(*conn, sendTime, std::nullopt, PacketType::Handshake);
  PacketNum second =
      sendPacket(*conn, sendTime + 1ms, std::nullopt, PacketType::Handshake);
  auto lossTime = sendTime + 50ms;

  auto& ackState = getAckState(*conn, PacketNumberSpace::Handshake);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = second;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   testingLossMarkFunc(lostPackets),
                   lossTime,
                   PacketNumberSpace::Handshake)
                   .hasError());
  EXPECT_TRUE(lostPackets.empty());
  EXPECT_TRUE(
      conn->lossState.lossTimes[PacketNumberSpace::Handshake].has_value());
  EXPECT_EQ(
      expectedDelayUntilLost + sendTime,
      conn->lossState.lossTimes[PacketNumberSpace::Handshake].value());

  MockClock::mockNow = [=]() { return sendTime; };
  auto alarm = calculateAlarmDuration<MockClock>(*conn);
  EXPECT_EQ(
      folly::chrono::ceil<std::chrono::milliseconds>(expectedDelayUntilLost),
      alarm.first);
  EXPECT_EQ(LossState::AlarmMethod::EarlyRetransmitOrReordering, alarm.second);
  // Manual set lossState. Calling setLossDetectionAlarm requires a Timeout
  conn->lossState.currentAlarmMethod = alarm.second;

  // Second packet gets acked:
  getAckState(*conn, PacketNumberSpace::Handshake).largestAckedByPeer = second;
  conn->outstandings.packets.pop_back();
  MockClock::mockNow = [=]() { return sendTime + expectedDelayUntilLost + 5s; };
  ASSERT_FALSE(
      onLossDetectionAlarm<MockClock>(*conn, testingLossMarkFunc(lostPackets))
          .hasError());
  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(1, lostPackets.size());
  EXPECT_EQ(numDeclaredLost, lostPackets.size());
  EXPECT_FALSE(
      conn->lossState.lossTimes[PacketNumberSpace::Handshake].has_value());
  EXPECT_EQ(numDeclaredLost, conn->outstandings.packets.size());
}

TEST_F(QuicLossFunctionsTest, PTONoLongerMarksPacketsToBeRetransmitted) {
  auto conn = createConn();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  TimePoint startTime(123ms);
  MockClock::mockNow = [&]() { return startTime; };
  std::vector<PacketNum> lostPackets;
  for (auto i = 0; i < kPacketToSendForPTO + 10; i++) {
    sendPacket(*conn, startTime, std::nullopt, PacketType::OneRtt);
    setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
    startTime += 1ms;
  }
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _)).Times(0);
  EXPECT_CALL(*quicStats_, onPTO());
  ASSERT_FALSE(
      onLossDetectionAlarm<MockClock>(*conn, testingLossMarkFunc(lostPackets))
          .hasError());
  EXPECT_EQ(1, conn->lossState.ptoCount);
  // Hey PTOs are not losses either from now on
  EXPECT_TRUE(lostPackets.empty());
}

TEST_F(QuicLossFunctionsTest, PTOWithHandshakePackets) {
  auto conn = createConn();
  conn->handshakeWriteCipher = createNoOpAead();
  conn->handshakeWriteHeaderCipher = createNoOpHeaderCipher().value();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Server);
  conn->qLogger = mockQLogger;
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());
  EXPECT_CALL(*mockQLogger, addLossAlarm(_, _, _, _));
  std::vector<PacketNum> lostPackets;
  PacketNum expectedLargestLostNum = 0;
  conn->lossState.currentAlarmMethod = LossState::AlarmMethod::PTO;
  for (auto i = 0; i < 10; i++) {
    // Half are handshakes
    auto sentPacketNum = sendPacket(
        *conn,
        TimePoint(100ms),
        std::nullopt,
        (i % 2 ? PacketType::OneRtt : PacketType::Handshake));
    expectedLargestLostNum = std::max(
        expectedLargestLostNum, i % 2 ? sentPacketNum : expectedLargestLostNum);
  }
  EXPECT_CALL(*quicStats_, onPTO());
  // Verify packet count doesn't change across PTO.
  auto originalPacketCount = conn->outstandings.packetCount;
  ASSERT_FALSE(
      onLossDetectionAlarm<Clock>(*conn, testingLossMarkFunc(lostPackets))
          .hasError());
  EXPECT_EQ(originalPacketCount, conn->outstandings.packetCount);

  EXPECT_EQ(0, lostPackets.size());
  EXPECT_EQ(1, conn->lossState.ptoCount);
  EXPECT_EQ(0, conn->lossState.timeoutBasedRtxCount);
  EXPECT_EQ(
      conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake],
      kPacketToSendForPTO);
  EXPECT_EQ(
      conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData],
      kPacketToSendForPTO);
  EXPECT_EQ(0, conn->lossState.rtxCount);
}

TEST_F(QuicLossFunctionsTest, PTOWithLostInitialData) {
  // Verify that lost initial data will trigger PTOs even if there are no other
  // outstanding packets.
  // The other packet number spaces have no outstanding data or losses so they
  // will have 0 probe packets.

  auto conn = createConn();

  conn->initialWriteCipher = createNoOpAead();
  conn->initialHeaderCipher = createNoOpHeaderCipher().value();
  conn->handshakeWriteCipher = createNoOpAead();
  conn->handshakeWriteHeaderCipher = createNoOpHeaderCipher().value();
  conn->oneRttWriteCipher = createNoOpAead();
  conn->oneRttWriteHeaderCipher = createNoOpHeaderCipher().value();

  auto buf = buildRandomInputData(20);
  WriteStreamBuffer initialData(ChainedByteRangeHead(buf), 0);
  conn->cryptoState->initialStream.lossBuffer.push_back(std::move(initialData));

  ASSERT_TRUE(conn->outstandings.packets.empty())
      << "There should be no outstanding packets";
  auto ret = onPTOAlarm(*conn);
  EXPECT_FALSE(ret.hasError());
  EXPECT_EQ(
      conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial],
      kPacketToSendForPTO);
  EXPECT_EQ(
      conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake], 0);
  EXPECT_EQ(conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData], 0);
}

TEST_F(QuicLossFunctionsTest, PTOWithLostHandshakeData) {
  // Verify that lost handshake data will trigger PTOs even if there are no
  // other outstanding packets.
  // The other packet number spaces have no outstanding data or losses so they
  // will have 0 probe packets.
  auto conn = createConn();

  conn->initialWriteCipher = createNoOpAead();
  conn->initialHeaderCipher = createNoOpHeaderCipher().value();
  conn->handshakeWriteCipher = createNoOpAead();
  conn->handshakeWriteHeaderCipher = createNoOpHeaderCipher().value();
  conn->oneRttWriteCipher = createNoOpAead();
  conn->oneRttWriteHeaderCipher = createNoOpHeaderCipher().value();

  auto buf = buildRandomInputData(20);
  WriteStreamBuffer handshakeData(ChainedByteRangeHead(buf), 0);
  conn->cryptoState->handshakeStream.lossBuffer.push_back(
      std::move(handshakeData));

  ASSERT_TRUE(conn->outstandings.packets.empty())
      << "There should be no outstanding packets";
  auto ret = onPTOAlarm(*conn);
  EXPECT_FALSE(ret.hasError());

  EXPECT_EQ(conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial], 0);
  EXPECT_EQ(
      conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake],
      kPacketToSendForPTO);
  EXPECT_EQ(conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData], 0);
}

TEST_F(QuicLossFunctionsTest, PTOWithLostAppData) {
  // Verify that lost app data will trigger PTOs even if there are no other
  // outstanding packets.
  // The other packet number spaces have no outstanding data or losses so they
  // will have 0 probe packets.
  auto conn = createConn();

  conn->initialWriteCipher = createNoOpAead();
  conn->initialHeaderCipher = createNoOpHeaderCipher().value();
  conn->handshakeWriteCipher = createNoOpAead();
  conn->handshakeWriteHeaderCipher = createNoOpHeaderCipher().value();
  conn->oneRttWriteCipher = createNoOpAead();
  conn->oneRttWriteHeaderCipher = createNoOpHeaderCipher().value();

  auto buf = buildRandomInputData(20);
  WriteStreamBuffer appData(ChainedByteRangeHead(buf), 0);
  conn->cryptoState->oneRttStream.lossBuffer.push_back(std::move(appData));

  ASSERT_TRUE(conn->outstandings.packets.empty())
      << "There should be no outstanding packets";
  auto ret = onPTOAlarm(*conn);
  EXPECT_FALSE(ret.hasError());

  EXPECT_EQ(conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial], 0);
  EXPECT_EQ(
      conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake], 0);
  EXPECT_EQ(
      conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData],
      kPacketToSendForPTO);
}

TEST_F(QuicLossFunctionsTest, PTOAvoidPointless) {
  // If there is no lost data and the outstanding data is less than the
  // kPacketToSendForPTO packets, send only the available outstanding count.
  auto conn = createConn();

  conn->initialWriteCipher = createNoOpAead();
  conn->initialHeaderCipher = createNoOpHeaderCipher().value();

  conn->handshakeWriteCipher = createNoOpAead();
  conn->handshakeWriteHeaderCipher = createNoOpHeaderCipher().value();

  conn->oneRttWriteCipher = createNoOpAead();
  conn->oneRttWriteHeaderCipher = createNoOpHeaderCipher().value();

  conn->outstandings.packetCount[PacketNumberSpace::Initial] = 1;
  conn->outstandings.packetCount[PacketNumberSpace::Handshake] = 1;
  conn->outstandings.packetCount[PacketNumberSpace::AppData] = 1;

  auto ret = onPTOAlarm(*conn);
  EXPECT_FALSE(ret.hasError());

  EXPECT_EQ(conn->pendingEvents.numProbePackets[PacketNumberSpace::Initial], 1);
  EXPECT_EQ(
      conn->pendingEvents.numProbePackets[PacketNumberSpace::Handshake], 1);
  EXPECT_EQ(conn->pendingEvents.numProbePackets[PacketNumberSpace::AppData], 1);
}

TEST_F(QuicLossFunctionsTest, EmptyOutstandingNoTimeout) {
  auto conn = createConn();
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  setLossDetectionAlarm(*conn, timeout);
}

TEST_F(QuicLossFunctionsTest, AlarmDurationHasLossTime) {
  auto conn = createConn();
  TimePoint lastPacketSentTime = Clock::now();
  auto thisMoment = lastPacketSentTime;
  MockClock::mockNow = [=]() { return thisMoment; };
  conn->lossState.lossTimes[PacketNumberSpace::AppData] = thisMoment + 100ms;
  conn->lossState.srtt = 200ms;
  conn->lossState.lrtt = 150ms;

  sendPacket(*conn, lastPacketSentTime, std::nullopt, PacketType::OneRtt);
  auto duration = calculateAlarmDuration<MockClock>(*conn);
  EXPECT_EQ(100ms, duration.first);
  EXPECT_EQ(
      duration.second, LossState::AlarmMethod::EarlyRetransmitOrReordering);
}

TEST_F(QuicLossFunctionsTest, AlarmDurationLossTimeIsZero) {
  // The timer could be delayed a bit, so this tests that the alarm will return
  // a timer of 0 if we are in the loss time case.
  auto conn = createConn();
  TimePoint lastPacketSentTime = Clock::now();
  auto thisMoment = lastPacketSentTime + 200ms;
  MockClock::mockNow = [=]() { return thisMoment; };
  conn->lossState.lossTimes[PacketNumberSpace::AppData] =
      lastPacketSentTime + 100ms;
  conn->lossState.srtt = 200ms;
  conn->lossState.lrtt = 150ms;

  sendPacket(*conn, lastPacketSentTime, std::nullopt, PacketType::OneRtt);
  auto duration = calculateAlarmDuration<MockClock>(*conn);
  EXPECT_EQ(0ms, duration.first);
  EXPECT_EQ(
      duration.second, LossState::AlarmMethod::EarlyRetransmitOrReordering);
}

TEST_F(QuicLossFunctionsTest, AlarmDurationNonHandshakeOutstanding) {
  auto conn = createConn();
  conn->lossState.srtt = 4ms;
  conn->lossState.rttvar = 10ms;
  conn->lossState.maxAckDelay = 25ms;
  TimePoint lastPacketSentTime = Clock::now();
  MockClock::mockNow = [=]() { return lastPacketSentTime; };
  sendPacket(*conn, lastPacketSentTime, std::nullopt, PacketType::OneRtt);
  auto duration = calculateAlarmDuration<MockClock>(*conn);
  EXPECT_EQ(duration.second, LossState::AlarmMethod::PTO);
  setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
  EXPECT_EQ(conn->lossState.currentAlarmMethod, LossState::AlarmMethod::PTO);

  conn->lossState.ptoCount = 2;
  auto newDuration = calculateAlarmDuration<MockClock>(*conn);
  EXPECT_EQ(duration.second, LossState::AlarmMethod::PTO);
  EXPECT_LT(duration.first, newDuration.first);
}

TEST_F(QuicLossFunctionsTest, NoSkipLossVisitor) {
  auto conn = createConn();
  conn->congestionController.reset();
  // make srtt large so delayUntilLost won't kick in
  conn->lossState.srtt = 1000000000us;
  uint16_t lossVisitorCount = 0;
  auto countingLossVisitor =
      [&](auto& /* conn */,
          auto& /* packet */,
          bool processed) -> quic::Expected<void, quic::QuicError> {
    if (!processed) {
      lossVisitorCount++;
    }
    return {};
  };
  // Send 5 packets, so when we ack the last one, we mark the first one loss
  PacketNum lastSent;
  for (size_t i = 0; i < 5; i++) {
    lastSent =
        sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  }

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = lastSent;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   countingLossVisitor,
                   TimePoint(100ms),
                   PacketNumberSpace::AppData)
                   .hasError());
  EXPECT_EQ(1, lossVisitorCount);
}

TEST_F(QuicLossFunctionsTest, SkipLossVisitor) {
  auto conn = createConn();
  conn->congestionController.reset();
  // make srtt large so delayUntilLost won't kick in
  conn->lossState.srtt = 1000000000us;
  uint16_t lossVisitorCount = 0;
  auto countingLossVisitor =
      [&](auto& /* conn */,
          auto& /* packet */,
          bool processed) -> quic::Expected<void, quic::QuicError> {
    if (!processed) {
      lossVisitorCount++;
    }
    return {};
  };
  // Send 5 packets, so when we ack the last one, we mark the first one loss
  PacketNum lastSent;
  for (size_t i = 0; i < 5; i++) {
    lastSent = conn->ackStates.appDataAckState.nextPacketNum;
    ClonedPacketIdentifier clonedPacketIdentifier(
        PacketNumberSpace::AppData, lastSent);
    sendPacket(*conn, Clock::now(), clonedPacketIdentifier, PacketType::OneRtt);
  }

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = lastSent;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   countingLossVisitor,
                   TimePoint(100ms),
                   PacketNumberSpace::AppData)
                   .hasError());
  EXPECT_EQ(0, lossVisitorCount);
}

TEST_F(QuicLossFunctionsTest, NoDoubleProcess) {
  auto conn = createConn();
  conn->congestionController.reset();
  // make srtt large so delayUntilLost won't kick in
  conn->lossState.srtt = 1000000000us;

  uint16_t lossVisitorCount = 0;
  auto countingLossVisitor =
      [&](auto& /* conn */,
          auto& /* packet */,
          bool processed) -> quic::Expected<void, quic::QuicError> {
    if (!processed) {
      lossVisitorCount++;
    }
    return {};
  };
  // Send 6 packets, so when we ack the last one, we mark the first two loss
  EXPECT_EQ(1, conn->ackStates.appDataAckState.nextPacketNum);
  PacketNum lastSent;
  lastSent = sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  ClonedPacketIdentifier clonedPacketIdentifier(
      PacketNumberSpace::AppData, lastSent);
  for (size_t i = 0; i < 6; i++) {
    lastSent = sendPacket(
        *conn, Clock::now(), clonedPacketIdentifier, PacketType::OneRtt);
  }
  EXPECT_EQ(7, conn->outstandings.packets.size());
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  // Add the ClonedPacketIdentifier to the outstandings.clonedPacketIdentifiers
  // set
  conn->outstandings.clonedPacketIdentifiers.insert(clonedPacketIdentifier);

  // Ack the last sent packet. Despite three losses, lossVisitor only visit one
  // packet
  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = lastSent;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   countingLossVisitor,
                   TimePoint(100ms),
                   PacketNumberSpace::AppData)
                   .hasError());
  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(3, numDeclaredLost);
  EXPECT_EQ(1, lossVisitorCount);
  EXPECT_EQ(4 + numDeclaredLost, conn->outstandings.packets.size());
}

TEST_F(QuicLossFunctionsTest, DetectPacketLossClonedPacketsCounter) {
  auto conn = createConn();
  ClonedPacketIdentifier clonedPacketIdentifier1(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  sendPacket(*conn, Clock::now(), clonedPacketIdentifier1, PacketType::OneRtt);
  sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  auto ackedPacket =
      sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  auto noopLossMarker =
      [](auto&, auto&, bool) -> quic::Expected<void, quic::QuicError> {
    return {};
  };

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = ackedPacket;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   noopLossMarker,
                   Clock::now(),
                   PacketNumberSpace::AppData)
                   .hasError());
  EXPECT_EQ(0, conn->outstandings.numClonedPackets());
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossProcessedPacket) {
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();
  ASSERT_TRUE(conn->outstandings.packets.empty());
  ASSERT_TRUE(conn->outstandings.clonedPacketIdentifiers.empty());
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto buf = folly::IOBuf::copyBuffer("I wrestled by the sea.");
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  conn->streamManager->queueWindowUpdate(stream2Id);
  conn->pendingEvents.connWindowUpdate = true;
  // writeQuicPacket will call writeQuicDataToSocket which will also take care
  // of sending the MaxStreamDataFrame for stream2
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto packet = writeQuicPacket(
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      socket,
      *stream1,
      *buf,
      true);
  EXPECT_FALSE(conn->streamManager->pendingWindowUpdate(stream2->id));
  EXPECT_FALSE(conn->pendingEvents.connWindowUpdate);
  ASSERT_EQ(1, conn->outstandings.packets.size());
  ASSERT_TRUE(conn->outstandings.clonedPacketIdentifiers.empty());
  uint32_t streamDataCounter = 0, streamWindowUpdateCounter = 0,
           connWindowUpdateCounter = 0;
  auto strippedPacket = stripPaddingFrames(
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet);
  for (const auto& frame : strippedPacket.frames) {
    switch (frame.type()) {
      case QuicWriteFrame::Type::WriteStreamFrame:
        streamDataCounter++;
        break;
      case QuicWriteFrame::Type::MaxStreamDataFrame:
        streamWindowUpdateCounter++;
        break;
      case QuicWriteFrame::Type::MaxDataFrame:
        connWindowUpdateCounter++;
        break;
      default:
        CHECK(false) << "unexpected frame=" << (int)frame.type();
    }
  }
  EXPECT_EQ(1, streamDataCounter);
  EXPECT_EQ(1, streamWindowUpdateCounter);
  EXPECT_EQ(1, connWindowUpdateCounter);
  // Force this packet to be a processed clone
  ASSERT_FALSE(markPacketLoss(*conn, packet, true).hasError());
  EXPECT_EQ(1, stream1->retransmissionBuffer.size());
  EXPECT_TRUE(stream1->lossBuffer.empty());

  // Window update though, will still be marked loss
  EXPECT_TRUE(conn->streamManager->pendingWindowUpdate(stream2->id));
  EXPECT_TRUE(conn->pendingEvents.connWindowUpdate);
}

TEST_F(QuicLossFunctionsTest, TestTotalPTOCount) {
  auto conn = createConn();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Server);
  conn->qLogger = mockQLogger;
  conn->lossState.totalPTOCount = 100;
  EXPECT_CALL(*mockQLogger, addLossAlarm(0, 1, 0, kPtoAlarm));
  EXPECT_CALL(*quicStats_, onPTO());
  auto ret = onPTOAlarm(*conn);
  EXPECT_FALSE(ret.hasError());
  EXPECT_EQ(101, conn->lossState.totalPTOCount);
}

TEST_F(QuicLossFunctionsTest, TestExceedsMaxPTOError) {
  auto conn = createConn();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Server);
  conn->qLogger = mockQLogger;
  conn->transportSettings.maxNumPTOs = 3;
  for (int i = 1; i <= 3; i++) {
    EXPECT_CALL(*mockQLogger, addLossAlarm(0, i, 0, kPtoAlarm));
  }
  EXPECT_CALL(*quicStats_, onPTO()).Times(3);
  auto ret = onPTOAlarm(*conn);
  EXPECT_FALSE(ret.hasError());
  ret = onPTOAlarm(*conn);
  EXPECT_FALSE(ret.hasError());
  ret = onPTOAlarm(*conn);
  EXPECT_TRUE(ret.hasError());
}

TEST_F(QuicLossFunctionsTest, TotalLossCount) {
  auto conn = createConn();
  conn->congestionController = nullptr;
  PacketNum largestSent = 0;
  for (int i = 0; i < 10; i++) {
    largestSent =
        sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  }
  EXPECT_EQ(10, conn->outstandings.packets.size());
  uint32_t lostPackets = 0;
  auto countingLossVisitor =
      [&](auto& /* conn */,
          auto& /* packet */,
          bool processed) -> quic::Expected<void, quic::QuicError> {
    if (!processed) {
      lostPackets++;
    }
    return {};
  };

  conn->lossState.rtxCount = 135;

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   countingLossVisitor,
                   TimePoint(100ms),
                   PacketNumberSpace::AppData)
                   .hasError());
  EXPECT_EQ(135 + lostPackets, conn->lossState.rtxCount);
}

TEST_F(QuicLossFunctionsTest, TestZeroRttRejected) {
  auto conn = createConn();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());
  // By adding an maybeClonedPacketIdentifier that doesn't exist in the
  // outstandings.clonedPacketIdentifiers, they are all processed and will skip
  // lossVisitor
  for (auto i = 0; i < 2; i++) {
    sendPacket(*conn, TimePoint(), std::nullopt, PacketType::OneRtt);
    sendPacket(*conn, TimePoint(), std::nullopt, PacketType::ZeroRtt);
  }
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(4, conn->outstandings.packets.size());
  std::vector<bool> lostPackets;
  // onRemoveBytesFromInflight should still happen
  EXPECT_CALL(*rawCongestionController, onRemoveBytesFromInflight(_)).Times(1);
  auto result = markZeroRttPacketsLost(
      *conn,
      [&lostPackets](auto&, auto&, bool processed)
          -> quic::Expected<void, quic::QuicError> {
        lostPackets.emplace_back(processed);
        return {};
      });
  ASSERT_FALSE(result.hasError());
  EXPECT_EQ(2, conn->outstandings.packets.size());
  EXPECT_EQ(lostPackets.size(), 2);
  for (auto lostPacket : lostPackets) {
    EXPECT_FALSE(lostPacket);
  }
  for (size_t i = 0; i < conn->outstandings.packets.size(); ++i) {
    auto longHeader = conn->outstandings.packets[i].packet.header.asLong();
    EXPECT_FALSE(
        longHeader &&
        longHeader->getProtectionType() == ProtectionType::ZeroRtt);
  }
  EXPECT_EQ(2, conn->lossState.rtxCount);
}

TEST_F(QuicLossFunctionsTest, TestZeroRttRejectedWithClones) {
  auto conn = createConn();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());
  // By adding an maybeClonedPacketIdentifier that doesn't exist in the
  // outstandings.clonedPacketIdentifiers, they are all processed and will skip
  // lossVisitor
  std::set<PacketNum> zeroRttPackets;
  Optional<ClonedPacketIdentifier> lastClonedPacketIdentifier;
  for (auto i = 0; i < 2; i++) {
    auto packetNum = sendPacket(
        *conn, TimePoint(), lastClonedPacketIdentifier, PacketType::ZeroRtt);
    lastClonedPacketIdentifier =
        ClonedPacketIdentifier(PacketNumberSpace::AppData, packetNum);
    zeroRttPackets.emplace(packetNum);
  }
  zeroRttPackets.emplace(
      sendPacket(*conn, TimePoint(), std::nullopt, PacketType::ZeroRtt));
  for (auto zeroRttPacketNum : zeroRttPackets) {
    ClonedPacketIdentifier zeroRttPacketEvent(
        PacketNumberSpace::AppData, zeroRttPacketNum);
    sendPacket(*conn, TimePoint(), zeroRttPacketEvent, PacketType::OneRtt);
  }

  EXPECT_EQ(6, conn->outstandings.packets.size());
  ASSERT_EQ(conn->outstandings.numClonedPackets(), 6);
  ASSERT_EQ(conn->outstandings.clonedPacketIdentifiers.size(), 2);
  ASSERT_EQ(2, conn->outstandings.packetCount[PacketNumberSpace::AppData]);

  std::vector<bool> lostPackets;
  // onRemoveBytesFromInflight should still happen
  EXPECT_CALL(*rawCongestionController, onRemoveBytesFromInflight(_)).Times(1);
  auto result = markZeroRttPacketsLost(
      *conn,
      [&lostPackets](auto&, auto&, bool processed)
          -> quic::Expected<void, quic::QuicError> {
        lostPackets.emplace_back(processed);
        return {};
      });
  ASSERT_FALSE(result.hasError());
  ASSERT_EQ(conn->outstandings.clonedPacketIdentifiers.size(), 0);
  EXPECT_EQ(3, conn->outstandings.packets.size());
  EXPECT_EQ(lostPackets.size(), 3);
  ASSERT_EQ(conn->outstandings.numClonedPackets(), 3);
  size_t numProcessed = 0;
  for (auto lostPacket : lostPackets) {
    numProcessed += lostPacket;
  }
  EXPECT_EQ(numProcessed, 1);
  for (size_t i = 0; i < conn->outstandings.packets.size(); ++i) {
    auto longHeader = conn->outstandings.packets[i].packet.header.asLong();
    EXPECT_FALSE(
        longHeader &&
        longHeader->getProtectionType() == ProtectionType::ZeroRtt);
  }
}

TEST_F(QuicLossFunctionsTest, PTOLargerThanMaxDelay) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.lossState.srtt = 1ms;
  conn.lossState.maxAckDelay = 20s;
  EXPECT_GE(calculatePTO(conn), 20s);
}

TEST_F(QuicLossFunctionsTest, InitialPTOs) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.transportSettings.initialRtt = 20ms;
  EXPECT_EQ(40ms, calculatePTO(conn));
}

TEST_F(QuicLossFunctionsTest, TimeThreshold) {
  auto conn = createConn();
  conn->lossState.srtt = 10ms;
  auto referenceTime = Clock::now();
  auto packet1 =
      sendPacket(*conn, referenceTime - 10ms, std::nullopt, PacketType::OneRtt);
  auto packet2 = sendPacket(
      *conn,
      referenceTime + conn->lossState.srtt / 2,
      std::nullopt,
      PacketType::OneRtt);
  auto lossVisitor = [&](const auto& /*conn*/,
                         const auto& packet,
                         bool) -> quic::Expected<void, quic::QuicError> {
    EXPECT_EQ(packet1, packet.header.getPacketSequenceNum());
    return {};
  };

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = packet2;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   lossVisitor,
                   referenceTime + conn->lossState.srtt * 9 / 8 + 5ms,
                   PacketNumberSpace::AppData)
                   .hasError());
}

TEST_F(QuicLossFunctionsTest, OutstandingInitialCounting) {
  auto conn = createConn();
  // Simplify the test by never triggering timer threshold
  conn->lossState.srtt = 100s;
  PacketNum largestSent = 0;
  while (largestSent < 10) {
    largestSent =
        sendPacket(*conn, Clock::now(), std::nullopt, PacketType::Initial);
  }
  EXPECT_EQ(10, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  auto noopLossVisitor =
      [&](auto& /* conn */, auto& /* packet */, bool /* processed */
          ) -> quic::Expected<void, quic::QuicError> { return {}; };

  auto& ackState = getAckState(*conn, PacketNumberSpace::Initial);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   noopLossVisitor,
                   TimePoint(100ms),
                   PacketNumberSpace::Initial)
                   .hasError());
  // [1, 6] are removed, [7, 10] are still in OP list
  EXPECT_EQ(4, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
}

TEST_F(QuicLossFunctionsTest, OutstandingHandshakeCounting) {
  auto conn = createConn();
  // Simplify the test by never triggering timer threshold
  conn->lossState.srtt = 100s;
  PacketNum largestSent = 0;
  while (largestSent < 10) {
    largestSent =
        sendPacket(*conn, Clock::now(), std::nullopt, PacketType::Handshake);
  }
  EXPECT_EQ(10, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  auto noopLossVisitor =
      [&](auto& /* conn */, auto& /* packet */, bool /* processed */
          ) -> quic::Expected<void, quic::QuicError> { return {}; };
  auto& ackState = getAckState(*conn, PacketNumberSpace::Handshake);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   noopLossVisitor,
                   TimePoint(100ms),
                   PacketNumberSpace::Handshake)
                   .hasError());
  // [1, 6] are removed, [7, 10] are still in OP list
  EXPECT_EQ(4, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
}

TEST_P(QuicLossFunctionsTest, CappedShiftNoCrash) {
  auto conn = createConn();
  conn->outstandings.reset();
  conn->lossState.ptoCount =
      std::numeric_limits<decltype(conn->lossState.ptoCount)>::max();
  sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  calculateAlarmDuration(*conn);
}

TEST_F(QuicLossFunctionsTest, PersistentCongestion) {
  // Test cases copied over from PersistentCongestion above.
  auto conn = createConn();
  auto currentTime = Clock::now();
  conn->lossState.srtt = 1s;

  auto ackTime = Clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(ackTime)
                 .setAdjustedAckTime(ackTime)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(1)
                 .build();

  EXPECT_TRUE(isPersistentCongestion(
      calculatePTO(*conn), currentTime - 10s, currentTime, ack));
  EXPECT_TRUE(isPersistentCongestion(
      calculatePTO(*conn), currentTime - 3s, currentTime, ack));
  EXPECT_TRUE(isPersistentCongestion(
      calculatePTO(*conn),
      currentTime - (1s * kPersistentCongestionThreshold),
      currentTime,
      ack));
  EXPECT_FALSE(isPersistentCongestion(
      calculatePTO(*conn),
      currentTime - (1s * kPersistentCongestionThreshold) + 1us,
      currentTime,
      ack));
  EXPECT_FALSE(isPersistentCongestion(
      calculatePTO(*conn), currentTime - 2s, currentTime, ack));
  EXPECT_FALSE(isPersistentCongestion(
      calculatePTO(*conn), currentTime - 100ms, currentTime, ack));

  conn->lossState.rttvar = 2s;
  conn->lossState.maxAckDelay = 5s;
  EXPECT_TRUE(isPersistentCongestion(
      calculatePTO(*conn), currentTime - 42s, currentTime, ack));
  EXPECT_TRUE(isPersistentCongestion(
      calculatePTO(*conn), currentTime - 43s, currentTime, ack));
  EXPECT_FALSE(isPersistentCongestion(
      calculatePTO(*conn), currentTime - 42s + 1ms, currentTime, ack));
  EXPECT_FALSE(isPersistentCongestion(
      calculatePTO(*conn), currentTime - 100us, currentTime, ack));
}

TEST_F(QuicLossFunctionsTest, PersistentCongestionAckOutsideWindow) {
  auto conn = createConn();
  auto currentTime = Clock::now();
  conn->lossState.srtt = 1s;

  const auto now = TimePoint::clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(now)
                 .setAdjustedAckTime(now)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(1)
                 .build();
  OutstandingPacketMetadata opm(
      currentTime + 12s /* sentTime */,
      0 /* encodedSize */,
      0 /* encodedBodySize */,
      0 /* totalBytesSent */,
      0 /* inflightBytes */,
      LossState() /* lossState */,
      0 /* writeCount */,
      OutstandingPacketMetadata::DetailsPerStream());
  ack.ackedPackets.push_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(1)
          .setNonDsrPacketSequenceNumber(1)
          .setOutstandingPacketMetadata(opm)
          .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
          .build());

  EXPECT_TRUE(isPersistentCongestion(
      calculatePTO(*conn), currentTime + 1s, currentTime + 8s, ack));
}

TEST_F(QuicLossFunctionsTest, PersistentCongestionAckInsideWindow) {
  auto conn = createConn();
  auto currentTime = Clock::now();
  conn->lossState.srtt = 1s;

  const auto now = TimePoint::clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(now)
                 .setAdjustedAckTime(now)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(1)
                 .build();
  OutstandingPacketMetadata opm(
      currentTime + 4s /* sentTime */,
      0 /* encodedSize */,
      0 /* encodedBodySize */,
      0 /* totalBytesSent */,
      0 /* inflightBytes */,
      LossState() /* lossState */,
      0 /* writeCount */,
      OutstandingPacketMetadata::DetailsPerStream());
  ack.ackedPackets.push_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(1)
          .setNonDsrPacketSequenceNumber(1)
          .setOutstandingPacketMetadata(opm)
          .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
          .build());

  EXPECT_FALSE(isPersistentCongestion(
      calculatePTO(*conn), currentTime + 1s, currentTime + 8s, ack));
}

TEST_F(QuicLossFunctionsTest, PersistentCongestionNoPTO) {
  auto conn = createConn();
  auto currentTime = Clock::now();

  const auto now = TimePoint::clock::now();
  auto ack = AckEvent::Builder()
                 .setAckTime(now)
                 .setAdjustedAckTime(now)
                 .setAckDelay(0us)
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(1)
                 .build();
  OutstandingPacketMetadata opm(
      currentTime + 12s /* sentTime */,
      0 /* encodedSize */,
      0 /* encodedBodySize */,
      0 /* totalBytesSent */,
      0 /* inflightBytes */,
      LossState() /* lossState */,
      0 /* writeCount */,
      OutstandingPacketMetadata::DetailsPerStream());
  ack.ackedPackets.push_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(1)
          .setNonDsrPacketSequenceNumber(1)
          .setOutstandingPacketMetadata(opm)
          .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
          .build());

  EXPECT_FALSE(isPersistentCongestion(
      std::nullopt, currentTime + 1s, currentTime + 8s, ack));
}

TEST_F(QuicLossFunctionsTest, ObserverLossEventReorder) {
  auto conn = createConn();

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::lossEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  CHECK_NOTNULL(conn->getSocketObserverContainer())->addObserver(obs1.get());

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent = sendPacket(
        *conn, TimePoint(i * 10ms), std::nullopt, PacketType::OneRtt);
  }
  // Some packets are already acked
  conn->outstandings.packets.erase(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5);

  // setting a very low reordering threshold to force loss by reorder
  conn->lossState.reorderingThreshold = 1;
  // setting time out parameters higher than the time at which detectLossPackets
  // is called to make sure there are no losses by timeout
  conn->lossState.srtt = 400ms;
  conn->lossState.lrtt = 350ms;
  conn->transportSettings.timeReorderingThreshDividend = 1.0;
  conn->transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = TimePoint(200ms);

  // Out of 1, 2, 3, 4, 5, 6, 7 -- we deleted (acked) 3,4,5.
  // 1, 2 and 6 are "lost" due to reodering. None lost due to timeout
  EXPECT_CALL(
      *obs1,
      packetLossDetected(
          socket_.get(),
          Field(
              &SocketObserverInterface::LossEvent::lostPackets,
              UnorderedElementsAre(
                  getLossPacketMatcher(
                      1 /* packetNum */,
                      true /* lossByReorder */,
                      false /* lossByTimeout */),
                  getLossPacketMatcher(
                      2 /* packetNum */,
                      true /* lossByReorder */,
                      false /* lossByTimeout */),
                  getLossPacketMatcher(
                      6 /* packetNum */,
                      true /* lossByReorder */,
                      false /* lossByTimeout */)))))
      .Times(1);

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent + 1;
  ASSERT_FALSE(
      detectLossPackets(
          *conn,
          ackState,
          [](auto&, auto&, bool) -> quic::Expected<void, quic::QuicError> {
            return {};
          },
          checkTime,
          PacketNumberSpace::AppData)
          .hasError());
  EXPECT_THAT(
      conn->outstandings.packets,
      UnorderedElementsAre(
          getOutstandingPacketMatcher(
              1 /* packetNum */,
              true /* lossByReorder */,
              false /* lossByTimeout */),
          getOutstandingPacketMatcher(
              2 /* packetNum */,
              true /* lossByReorder */,
              false /* lossByTimeout */),
          getOutstandingPacketMatcher(
              6 /* packetNum */,
              true /* lossByReorder */,
              false /* lossByTimeout */),
          getOutstandingPacketMatcher(
              7 /* packetNum */,
              false /* lossByReorder */,
              false /* lossByTimeout */)));

  CHECK_NOTNULL(conn->getSocketObserverContainer())->removeObserver(obs1.get());
}

TEST_F(QuicLossFunctionsTest, ObserverLossEventTimeout) {
  auto conn = createConn();

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::lossEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  CHECK_NOTNULL(conn->getSocketObserverContainer())->addObserver(obs1.get());

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent = sendPacket(
        *conn, TimePoint(i * 10ms), std::nullopt, PacketType::OneRtt);
  }

  // setting a very high reordering threshold to force loss by timeout only
  conn->lossState.reorderingThreshold = 100;
  // setting time out parameters lower than the time at which detectLossPackets
  // is called to make sure all packets timeout
  conn->lossState.srtt = 400ms;
  conn->lossState.lrtt = 350ms;
  conn->transportSettings.timeReorderingThreshDividend = 1.0;
  conn->transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = TimePoint(500ms);

  // expect all packets to be lost due to timeout
  EXPECT_CALL(
      *obs1,
      packetLossDetected(
          socket_.get(),
          Field(
              &SocketObserverInterface::LossEvent::lostPackets,
              UnorderedElementsAre(
                  getLossPacketMatcher(
                      1 /* packetNum */,
                      false /* lossByReorder */,
                      true /* lossByTimeout */),
                  getLossPacketMatcher(
                      2 /* packetNum */,
                      false /* lossByReorder */,
                      true /* lossByTimeout */),
                  getLossPacketMatcher(
                      3 /* packetNum */,
                      false /* lossByReorder */,
                      true /* lossByTimeout */),
                  getLossPacketMatcher(
                      4 /* packetNum */,
                      false /* lossByReorder */,
                      true /* lossByTimeout */),
                  getLossPacketMatcher(
                      5 /* packetNum */,
                      false /* lossByReorder */,
                      true /* lossByTimeout */),
                  getLossPacketMatcher(
                      6 /* packetNum */,
                      false /* lossByReorder */,
                      true /* lossByTimeout */),
                  getLossPacketMatcher(
                      7 /* packetNum */,
                      false /* lossByReorder */,
                      true /* lossByTimeout */)))))
      .Times(1);
  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent + 1;
  ASSERT_FALSE(
      detectLossPackets(
          *conn,
          ackState,
          [](auto&, auto&, bool) -> quic::Expected<void, quic::QuicError> {
            return {};
          },
          checkTime,
          PacketNumberSpace::AppData)
          .hasError());
  EXPECT_THAT(
      conn->outstandings.packets,
      UnorderedElementsAre(
          getOutstandingPacketMatcher(
              1 /* packetNum */,
              false /* lossByReorder */,
              true /* lossByTimeout */),
          getOutstandingPacketMatcher(
              2 /* packetNum */,
              false /* lossByReorder */,
              true /* lossByTimeout */),
          getOutstandingPacketMatcher(
              3 /* packetNum */,
              false /* lossByReorder */,
              true /* lossByTimeout */),
          getOutstandingPacketMatcher(
              4 /* packetNum */,
              false /* lossByReorder */,
              true /* lossByTimeout */),
          getOutstandingPacketMatcher(
              5 /* packetNum */,
              false /* lossByReorder */,
              true /* lossByTimeout */),
          getOutstandingPacketMatcher(
              6 /* packetNum */,
              false /* lossByReorder */,
              true /* lossByTimeout */),
          getOutstandingPacketMatcher(
              7 /* packetNum */,
              false /* lossByReorder */,
              true /* lossByTimeout */)));

  CHECK_NOTNULL(conn->getSocketObserverContainer())->removeObserver(obs1.get());
}

TEST_F(QuicLossFunctionsTest, ObserverLossEventTimeoutAndReorder) {
  auto conn = createConn();

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::lossEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  CHECK_NOTNULL(conn->getSocketObserverContainer())->addObserver(obs1.get());

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent = sendPacket(
        *conn, TimePoint(i * 10ms), std::nullopt, PacketType::OneRtt);
  }

  // Some packets are already acked
  conn->outstandings.packets.erase(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5);

  // setting a low reorder threshold
  conn->lossState.reorderingThreshold = 1;

  // setting time out parameters lower than the time at which detectLossPackets
  // is called to make sure all packets timeout
  conn->lossState.srtt = 400ms;
  conn->lossState.lrtt = 350ms;
  conn->transportSettings.timeReorderingThreshDividend = 1.0;
  conn->transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = TimePoint(500ms);

  // Out of 1, 2, 3, 4, 5, 6, 7 -- we deleted (acked) 3,4,5.
  // 1, 2, 6 are lost due to reodering and timeout.
  // 7 just timed out
  EXPECT_CALL(
      *obs1,
      packetLossDetected(
          socket_.get(),
          Field(
              &SocketObserverInterface::LossEvent::lostPackets,
              UnorderedElementsAre(
                  getLossPacketMatcher(
                      1 /* packetNum */,
                      true /* lossByReorder */,
                      true /* lossByTimeout */),
                  getLossPacketMatcher(
                      2 /* packetNum */,
                      true /* lossByReorder */,
                      true /* lossByTimeout */),
                  getLossPacketMatcher(
                      6 /* packetNum */,
                      true /* lossByReorder */,
                      true /* lossByTimeout */),
                  getLossPacketMatcher(
                      7 /* packetNum */,
                      false /* lossByReorder */,
                      true /* lossByTimeout */)))))
      .Times(1);
  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent + 1;
  ASSERT_FALSE(
      detectLossPackets(
          *conn,
          ackState,
          [](auto&, auto&, bool) -> quic::Expected<void, quic::QuicError> {
            return {};
          },
          checkTime,
          PacketNumberSpace::AppData)
          .hasError());
  EXPECT_THAT(
      conn->outstandings.packets,
      UnorderedElementsAre(
          getOutstandingPacketMatcher(
              1 /* packetNum */,
              true /* lossByReorder */,
              true /* lossByTimeout */),
          getOutstandingPacketMatcher(
              2 /* packetNum */,
              true /* lossByReorder */,
              true /* lossByTimeout */),
          getOutstandingPacketMatcher(
              6 /* packetNum */,
              true /* lossByReorder */,
              true /* lossByTimeout */),
          getOutstandingPacketMatcher(
              7 /* packetNum */,
              false /* lossByReorder */,
              true /* lossByTimeout */)));

  CHECK_NOTNULL(conn->getSocketObserverContainer())->removeObserver(obs1.get());
}

TEST_F(QuicLossFunctionsTest, TotalPacketsMarkedLostByReordering) {
  auto conn = createConn();
  auto noopLossVisitor =
      [](auto&, auto&, bool) -> quic::Expected<void, quic::QuicError> {
    return {};
  };

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent = sendPacket(
        *conn, TimePoint(i * 10ms), std::nullopt, PacketType::OneRtt);
  }

  // Some packets are already acked
  conn->outstandings.packets.erase(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5);

  // setting a very low reordering threshold to force loss by reorder
  conn->lossState.reorderingThreshold = 1;
  // setting time out parameters higher than the time at which detectLossPackets
  // is called to make sure there are no losses by timeout
  conn->lossState.srtt = 400ms;
  conn->lossState.lrtt = 350ms;
  conn->transportSettings.timeReorderingThreshDividend = 1.0;
  conn->transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = TimePoint(200ms);

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent + 1;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   noopLossVisitor,
                   checkTime,
                   PacketNumberSpace::AppData)
                   .hasError());

  // Sent 7 packets, out of 0, 1, 2, 3, 4, 5, 6 -- we deleted (acked) 2,3,4
  // 0, 1, and 5 should be marked lost due to reordering, std::nullopt due to
  // timeout 6 is outstanding / on the wire still (no determination made)
  EXPECT_EQ(3, conn->lossState.totalPacketsMarkedLost);
  EXPECT_EQ(0, conn->lossState.totalPacketsMarkedLostByTimeout);
  EXPECT_EQ(3, conn->lossState.totalPacketsMarkedLostByReorderingThreshold);
}

TEST_F(QuicLossFunctionsTest, TotalPacketsMarkedLostByTimeout) {
  auto conn = createConn();
  auto noopLossVisitor =
      [](auto&, auto&, bool) -> quic::Expected<void, quic::QuicError> {
    return {};
  };

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent = sendPacket(
        *conn, TimePoint(i * 10ms), std::nullopt, PacketType::OneRtt);
  }

  // setting a very high reordering threshold to force loss by timeout only
  conn->lossState.reorderingThreshold = 100;
  // setting time out parameters lower than the time at which detectLossPackets
  // is called to make sure all packets timeout
  conn->lossState.srtt = 400ms;
  conn->lossState.lrtt = 350ms;
  conn->transportSettings.timeReorderingThreshDividend = 1.0;
  conn->transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = TimePoint(500ms);

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent + 1;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   noopLossVisitor,
                   checkTime,
                   PacketNumberSpace::AppData)
                   .hasError());

  // All 7 packets should be marked as lost by PTO
  EXPECT_EQ(7, conn->lossState.totalPacketsMarkedLost);
  EXPECT_EQ(7, conn->lossState.totalPacketsMarkedLostByTimeout);
  EXPECT_EQ(0, conn->lossState.totalPacketsMarkedLostByReorderingThreshold);
}

TEST_F(QuicLossFunctionsTest, TotalPacketsMarkedLostByTimeoutPartial) {
  auto conn = createConn();
  auto noopLossVisitor =
      [](auto&, auto&, bool) -> quic::Expected<void, quic::QuicError> {
    return {};
  };

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent = sendPacket(
        *conn, TimePoint(i * 10ms), std::nullopt, PacketType::OneRtt);
  }

  // Some packets are already acked
  conn->outstandings.packets.erase(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5);

  // setting a very high reordering threshold to force loss by timeout only
  conn->lossState.reorderingThreshold = 100;
  // setting time out parameters lower than the time at which detectLossPackets
  // is called to make sure all packets timeout
  conn->lossState.srtt = 400ms;
  conn->lossState.lrtt = 350ms;
  conn->transportSettings.timeReorderingThreshDividend = 1.0;
  conn->transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = TimePoint(500ms);

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent + 1;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   noopLossVisitor,
                   checkTime,
                   PacketNumberSpace::AppData)
                   .hasError());

  // Sent 7 packets, out of 0, 1, 2, 3, 4, 5, 6 -- we deleted (acked) 2,3,4
  // 0, 1, 5, and 6 should be marked lost due to timeout, std::nullopt due to
  // reordering
  EXPECT_EQ(4, conn->lossState.totalPacketsMarkedLost);
  EXPECT_EQ(4, conn->lossState.totalPacketsMarkedLostByTimeout);
  EXPECT_EQ(0, conn->lossState.totalPacketsMarkedLostByReorderingThreshold);
}

TEST_F(QuicLossFunctionsTest, TotalPacketsMarkedLostByTimeoutAndReordering) {
  auto conn = createConn();
  auto noopLossVisitor =
      [](auto&, auto&, bool) -> quic::Expected<void, quic::QuicError> {
    return {};
  };

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent = sendPacket(
        *conn, TimePoint(i * 10ms), std::nullopt, PacketType::OneRtt);
  }

  // Some packets are already acked
  conn->outstandings.packets.erase(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5);

  // setting a low reorder threshold
  conn->lossState.reorderingThreshold = 1;

  // setting time out parameters lower than the time at which detectLossPackets
  // is called to make sure all packets timeout
  conn->lossState.srtt = 400ms;
  conn->lossState.lrtt = 350ms;
  conn->transportSettings.timeReorderingThreshDividend = 1.0;
  conn->transportSettings.timeReorderingThreshDivisor = 1.0;
  TimePoint checkTime = TimePoint(500ms);

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = largestSent + 1;
  ASSERT_FALSE(detectLossPackets(
                   *conn,
                   ackState,
                   noopLossVisitor,
                   checkTime,
                   PacketNumberSpace::AppData)
                   .hasError());

  // Sent 7 packets, out of 0, 1, 2, 3, 4, 5, 6 -- we deleted (acked) 2,3,4
  // 0, 1, and 5 should be marked lost due to reordering AND timeout
  // 6 should be marked as lost due to timeout only
  EXPECT_EQ(4, conn->lossState.totalPacketsMarkedLost);
  EXPECT_EQ(4, conn->lossState.totalPacketsMarkedLostByTimeout);
  EXPECT_EQ(3, conn->lossState.totalPacketsMarkedLostByReorderingThreshold);
}

TEST_F(QuicLossFunctionsTest, LossVisitorDSRTest) {
  auto conn = createConn();
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  ASSERT_FALSE(
      writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("grape"), false)
          .hasError());
  ASSERT_FALSE(
      writeBufMetaToQuicStream(*stream, BufferMeta(1000), true).hasError());
  auto bufMetaStartingOffset = stream->writeBufMeta.offset;
  ASSERT_EQ(1000, stream->writeBufMeta.length);
  ASSERT_TRUE(stream->writeBufMeta.eof);
  ASSERT_EQ(bufMetaStartingOffset + 1000, *stream->finalWriteOffset);
  // Send real data
  ASSERT_FALSE(handleStreamWritten(
                   *conn,
                   *stream,
                   0,
                   bufMetaStartingOffset,
                   false,
                   0 /* PacketNum */,
                   PacketNumberSpace::AppData)
                   .hasError());
  ASSERT_EQ(0, stream->pendingWrites.chainLength());
  auto retxIter = stream->retransmissionBuffer.find(0);
  ASSERT_NE(stream->retransmissionBuffer.end(), retxIter);
  ASSERT_EQ(0, retxIter->second->offset);
  ASSERT_FALSE(retxIter->second->eof);
  auto expectedBuf = folly::IOBuf::copyBuffer("grape");
  ASSERT_EQ(
      ByteRange(expectedBuf->buffer(), expectedBuf->length()),
      retxIter->second->data.getHead()->getRange());
  ASSERT_EQ(stream->currentWriteOffset, bufMetaStartingOffset);

  // Send BufMeta in 3 chunks:
  handleStreamBufMetaWritten(
      *conn,
      *stream,
      bufMetaStartingOffset,
      200,
      false,
      1 /* PacketNum */,
      PacketNumberSpace::AppData);
  ASSERT_EQ(800, stream->writeBufMeta.length);
  ASSERT_TRUE(stream->writeBufMeta.eof);
  ASSERT_EQ(bufMetaStartingOffset + 200, stream->writeBufMeta.offset);
  auto retxBufMetaIter =
      stream->retransmissionBufMetas.find(bufMetaStartingOffset);
  ASSERT_NE(stream->retransmissionBufMetas.end(), retxBufMetaIter);
  ASSERT_EQ(bufMetaStartingOffset, retxBufMetaIter->second.offset);
  ASSERT_EQ(200, retxBufMetaIter->second.length);
  ASSERT_FALSE(retxBufMetaIter->second.eof);
  conn->streamManager->updateWritableStreams(*stream);
  EXPECT_FALSE(conn->streamManager->hasLoss());
  EXPECT_FALSE(conn->streamManager->writableDSRStreams().empty());

  handleStreamBufMetaWritten(
      *conn,
      *stream,
      bufMetaStartingOffset + 200,
      400,
      false,
      2 /* PacketNum */,
      PacketNumberSpace::AppData);
  ASSERT_EQ(400, stream->writeBufMeta.length);
  ASSERT_TRUE(stream->writeBufMeta.eof);
  ASSERT_EQ(bufMetaStartingOffset + 600, stream->writeBufMeta.offset);
  retxBufMetaIter =
      stream->retransmissionBufMetas.find(bufMetaStartingOffset + 200);
  ASSERT_NE(stream->retransmissionBufMetas.end(), retxBufMetaIter);
  ASSERT_EQ(bufMetaStartingOffset + 200, retxBufMetaIter->second.offset);
  ASSERT_EQ(400, retxBufMetaIter->second.length);
  ASSERT_FALSE(retxBufMetaIter->second.eof);
  conn->streamManager->updateWritableStreams(*stream);
  EXPECT_FALSE(conn->streamManager->hasLoss());
  EXPECT_FALSE(conn->streamManager->writableDSRStreams().empty());

  handleStreamBufMetaWritten(
      *conn,
      *stream,
      bufMetaStartingOffset + 600,
      400,
      true,
      3 /* PacketNum */,
      PacketNumberSpace::AppData);
  ASSERT_EQ(0, stream->writeBufMeta.length);
  ASSERT_TRUE(stream->writeBufMeta.eof);
  ASSERT_EQ(bufMetaStartingOffset + 1000 + 1, stream->writeBufMeta.offset);
  retxBufMetaIter =
      stream->retransmissionBufMetas.find(bufMetaStartingOffset + 600);
  ASSERT_NE(stream->retransmissionBufMetas.end(), retxBufMetaIter);
  ASSERT_EQ(bufMetaStartingOffset + 600, retxBufMetaIter->second.offset);
  ASSERT_EQ(400, retxBufMetaIter->second.length);
  ASSERT_TRUE(retxBufMetaIter->second.eof);
  conn->streamManager->updateWritableStreams(*stream);
  EXPECT_FALSE(conn->streamManager->hasLoss());
  EXPECT_TRUE(conn->streamManager->writableDSRStreams().empty());

  // Lose the 1st dsr packet:
  RegularQuicWritePacket packet1(PacketHeader(ShortHeader(
      ProtectionType::KeyPhaseZero, conn->serverConnectionId.value(), 1)));
  WriteStreamFrame frame1(stream->id, bufMetaStartingOffset, 200, false);
  frame1.fromBufMeta = true;
  packet1.frames.push_back(frame1);
  ASSERT_FALSE(
      markPacketLoss(*conn, packet1, false /* processed */).hasError());
  EXPECT_EQ(1, stream->lossBufMetas.size());
  const auto& lostBufMeta1 = stream->lossBufMetas.front();
  EXPECT_EQ(bufMetaStartingOffset, lostBufMeta1.offset);
  EXPECT_EQ(200, lostBufMeta1.length);
  EXPECT_FALSE(lostBufMeta1.eof);
  EXPECT_EQ(2, stream->retransmissionBufMetas.size());
  EXPECT_TRUE(conn->streamManager->hasLoss());
  ASSERT_EQ(stream->streamLossCount, 1);
  EXPECT_FALSE(stream->hasWritableBufMeta());
  EXPECT_FALSE(conn->streamManager->writableDSRStreams().contains(stream->id));
  EXPECT_TRUE(writeQueueContains(*conn, stream->id));

  // Lose the 3rd dsr packet:
  RegularQuicWritePacket packet3(PacketHeader(ShortHeader(
      ProtectionType::KeyPhaseZero, conn->serverConnectionId.value(), 3)));
  WriteStreamFrame frame3(stream->id, bufMetaStartingOffset + 600, 400, true);
  frame3.fromBufMeta = true;
  packet3.frames.push_back(frame3);
  ASSERT_FALSE(
      markPacketLoss(*conn, packet3, false /* processed */).hasError());
  EXPECT_EQ(2, stream->lossBufMetas.size());
  const auto& lostBufMeta2 = stream->lossBufMetas.back();
  EXPECT_EQ(bufMetaStartingOffset + 600, lostBufMeta2.offset);
  EXPECT_EQ(400, lostBufMeta2.length);
  EXPECT_TRUE(lostBufMeta2.eof);
  EXPECT_EQ(1, stream->retransmissionBufMetas.size());
  ASSERT_EQ(stream->streamLossCount, 2);
  EXPECT_TRUE(conn->streamManager->hasLoss());
  EXPECT_FALSE(stream->hasWritableBufMeta());
  EXPECT_FALSE(conn->streamManager->writableDSRStreams().contains(stream->id));
  EXPECT_TRUE(writeQueueContains(*conn, stream->id));

  // Lose the 3rd dsr packet, it should be merged together with the first
  // element in the lossBufMetas:
  RegularQuicWritePacket packet2(PacketHeader(ShortHeader(
      ProtectionType::KeyPhaseZero, conn->serverConnectionId.value(), 2)));
  WriteStreamFrame frame2(stream->id, bufMetaStartingOffset + 200, 400, false);
  frame2.fromBufMeta = true;
  packet2.frames.push_back(frame2);
  ASSERT_FALSE(
      markPacketLoss(*conn, packet2, false /* processed */).hasError());
  EXPECT_EQ(2, stream->lossBufMetas.size());
  const auto& lostBufMeta3 = stream->lossBufMetas.front();
  EXPECT_EQ(bufMetaStartingOffset, lostBufMeta3.offset);
  EXPECT_EQ(600, lostBufMeta3.length);
  EXPECT_FALSE(lostBufMeta3.eof);
  EXPECT_EQ(0, stream->retransmissionBufMetas.size());
  ASSERT_EQ(stream->streamLossCount, 3);
  EXPECT_TRUE(conn->streamManager->hasLoss());
  EXPECT_FALSE(stream->hasWritableBufMeta());
  EXPECT_FALSE(conn->streamManager->writableDSRStreams().contains(stream->id));
  EXPECT_TRUE(writeQueueContains(*conn, stream->id));
}

TEST_F(QuicLossFunctionsTest, TestReorderingThresholdDSRNormal) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  auto testingLossMarkFunc = [&lostPacket](auto& /*conn*/, auto& packet, bool)
      -> quic::Expected<void, quic::QuicError> {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPacket.push_back(packetNum);
    return {};
  };
  for (int i = 0; i < 6; ++i) {
    sendPacket(
        *conn,
        Clock::now(),
        std::nullopt,
        PacketType::OneRtt,
        std::nullopt,
        true);
  }
  // Add some DSR frames
  for (auto& op : conn->outstandings.packets) {
    // This matches the stream packet index to the one used by the packet.
    op.packet.frames.emplace_back(WriteStreamFrame{
        0,
        10,
        100,
        false,
        true,
        std::nullopt,
        op.packet.header.getPacketSequenceNum()});
    op.isDSRPacket = true;
    conn->outstandings.dsrCount++;
  }
  EXPECT_EQ(6, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  // Assume some packets are already acked
  for (auto iter =
           getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2;
       iter < getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5;
       iter++) {
    conn->outstandings.packetCount[PacketNumberSpace::AppData]--;
  }
  auto firstAppDataOpIter =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData);
  conn->outstandings.packets.erase(
      firstAppDataOpIter + 2, firstAppDataOpIter + 5);
  // Ack for packet 9 arrives
  auto ack = AckEvent::Builder()
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(9)
                 .setIsImplicitAck(false)
                 .setAckTime(Clock::now())
                 .setAdjustedAckTime(Clock::now())
                 .setAckDelay(0us)
                 .build();
  AckEvent::AckPacket::DetailsPerStream detailsPerStream;
  detailsPerStream.recordFrameDelivered(
      WriteStreamFrame{0, 10, 100, false, true, std::nullopt, 9});
  ack.ackedPackets.emplace_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(9)
          .setNonDsrPacketSequenceNumber(0)
          .setDetailsPerStream(std::move(detailsPerStream))
          .setOutstandingPacketMetadata(
              getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
                  ->metadata)
          .build());
  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = 9;
  auto lossEventResult = detectLossPackets(
      *conn,
      ackState,
      testingLossMarkFunc,
      TimePoint(90ms),
      PacketNumberSpace::AppData,
      &ack);
  ASSERT_FALSE(lossEventResult.hasError());
  auto& lossEvent = lossEventResult.value();
  ASSERT_TRUE(lossEvent->largestLostPacketNum.has_value());
  EXPECT_EQ(2, lossEvent->largestLostPacketNum.value());
  EXPECT_EQ(TimePoint(90ms), lossEvent->lossTime);
  // Packet 1,2 should be marked as loss
  EXPECT_EQ(lostPacket.size(), 2);
  EXPECT_EQ(lostPacket.front(), 1);
  EXPECT_EQ(lostPacket.back(), 2);

  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::AppData]);

  // Packet 6 should remain in packet as the delta is less than threshold
  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(conn->outstandings.packets.size(), 1 + numDeclaredLost);
  auto first = getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData);
  auto packetNum = first->packet.header.getPacketSequenceNum();
  EXPECT_EQ(packetNum, 6);
}

TEST_F(QuicLossFunctionsTest, TestReorderingThresholdDSRNormalOverflow) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  auto testingLossMarkFunc = [&lostPacket](auto& /*conn*/, auto& packet, bool)
      -> quic::Expected<void, quic::QuicError> {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPacket.push_back(packetNum);
    return {};
  };
  for (int i = 0; i < 6; ++i) {
    sendPacket(
        *conn,
        Clock::now(),
        std::nullopt,
        PacketType::OneRtt,
        std::nullopt,
        true);
  }
  // Add some DSR frames
  for (auto& op : conn->outstandings.packets) {
    op.packet.frames.emplace_back(WriteStreamFrame{0, 10, 100, false, true});
    op.isDSRPacket = true;
    conn->outstandings.dsrCount++;
  }
  EXPECT_EQ(6, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  // Assume some packets are already acked
  for (auto iter =
           getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2;
       iter < getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5;
       iter++) {
    conn->outstandings.packetCount[PacketNumberSpace::AppData]--;
  }
  auto firstAppDataOpIter =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData);
  conn->outstandings.packets.erase(
      firstAppDataOpIter + 2, firstAppDataOpIter + 5);
  // Ack for packet 9 arrives
  auto ack = AckEvent::Builder()
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(9)
                 .setIsImplicitAck(false)
                 .setAckTime(Clock::now())
                 .setAdjustedAckTime(Clock::now())
                 .setAckDelay(0us)
                 .build();
  AckEvent::AckPacket::DetailsPerStream detailsPerStream;
  detailsPerStream.recordFrameDelivered(
      WriteStreamFrame{0, 10, 100, false, true});
  ack.ackedPackets.emplace_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(0)
          .setNonDsrPacketSequenceNumber(0)
          .setDetailsPerStream(std::move(detailsPerStream))
          .setOutstandingPacketMetadata(
              getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
                  ->metadata)
          .build());

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = 9;
  auto lossEventResult = detectLossPackets(
      *conn,
      ackState,
      testingLossMarkFunc,
      TimePoint(90ms),
      PacketNumberSpace::AppData,
      &ack);
  EXPECT_FALSE(lossEventResult.hasError());
  auto& lossEvent = lossEventResult.value();
  EXPECT_FALSE(lossEvent.has_value());

  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(numDeclaredLost, 0);
}

TEST_F(QuicLossFunctionsTest, TestReorderingThresholdDSRIgnoreReorder) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  auto testingLossMarkFunc = [&lostPacket](auto& /*conn*/, auto& packet, bool)
      -> quic::Expected<void, quic::QuicError> {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPacket.push_back(packetNum);
    return {};
  };
  for (int i = 0; i < 6; ++i) {
    sendPacket(
        *conn,
        Clock::now(),
        std::nullopt,
        PacketType::OneRtt,
        std::nullopt,
        true);
  }
  // Add some DSR frames
  for (auto& op : conn->outstandings.packets) {
    op.packet.frames.emplace_back(WriteStreamFrame{
        0,
        10,
        100,
        false,
        true,
        std::nullopt,
        op.packet.header.getPacketSequenceNum()});
    op.isDSRPacket = true;
    conn->outstandings.dsrCount++;
  }
  // Add another non-DSR after
  sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  EXPECT_EQ(7, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  // Assume some packets are already acked
  for (auto iter =
           getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2;
       iter < getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5;
       iter++) {
    conn->outstandings.packetCount[PacketNumberSpace::AppData]--;
  }
  auto firstAppDataOpIter =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData);
  conn->outstandings.packets.erase(
      firstAppDataOpIter + 2, firstAppDataOpIter + 5);
  // Ack for packet 20 arrives
  auto ack = AckEvent::Builder()
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(20)
                 .setIsImplicitAck(false)
                 .setAckTime(Clock::now())
                 .setAdjustedAckTime(Clock::now())
                 .setAckDelay(0us)
                 .build();
  AckEvent::AckPacket::DetailsPerStream detailsPerStream;
  // Ack a different stream.
  detailsPerStream.recordFrameDelivered(
      WriteStreamFrame{4, 10, 100, false, true});
  ack.ackedPackets.emplace_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(20)
          .setNonDsrPacketSequenceNumber(0)
          .setDetailsPerStream(std::move(detailsPerStream))
          .setOutstandingPacketMetadata(
              getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
                  ->metadata)
          .build());
  ack.ackedPackets.emplace_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(19)
          .setNonDsrPacketSequenceNumber(19 - 6)
          .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
          .setOutstandingPacketMetadata(
              getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
                  ->metadata)
          .build());
  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = 20;
  auto lossEventResult = detectLossPackets(
      *conn,
      ackState,
      testingLossMarkFunc,
      TimePoint(90ms),
      PacketNumberSpace::AppData,
      &ack);
  EXPECT_FALSE(lossEventResult.hasError());
  auto& lossEvent = lossEventResult.value();
  ASSERT_TRUE(lossEvent.has_value());

  EXPECT_EQ(3, conn->outstandings.packetCount[PacketNumberSpace::AppData]);

  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  // We should declare the non DSR packet lost.
  EXPECT_EQ(1, numDeclaredLost);
}

TEST_F(QuicLossFunctionsTest, TestReorderingThresholdNonDSRIgnoreReorder) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  auto testingLossMarkFunc = [&lostPacket](auto& /*conn*/, auto& packet, bool)
      -> quic::Expected<void, quic::QuicError> {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPacket.push_back(packetNum);
    return {};
  };
  for (int i = 0; i < 6; ++i) {
    sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  }
  EXPECT_EQ(6, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  // Assume some packets are already acked
  for (auto iter =
           getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2;
       iter < getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5;
       iter++) {
    conn->outstandings.packetCount[PacketNumberSpace::AppData]--;
  }
  auto firstAppDataOpIter =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData);
  conn->outstandings.packets.erase(
      firstAppDataOpIter + 2, firstAppDataOpIter + 5);
  // Ack for packet 9 arrives
  auto ack = AckEvent::Builder()
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(9)
                 .setIsImplicitAck(false)
                 .setAckTime(Clock::now())
                 .setAdjustedAckTime(Clock::now())
                 .setAckDelay(0us)
                 .build();
  AckEvent::AckPacket::DetailsPerStream detailsPerStream;
  // Ack a different stream.
  detailsPerStream.recordFrameDelivered(
      WriteStreamFrame{4, 10, 100, false, true});
  ack.ackedPackets.emplace_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(9)
          .setNonDsrPacketSequenceNumber(9)
          .setDetailsPerStream(std::move(detailsPerStream))
          .setOutstandingPacketMetadata(
              getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
                  ->metadata)
          .build());

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = 9;
  auto lossEventResult = detectLossPackets(
      *conn,
      ackState,
      testingLossMarkFunc,
      TimePoint(90ms),
      PacketNumberSpace::AppData,
      &ack);
  EXPECT_FALSE(lossEventResult.hasError());
  auto& lossEvent = lossEventResult.value();
  EXPECT_FALSE(lossEvent.has_value());

  EXPECT_EQ(3, conn->outstandings.packetCount[PacketNumberSpace::AppData]);

  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(0, numDeclaredLost);
  EXPECT_EQ(conn->outstandings.packets.size(), 3);
}

TEST_F(
    QuicLossFunctionsTest,
    TestReorderingThresholdNonDSRIgnoreReorderOverflow) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  auto testingLossMarkFunc = [&lostPacket](auto& /*conn*/, auto& packet, bool)
      -> quic::Expected<void, quic::QuicError> {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPacket.push_back(packetNum);
    return {};
  };
  for (int i = 0; i < 6; ++i) {
    sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  }
  EXPECT_EQ(6, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  // Assume some packets are already acked
  for (auto iter =
           getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2;
       iter < getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5;
       iter++) {
    conn->outstandings.packetCount[PacketNumberSpace::AppData]--;
  }
  auto firstAppDataOpIter =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData);
  conn->outstandings.packets.erase(
      firstAppDataOpIter + 2, firstAppDataOpIter + 5);
  // Ack for packet 0 arrives
  auto ack = AckEvent::Builder()
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(9)
                 .setIsImplicitAck(false)
                 .setAckTime(Clock::now())
                 .setAdjustedAckTime(Clock::now())
                 .setAckDelay(0us)
                 .build();
  AckEvent::AckPacket::DetailsPerStream detailsPerStream;
  detailsPerStream.recordFrameDelivered(
      WriteStreamFrame{4, 10, 100, false, true});
  ack.ackedPackets.emplace_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(9)
          .setNonDsrPacketSequenceNumber(9)
          .setDetailsPerStream(std::move(detailsPerStream))
          .setOutstandingPacketMetadata(
              getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
                  ->metadata)
          .build());
  ack.ackedPackets.emplace_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(0)
          .setNonDsrPacketSequenceNumber(0)
          .setOutstandingPacketMetadata(
              getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
                  ->metadata)
          .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
          .build());

  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = 9;
  auto lossEventResult = detectLossPackets(
      *conn,
      ackState,
      testingLossMarkFunc,
      TimePoint(90ms),
      PacketNumberSpace::AppData,
      &ack);
  EXPECT_FALSE(lossEventResult.hasError());
  auto& lossEvent = lossEventResult.value();
  EXPECT_FALSE(lossEvent.has_value());

  EXPECT_EQ(3, conn->outstandings.packetCount[PacketNumberSpace::AppData]);

  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  EXPECT_EQ(0, numDeclaredLost);
  EXPECT_EQ(conn->outstandings.packets.size(), 3);
}

TEST_F(QuicLossFunctionsTest, TestReorderingThresholdDSRIgnoreReorderBurst) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  auto testingLossMarkFunc = [&lostPacket](auto& /*conn*/, auto& packet, bool)
      -> quic::Expected<void, quic::QuicError> {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPacket.push_back(packetNum);
    return {};
  };
  for (int i = 0; i < 4; ++i) {
    sendPacket(
        *conn,
        Clock::now(),
        std::nullopt,
        PacketType::OneRtt,
        std::nullopt,
        true);
  }
  // Add some DSR frames and build the ACK
  auto ack = AckEvent::Builder()
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(9)
                 .setIsImplicitAck(false)
                 .setAckTime(Clock::now())
                 .setAdjustedAckTime(Clock::now())
                 .setAckDelay(0us)
                 .build();
  for (auto& op : conn->outstandings.packets) {
    WriteStreamFrame f{
        0,
        10,
        100,
        false,
        true,
        std::nullopt,
        op.packet.header.getPacketSequenceNum()};
    AckEvent::AckPacket::DetailsPerStream detailsPerStream;
    if (op.packet.header.getPacketSequenceNum() != 4) {
      detailsPerStream.recordFrameDelivered(f);
      ack.ackedPackets.emplace_back(
          CongestionController::AckEvent::AckPacket::Builder()
              .setPacketNum(op.packet.header.getPacketSequenceNum())
              .setNonDsrPacketSequenceNumber(0)
              .setDetailsPerStream(std::move(detailsPerStream))
              .setOutstandingPacketMetadata(op.metadata)
              .build());
    }
    op.packet.frames.emplace_back(f);
    op.isDSRPacket = true;
    conn->outstandings.dsrCount++;
  }
  // Add another non-DSR burst and ACK all of them
  for (int i = 0; i < 4; ++i) {
    sendPacket(
        *conn,
        Clock::now(),
        std::nullopt,
        PacketType::OneRtt,
        std::nullopt,
        false);
    auto& op = *getLastOutstandingPacket(*conn, PacketNumberSpace::AppData);
    ack.ackedPackets.emplace_back(
        CongestionController::AckEvent::AckPacket::Builder()
            .setPacketNum(op.packet.header.getPacketSequenceNum())
            .setNonDsrPacketSequenceNumber(
                op.nonDsrPacketSequenceNumber.value())
            .setDetailsPerStream({})
            .setOutstandingPacketMetadata(op.metadata)
            .build());
  }
  // Add one more DSR packet from the same stream, ACKed
  sendPacket(
      *conn,
      Clock::now(),
      std::nullopt,
      PacketType::OneRtt,
      std::nullopt,
      true);
  auto& op = *getLastOutstandingPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame f{0, 10, 100, false, true, std::nullopt, 5};
  AckEvent::AckPacket::DetailsPerStream detailsPerStream;
  detailsPerStream.recordFrameDelivered(f);
  op.packet.frames.emplace_back(f);
  op.isDSRPacket = true;
  conn->outstandings.dsrCount++;
  ack.ackedPackets.emplace_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(op.packet.header.getPacketSequenceNum())
          .setNonDsrPacketSequenceNumber(0)
          .setDetailsPerStream(std::move(detailsPerStream))
          .setOutstandingPacketMetadata(op.metadata)
          .build());

  ASSERT_EQ(9, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  // ACK everything that isn't packet 4.
  auto itr = getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData);
  while (itr != conn->outstandings.packets.end()) {
    if (itr->packet.header.getPacketSequenceNum() != 4) {
      itr = conn->outstandings.packets.erase(itr);
      conn->outstandings.packetCount[PacketNumberSpace::AppData]--;
    } else {
      itr++;
    }
  }
  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = 10;
  auto lossEventResult = detectLossPackets(
      *conn,
      ackState,
      testingLossMarkFunc,
      TimePoint(90ms),
      PacketNumberSpace::AppData,
      &ack);
  EXPECT_FALSE(lossEventResult.hasError());
  auto& lossEvent = lossEventResult.value();
  EXPECT_FALSE(lossEvent.has_value());
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  // The DSR packet before the burst shouldn't be lost.
  EXPECT_EQ(0, numDeclaredLost);
}

TEST_F(QuicLossFunctionsTest, TestReorderingThresholdNonDSRIgnoreReorderBurst) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  auto testingLossMarkFunc = [&lostPacket](auto& /*conn*/, auto& packet, bool)
      -> quic::Expected<void, quic::QuicError> {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPacket.push_back(packetNum);
    return {};
  };
  for (int i = 0; i < 4; ++i) {
    sendPacket(
        *conn,
        Clock::now(),
        std::nullopt,
        PacketType::OneRtt,
        std::nullopt,
        false);
  }
  // Add some non-DSR frames and build the ACK
  auto ack = AckEvent::Builder()
                 .setPacketNumberSpace(PacketNumberSpace::AppData)
                 .setLargestAckedPacket(9)
                 .setIsImplicitAck(false)
                 .setAckTime(Clock::now())
                 .setAdjustedAckTime(Clock::now())
                 .setAckDelay(0us)
                 .build();
  for (auto& op : conn->outstandings.packets) {
    WriteStreamFrame f{0, 10, 100, false, false, std::nullopt, 0};
    AckEvent::AckPacket::DetailsPerStream detailsPerStream;
    if (op.packet.header.getPacketSequenceNum() != 4) {
      detailsPerStream.recordFrameDelivered(f);
      ack.ackedPackets.emplace_back(
          CongestionController::AckEvent::AckPacket::Builder()
              .setPacketNum(op.packet.header.getPacketSequenceNum())
              .setNonDsrPacketSequenceNumber(
                  op.nonDsrPacketSequenceNumber.value())
              .setDetailsPerStream(std::move(detailsPerStream))
              .setOutstandingPacketMetadata(op.metadata)
              .build());
    }
    op.packet.frames.emplace_back(f);
  }
  // Add a DSR burst and ACK all of them
  for (int i = 0; i < 4; ++i) {
    sendPacket(
        *conn,
        Clock::now(),
        std::nullopt,
        PacketType::OneRtt,
        std::nullopt,
        true);
    auto& op = *getLastOutstandingPacket(*conn, PacketNumberSpace::AppData);
    WriteStreamFrame f{
        4, 10, 100, false, true, std::nullopt, conn->outstandings.dsrCount++};
    AckEvent::AckPacket::DetailsPerStream detailsPerStream;
    detailsPerStream.recordFrameDelivered(f);
    ack.ackedPackets.emplace_back(
        CongestionController::AckEvent::AckPacket::Builder()
            .setPacketNum(op.packet.header.getPacketSequenceNum())
            .setNonDsrPacketSequenceNumber(0)
            .setDetailsPerStream(std::move(detailsPerStream))
            .setOutstandingPacketMetadata(op.metadata)
            .build());
    op.packet.frames.emplace_back(f);
    op.isDSRPacket = true;
  }
  // Add one more non-DSR packet from the same stream, ACKed
  sendPacket(*conn, Clock::now(), std::nullopt, PacketType::OneRtt);
  auto& op = *getLastOutstandingPacket(*conn, PacketNumberSpace::AppData);
  WriteStreamFrame f{0, 10, 100, false, false, std::nullopt, 0};
  AckEvent::AckPacket::DetailsPerStream detailsPerStream;
  detailsPerStream.recordFrameDelivered(f);
  op.packet.frames.emplace_back(f);
  ack.ackedPackets.emplace_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(op.packet.header.getPacketSequenceNum())
          .setNonDsrPacketSequenceNumber(op.nonDsrPacketSequenceNumber.value())
          .setDetailsPerStream(std::move(detailsPerStream))
          .setOutstandingPacketMetadata(op.metadata)
          .build());

  ASSERT_EQ(9, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  // ACK everything that isn't packet 4.
  auto itr = getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData);
  while (itr != conn->outstandings.packets.end()) {
    if (itr->packet.header.getPacketSequenceNum() != 4) {
      itr = conn->outstandings.packets.erase(itr);
      conn->outstandings.packetCount[PacketNumberSpace::AppData]--;
    } else {
      itr++;
    }
  }
  auto& ackState = getAckState(*conn, PacketNumberSpace::AppData);
  ackState.largestAckedByPeer =
      ackState.largestNonDsrSequenceNumberAckedByPeer = 10;
  auto lossEventResult = detectLossPackets(
      *conn,
      ackState,
      testingLossMarkFunc,
      TimePoint(90ms),
      PacketNumberSpace::AppData,
      &ack);
  EXPECT_FALSE(lossEventResult.hasError());
  auto& lossEvent = lossEventResult.value();
  EXPECT_FALSE(lossEvent.has_value());
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  auto numDeclaredLost = std::count_if(
      conn->outstandings.packets.begin(),
      conn->outstandings.packets.end(),
      [](auto& op) { return op.declaredLost; });
  // The non-DSR packet before the burst shouldn't be lost.
  EXPECT_EQ(0, numDeclaredLost);
}

INSTANTIATE_TEST_SUITE_P(
    QuicLossFunctionsTests,
    QuicLossFunctionsTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossRetransmissionDisabled) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();

  conn->transportSettings.advertisedMaxStreamGroups = 16;

  const auto groupId =
      conn->streamManager->createNextBidirectionalStreamGroup();
  QuicStreamGroupRetransmissionPolicy policy;
  policy.disableRetransmission = true;
  conn->retransmissionPolicies.emplace(*groupId, policy);

  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(2);
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream(*groupId).value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream(*groupId).value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto buf = buildRandomInputData(20);
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());
  ASSERT_FALSE(writeDataToQuicStream(*stream2, buf->clone(), true).hasError());

  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());

  // One packet in outstandings.
  EXPECT_EQ(1, conn->outstandings.packets.size());

  // Lose the packet.
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet, false).hasError());

  // The lost packet data should not be transferred to the loss buffer of either
  // stream.
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream1->lossBuffer.size(), 0);
  EXPECT_EQ(stream2->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream2->lossBuffer.size(), 0);
}

TEST_F(
    QuicLossFunctionsTest,
    TestMarkPacketLossRetransmissionPolicyPresentButNotDisabled) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();

  conn->transportSettings.advertisedMaxStreamGroups = 16;

  const auto groupId =
      conn->streamManager->createNextBidirectionalStreamGroup();
  QuicStreamGroupRetransmissionPolicy policy;
  policy.disableRetransmission = false;
  conn->retransmissionPolicies.emplace(*groupId, policy);

  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(2);
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream(*groupId).value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream(*groupId).value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto buf = buildRandomInputData(20);
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());
  ASSERT_FALSE(writeDataToQuicStream(*stream2, buf->clone(), true).hasError());

  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());

  // One packet in outstandings.
  EXPECT_EQ(1, conn->outstandings.packets.size());

  // Lose the packet.
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet, false).hasError());

  // The data from the lost packet should be transferred to the loss buffer of
  // both streams because disableRetransmission = false on the policy.
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream1->lossBuffer.size(), 1);
  EXPECT_EQ(stream2->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream2->lossBuffer.size(), 1);
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossRetransmissionPolicyTwoGroups) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();

  conn->transportSettings.advertisedMaxStreamGroups = 16;

  const auto groupId1 =
      conn->streamManager->createNextBidirectionalStreamGroup();
  const auto groupId2 =
      conn->streamManager->createNextBidirectionalStreamGroup();

  QuicStreamGroupRetransmissionPolicy policy1;
  policy1.disableRetransmission = true;
  conn->retransmissionPolicies.emplace(*groupId1, policy1);

  QuicStreamGroupRetransmissionPolicy policy2;
  policy2.disableRetransmission = false;
  conn->retransmissionPolicies.emplace(*groupId2, policy2);

  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(2);
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream(*groupId1).value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream(*groupId2).value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
  auto buf = buildRandomInputData(20);
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());
  ASSERT_FALSE(writeDataToQuicStream(*stream2, buf->clone(), true).hasError());

  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());

  // One packet in outstandings.
  EXPECT_EQ(1, conn->outstandings.packets.size());

  // Lose the packet.
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet, false).hasError());

  // The data from the lost packet should not be transferred to the loss buffer
  // of stream1, but should be transferred to the loss buffer of stream2.
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream1->lossBuffer.size(), 0);
  EXPECT_EQ(stream2->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream2->lossBuffer.size(), 1);
}

TEST_F(
    QuicLossFunctionsTest,
    TestMarkPacketLossRetransmissionPolicyTwoGroupsTwoPackets) {
  folly::EventBase evb;
  auto qEvb = std::make_shared<FollyQuicEventBase>(&evb);
  MockAsyncUDPSocket socket(qEvb);
  ON_CALL(socket, getGSO).WillByDefault(testing::Return(0));
  auto conn = createConn();

  conn->transportSettings.advertisedMaxStreamGroups = 16;

  const auto groupId1 =
      conn->streamManager->createNextBidirectionalStreamGroup();
  const auto groupId2 =
      conn->streamManager->createNextBidirectionalStreamGroup();

  QuicStreamGroupRetransmissionPolicy policy1;
  policy1.disableRetransmission = true;
  conn->retransmissionPolicies.emplace(*groupId1, policy1);

  QuicStreamGroupRetransmissionPolicy policy2;
  policy2.disableRetransmission = false;
  conn->retransmissionPolicies.emplace(*groupId2, policy2);

  // Generate packet 1.
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream(*groupId1).value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto buf = buildRandomInputData(20);
  ASSERT_FALSE(writeDataToQuicStream(*stream1, buf->clone(), true).hasError());

  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());

  // Generate packet 2.
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream(*groupId2).value()->id;
  auto stream2 = conn->streamManager->findStream(stream2Id);
  ASSERT_FALSE(writeDataToQuicStream(*stream2, buf->clone(), true).hasError());

  ASSERT_FALSE(writeQuicDataToSocket(
                   socket,
                   *conn,
                   *conn->clientConnectionId,
                   *conn->serverConnectionId,
                   *aead,
                   *headerCipher,
                   *conn->version,
                   conn->transportSettings.writeConnectionDataPacketsLimit)
                   .hasError());

  // Two packets in outstandings.
  EXPECT_EQ(2, conn->outstandings.packets.size());

  // Lose the first packet.
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet, false).hasError());
  // Lose the second packet.
  auto& packet2 =
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  ASSERT_FALSE(markPacketLoss(*conn, packet2, false).hasError());

  // The data from the lost packet should not be transferred to the loss buffer
  // of stream1, but should be transferred to the loss buffer of stream2.
  stream1 = conn->streamManager->findStream(stream1Id);
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream1->lossBuffer.size(), 0);
  stream2 = conn->streamManager->findStream(stream2Id);
  EXPECT_EQ(stream2->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream2->lossBuffer.size(), 1);
}

} // namespace quic::test
