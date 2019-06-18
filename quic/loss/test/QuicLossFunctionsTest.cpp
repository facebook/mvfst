/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <folly/io/async/test/MockTimeoutManager.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/MockQuicStats.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/test/TestUtils.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/test/Mocks.h>

using namespace folly::test;
using namespace testing;
using namespace folly;
using namespace std::chrono_literals;

namespace quic {
namespace test {

class MockLossTimeout {
 public:
  MOCK_METHOD0(cancelLossTimeout, void());
  MOCK_METHOD1(scheduleLossTimeout, void(std::chrono::milliseconds));
  MOCK_METHOD0(isLossTimeoutScheduled, bool());
};

enum class PacketType {
  Handshake,
  ZeroRtt,
  OneRtt,
};

class QuicLossFunctionsTest : public TestWithParam<PacketNumberSpace> {
 public:
  void SetUp() override {
    aead = createNoOpAead();
    headerCipher = createNoOpHeaderCipher();
    transportInfoCb_ = std::make_unique<MockQuicStats>();
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
  }

  PacketNum sendPacket(
      QuicConnectionStateBase& conn,
      TimePoint time,
      bool pureAck,
      folly::Optional<PacketEvent> associatedEvent,
      PacketType packetType);

  std::unique_ptr<QuicServerConnectionState> createConn() {
    auto conn = std::make_unique<QuicServerConnectionState>();
    conn->clientConnectionId = getTestConnectionId();
    conn->version = QuicVersion::MVFST;
    conn->ackStates.initialAckState.nextPacketNum = 1;
    conn->ackStates.handshakeAckState.nextPacketNum = 1;
    conn->ackStates.appDataAckState.nextPacketNum = 1;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn->streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn->streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
    conn->infoCallback = transportInfoCb_.get();
    // create a serverConnectionId that is different from the client connId
    // with bits for processId and workerId set to 0
    ServerConnectionIdParams params(0, 0, 0);
    params.clientConnId = *conn->clientConnectionId;
    conn->connIdAlgo = connIdAlgo_.get();
    conn->serverConnectionId = connIdAlgo_->encodeConnectionId(params);
    return conn;
  }

  std::unique_ptr<QuicClientConnectionState> createClientConn() {
    auto conn = std::make_unique<QuicClientConnectionState>();
    conn->clientConnectionId = getTestConnectionId();
    conn->version = QuicVersion::MVFST;
    conn->ackStates.initialAckState.nextPacketNum = 1;
    conn->ackStates.handshakeAckState.nextPacketNum = 1;
    conn->ackStates.appDataAckState.nextPacketNum = 1;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn->flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn->infoCallback = transportInfoCb_.get();
    // create a serverConnectionId that is different from the client connId
    // with bits for processId and workerId set to 0
    ServerConnectionIdParams params(0, 0, 0);
    params.clientConnId = *conn->clientConnectionId;
    conn->connIdAlgo = connIdAlgo_.get();
    conn->serverConnectionId = connIdAlgo_->encodeConnectionId(params);
    return conn;
  }

  EventBase evb;
  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
  MockLossTimeout timeout;
  std::unique_ptr<MockQuicStats> transportInfoCb_;
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
};

auto testingLossMarkFunc(std::vector<PacketNum>& lostPackets) {
  return [&lostPackets](
             auto& /* conn */, auto& packet, bool processed, PacketNum) {
    if (!processed) {
      auto packetNum = folly::variant_match(packet.header, [](const auto& h) {
        return h.getPacketSequenceNum();
      });
      lostPackets.push_back(packetNum);
    }
  };
}

PacketNum QuicLossFunctionsTest::sendPacket(
    QuicConnectionStateBase& conn,
    TimePoint time,
    bool pureAck,
    folly::Optional<PacketEvent> associatedEvent,
    PacketType packetType) {
  folly::Optional<PacketHeader> header;
  bool isHandshake = false;
  switch (packetType) {
    case PacketType::Handshake:
      header = LongHeader(
          LongHeader::Types::Handshake,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.handshakeAckState.nextPacketNum,
          *conn.version);
      isHandshake = true;
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
  auto packetNumberSpace = folly::variant_match(
      *header, [](const auto& h) { return h.getPacketNumberSpace(); });

  RegularQuicPacketBuilder builder(
      conn.udpSendPacketLen,
      std::move(*header),
      getAckState(conn, packetNumberSpace).largestAckedByPeer);
  EXPECT_TRUE(builder.canBuildPacket());
  auto packet = std::move(builder).buildPacket();
  uint32_t encodedSize = 0;
  if (packet.header) {
    encodedSize += packet.header->computeChainDataLength();
  }
  if (packet.body) {
    encodedSize += packet.body->computeChainDataLength();
  }
  auto outstandingPacket = OutstandingPacket(
      packet.packet, time, encodedSize, isHandshake, pureAck, encodedSize);
  outstandingPacket.associatedEvent = associatedEvent;
  if (isHandshake) {
    conn.outstandingHandshakePacketsCount++;
    conn.lossState.lastHandshakePacketSentTime = time;
  }
  if (pureAck) {
    conn.outstandingPureAckPacketsCount++;
  } else {
    conn.lossState.lastRetransmittablePacketSentTime = time;
  }
  if (!pureAck && conn.congestionController) {
    conn.congestionController->onPacketSent(outstandingPacket);
  }
  if (associatedEvent) {
    conn.outstandingClonedPacketsCount++;
    // Simulates what the real writer does.
    auto it = std::find_if(
        conn.outstandingPackets.begin(),
        conn.outstandingPackets.end(),
        [&associatedEvent](const auto& packet) {
          auto packetNum = folly::variant_match(
              packet.packet.header,
              [](const auto& h) { return h.getPacketSequenceNum(); });
          return packetNum == *associatedEvent;
        });
    if (it != conn.outstandingPackets.end()) {
      if (!it->associatedEvent) {
        conn.outstandingPacketEvents.emplace(*associatedEvent);
        conn.outstandingClonedPacketsCount++;
        it->associatedEvent = *associatedEvent;
      }
    }
  }
  conn.outstandingPackets.emplace_back(std::move(outstandingPacket));
  conn.lossState.largestSent = getNextPacketNum(conn, packetNumberSpace);
  increaseNextPacketNum(conn, packetNumberSpace);
  conn.pendingEvents.setLossDetectionAlarm = true;
  return conn.lossState.largestSent;
}

TEST_F(QuicLossFunctionsTest, AllPacketsProcessed) {
  auto conn = createConn();
  EXPECT_CALL(*transportInfoCb_, onPTO()).Times(0);
  auto pkt1 = conn->ackStates.appDataAckState.nextPacketNum;
  sendPacket(*conn, Clock::now(), false, pkt1, PacketType::OneRtt);
  auto pkt2 = conn->ackStates.appDataAckState.nextPacketNum;
  sendPacket(*conn, Clock::now(), false, pkt2, PacketType::OneRtt);
  auto pkt3 = conn->ackStates.appDataAckState.nextPacketNum;
  sendPacket(*conn, Clock::now(), false, pkt3, PacketType::OneRtt);
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicLossFunctionsTest, HasDataToWrite) {
  auto conn = createConn();
  // There needs to be at least one outstanding packet.
  sendPacket(*conn, Clock::now(), false, folly::none, PacketType::OneRtt);
  conn->streamManager->addLoss(1);
  conn->pendingEvents.setLossDetectionAlarm = true;
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  EXPECT_CALL(timeout, scheduleLossTimeout(_)).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicLossFunctionsTest, NoLossTimeoutIfOnlyPureAcksAreOutstanding) {
  auto conn = createConn();
  conn->pendingEvents.setLossDetectionAlarm = true;
  EXPECT_TRUE(conn->outstandingPackets.empty());
  EXPECT_EQ(0, conn->outstandingPureAckPacketsCount);

  // Empty outstandingPackets: no timer scheduled
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);

  TimePoint now = Clock::now();
  // Only pure acks outstanding: no timer scheduled
  sendPacket(*conn, now, true, folly::none, PacketType::OneRtt);
  EXPECT_TRUE(conn->pendingEvents.setLossDetectionAlarm);
  EXPECT_EQ(1, conn->outstandingPackets.size());
  EXPECT_EQ(1, conn->outstandingPureAckPacketsCount);
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);

  // Non-pure ack outstanding: timer scheduled
  sendPacket(*conn, now, false, folly::none, PacketType::Handshake);
  EXPECT_TRUE(conn->pendingEvents.setLossDetectionAlarm);
  EXPECT_EQ(2, conn->outstandingPackets.size());
  EXPECT_EQ(1, conn->outstandingPureAckPacketsCount);
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  EXPECT_CALL(timeout, scheduleLossTimeout(_)).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);

  // Non-pure poped from outstanding: no timer scheduled
  conn->outstandingPackets.pop_back();
  conn->pendingEvents.setLossDetectionAlarm = true;
  EXPECT_EQ(1, conn->outstandingPackets.size());
  EXPECT_EQ(1, conn->outstandingPureAckPacketsCount);
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicLossFunctionsTest, TestOnLossDetectionAlarm) {
  auto conn = createConn();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  sendPacket(*conn, Clock::now(), false, folly::none, PacketType::OneRtt);
  MockClock::mockNow = []() { return TimePoint(123ms); };
  std::vector<PacketNum> lostPacket;
  MockClock::mockNow = []() { return TimePoint(23ms); };
  EXPECT_CALL(*transportInfoCb_, onPTO());
  setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
  EXPECT_EQ(LossState::AlarmMethod::PTO, conn->lossState.currentAlarmMethod);
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPacket)), MockClock>(
      *conn, testingLossMarkFunc(lostPacket));
  EXPECT_EQ(conn->lossState.ptoCount, 1);
  EXPECT_TRUE(conn->pendingEvents.setLossDetectionAlarm);
  // PTO shouldn't mark loss
  EXPECT_TRUE(lostPacket.empty());

  MockClock::mockNow = []() { return TimePoint(3ms); };
  EXPECT_CALL(*transportInfoCb_, onPTO());
  sendPacket(*conn, TimePoint(), false, folly::none, PacketType::OneRtt);
  setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _)).Times(0);
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPacket)), MockClock>(
      *conn, testingLossMarkFunc(lostPacket));
  EXPECT_EQ(conn->lossState.ptoCount, 2);
  // PTO doesn't take anything out of outstandingPackets
  EXPECT_FALSE(conn->outstandingPackets.empty());
  EXPECT_EQ(0, conn->outstandingPureAckPacketsCount);
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
  // By adding an associatedEvent that doesn't exist in the
  // outstandingPacketEvents, they are all processed and will skip lossVisitor
  for (auto i = 0; i < 10; i++) {
    sendPacket(*conn, TimePoint(), false, i, PacketType::OneRtt);
  }
  EXPECT_EQ(10, conn->outstandingPackets.size());
  std::vector<PacketNum> lostPackets;
  EXPECT_CALL(*rawCongestionController, onRemoveBytesFromInflight(_)).Times(0);
  EXPECT_CALL(*transportInfoCb_, onPTO());
  onPTOAlarm(*conn);
  EXPECT_EQ(10, conn->outstandingPackets.size());
  EXPECT_TRUE(lostPackets.empty());
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLoss) {
  folly::EventBase evb;
  MockAsyncUDPSocket socket(&evb);
  auto conn = createConn();
  EXPECT_CALL(*transportInfoCb_, onNewQuicStream()).Times(2);
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto stream2 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  writeDataToQuicStream(*stream1, buf->clone(), true);
  writeDataToQuicStream(*stream2, buf->clone(), true);

  auto packetSeqNum = conn->ackStates.handshakeAckState.nextPacketNum;
  LongHeader header(
      LongHeader::Types::Handshake,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      packetSeqNum,
      *conn->version);
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      *conn->version,
      conn->transportSettings.writeConnectionDataPacketsLimit);

  EXPECT_EQ(1, conn->outstandingPackets.size());
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  auto packetNum = folly::variant_match(
      packet.header, [](const auto& h) { return h.getPacketSequenceNum(); });
  markPacketLoss(*conn, packet, false, packetNum);
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream2->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream1->lossBuffer.size(), 1);
  EXPECT_EQ(stream2->lossBuffer.size(), 1);

  auto& buffer = stream1->lossBuffer.front();
  EXPECT_EQ(buffer.offset, 0);
  IOBufEqualTo eq;
  EXPECT_TRUE(eq(buf, buffer.data.move()));
}

TEST_F(QuicLossFunctionsTest, TestMarkCryptoLostAfterCancelRetransmission) {
  folly::EventBase evb;
  MockAsyncUDPSocket socket(&evb);
  auto conn = createConn();

  auto packetSeqNum = conn->ackStates.handshakeAckState.nextPacketNum;
  LongHeader header(
      LongHeader::Types::Handshake,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      packetSeqNum,
      *conn->version);
  writeDataToQuicStream(
      conn->cryptoState->handshakeStream, folly::IOBuf::copyBuffer("CFIN"));
  writeCryptoAndAckDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      LongHeader::Types::Handshake,
      *aead,
      *headerCipher,
      *conn->version,
      conn->transportSettings.writeConnectionDataPacketsLimit);
  ASSERT_EQ(conn->outstandingPackets.size(), 1);
  EXPECT_GT(conn->cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
  auto& packet = conn->outstandingPackets.front().packet;
  auto packetNum = folly::variant_match(
      packet.header, [](const auto& h) { return h.getPacketSequenceNum(); });
  cancelHandshakeCryptoStreamRetransmissions(*conn->cryptoState);
  markPacketLoss(*conn, packet, false, packetNum);
  EXPECT_EQ(conn->cryptoState->handshakeStream.retransmissionBuffer.size(), 0);
  EXPECT_EQ(conn->cryptoState->handshakeStream.lossBuffer.size(), 0);
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossAfterStreamReset) {
  folly::EventBase evb;
  MockAsyncUDPSocket socket(&evb);
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
  invokeStreamSendStateMachine(
      *conn,
      *stream1,
      StreamEvents::SendReset(GenericApplicationErrorCode::UNKNOWN));

  markPacketLoss(
      *conn,
      packet,
      false,
      folly::variant_match(packet.header, [](const auto& h) {
        return h.getPacketSequenceNum();
      }));

  EXPECT_TRUE(stream1->lossBuffer.empty());
  EXPECT_TRUE(stream1->retransmissionBuffer.empty());
  EXPECT_TRUE(stream1->writeBuffer.empty());
}

TEST_F(QuicLossFunctionsTest, TestReorderingThreshold) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  auto testingLossMarkFunc =
      [&lostPacket](auto& /*conn*/, auto& packet, bool, PacketNum) {
        auto packetNum = folly::variant_match(packet.header, [](const auto& h) {
          return h.getPacketSequenceNum();
        });
        lostPacket.push_back(packetNum);
      };
  for (int i = 0; i < 6; ++i) {
    sendPacket(
        *conn, Clock::now(), !(i % 2), folly::none, PacketType::Handshake);
  }
  EXPECT_EQ(6, conn->outstandingHandshakePacketsCount);
  EXPECT_EQ(3, conn->outstandingPureAckPacketsCount);
  // Assume some packets are already acked
  for (auto iter =
           getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake) + 2;
       iter <
       getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake) + 5;
       iter++) {
    if (iter->isHandshake) {
      conn->outstandingHandshakePacketsCount--;
    }
    if (iter->pureAck) {
      conn->outstandingPureAckPacketsCount--;
    }
  }
  auto firstHandshakeOpIter =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake);
  conn->outstandingPackets.erase(
      firstHandshakeOpIter + 2, firstHandshakeOpIter + 5);
  // Ack for packet 9 arrives
  auto lossEvent = detectLossPackets<decltype(testingLossMarkFunc)>(
      *conn,
      9,
      testingLossMarkFunc,
      TimePoint(90ms),
      PacketNumberSpace::Handshake);
  EXPECT_EQ(2, lossEvent->largestLostPacketNum.value());
  EXPECT_EQ(TimePoint(90ms), lossEvent->lossTime);
  // Packet 1,2 should be marked as loss
  EXPECT_EQ(lostPacket.size(), 2);
  EXPECT_EQ(lostPacket.front(), 1);
  EXPECT_EQ(lostPacket.back(), 2);

  // Packet 6 is the only thing remaining inflight, it is a handshake pkt
  EXPECT_EQ(1, conn->outstandingHandshakePacketsCount);
  EXPECT_EQ(0, conn->outstandingPureAckPacketsCount);

  // Packet 6 should remain in packet as the delta is less than threshold
  EXPECT_EQ(conn->outstandingPackets.size(), 1);
  auto packetNum = folly::variant_match(
      conn->outstandingPackets.front().packet.header,
      [](const auto& h) { return h.getPacketSequenceNum(); });
  EXPECT_EQ(packetNum, 6);
}

TEST_F(QuicLossFunctionsTest, TestHandleAckForLoss) {
  auto conn = createConn();
  conn->lossState.ptoCount = 100;
  conn->lossState.reorderingThreshold = 10;

  LongHeader longHeader(
      LongHeader::Types::Handshake,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      conn->ackStates.handshakeAckState.nextPacketNum++,
      conn->version.value());
  RegularQuicWritePacket outstandingRegularPacket(std::move(longHeader));
  auto now = Clock::now();
  conn->outstandingPackets.emplace_back(
      OutstandingPacket(outstandingRegularPacket, now, 0, false, false, 0));

  bool testLossMarkFuncCalled = false;
  auto testLossMarkFunc = [&](auto& /* conn */, auto&, bool, PacketNum) {
    testLossMarkFuncCalled = true;
  };

  CongestionController::AckEvent ackEvent;
  ackEvent.ackTime = now;
  ackEvent.largestAckedPacket = 1000;
  handleAckForLoss(
      *conn, testLossMarkFunc, ackEvent, PacketNumberSpace::Handshake);

  EXPECT_EQ(0, conn->lossState.ptoCount);
  EXPECT_TRUE(conn->outstandingPackets.empty());
  EXPECT_EQ(0, conn->outstandingPureAckPacketsCount);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
  EXPECT_TRUE(testLossMarkFuncCalled);
}

TEST_F(QuicLossFunctionsTest, TestHandleAckedPacket) {
  auto conn = createConn();
  conn->lossState.ptoCount = 10;
  conn->lossState.handshakeAlarmCount = 5;
  conn->lossState.reorderingThreshold = 10;

  sendPacket(*conn, TimePoint(), false, folly::none, PacketType::OneRtt);

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = conn->lossState.largestSent;
  ackFrame.ackBlocks.emplace_back(
      conn->lossState.largestSent, conn->lossState.largestSent);

  bool testLossMarkFuncCalled = false;
  auto testLossMarkFunc = [&](auto& /* conn */, auto&, bool, PacketNum) {
    testLossMarkFuncCalled = true;
  };

  auto ackVisitor = [&](auto&, auto&, auto&) {};

  // process and remove the acked packet.
  processAckFrame(
      *conn,
      PacketNumberSpace::AppData,
      ackFrame,
      ackVisitor,
      testLossMarkFunc,
      Clock::now());

  EXPECT_EQ(0, conn->lossState.ptoCount);
  EXPECT_EQ(0, conn->lossState.handshakeAlarmCount);
  EXPECT_TRUE(conn->outstandingPackets.empty());
  EXPECT_EQ(0, conn->outstandingPureAckPacketsCount);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
  EXPECT_FALSE(testLossMarkFuncCalled);
  ASSERT_TRUE(conn->outstandingPackets.empty());

  setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicLossFunctionsTest, TestMarkRstLoss) {
  auto conn = createConn();
  folly::EventBase evb;
  MockAsyncUDPSocket socket(&evb);

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  auto currentOffset = stream->currentWriteOffset;
  RstStreamFrame rstFrame(
      stream->id, GenericApplicationErrorCode::UNKNOWN, currentOffset);
  conn->pendingEvents.resets.insert({stream->id, rstFrame});
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      *conn->version,
      conn->transportSettings.writeConnectionDataPacketsLimit);

  EXPECT_EQ(conn->outstandingPackets.size(), 1);
  EXPECT_TRUE(conn->pendingEvents.resets.empty());
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  markPacketLoss(
      *conn,
      packet,
      false,
      folly::variant_match(packet.header, [](const auto& h) {
        return h.getPacketSequenceNum();
      }));

  EXPECT_EQ(1, conn->pendingEvents.resets.size());
  EXPECT_EQ(1, conn->pendingEvents.resets.count(stream->id));
  auto& retxRstFrame = conn->pendingEvents.resets.at(stream->id);
  EXPECT_EQ(stream->id, retxRstFrame.streamId);
  EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, retxRstFrame.errorCode);
  EXPECT_EQ(currentOffset, retxRstFrame.offset);

  // write again:
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      *conn->version,
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_TRUE(conn->pendingEvents.resets.empty());
  auto& packet2 =
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  bool rstFound = false;
  for (auto& frame : all_frames<RstStreamFrame>(packet2.frames)) {
    EXPECT_EQ(stream->id, frame.streamId);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, frame.errorCode);
    EXPECT_EQ(currentOffset, frame.offset);
    rstFound = true;
  }
  EXPECT_TRUE(rstFound);
}

TEST_F(QuicLossFunctionsTest, ReorderingThresholdChecksSamePacketNumberSpace) {
  auto conn = createConn();
  uint16_t lossVisitorCount = 0;
  auto countingLossVisitor = [&](auto& /* conn */,
                                 auto& /* packet */,
                                 bool processed,
                                 PacketNum /* currentPacketNum */) {
    if (!processed) {
      lossVisitorCount++;
    }
  };
  PacketNum latestSent = 0;
  for (size_t i = 0; i < conn->lossState.reorderingThreshold + 1; i++) {
    latestSent = sendPacket(
        *conn, Clock::now(), false, folly::none, PacketType::Handshake);
  }

  detectLossPackets(
      *conn,
      latestSent + 1,
      countingLossVisitor,
      Clock::now(),
      PacketNumberSpace::AppData);
  EXPECT_EQ(0, lossVisitorCount);

  detectLossPackets(
      *conn,
      latestSent + 1,
      countingLossVisitor,
      Clock::now(),
      PacketNumberSpace::Handshake);
  EXPECT_GT(lossVisitorCount, 0);
}

TEST_F(QuicLossFunctionsTest, TestMarkWindowUpdateLoss) {
  auto conn = createConn();
  folly::EventBase evb;
  MockAsyncUDPSocket socket(&evb);

  auto stream = conn->streamManager->createNextBidirectionalStream().value();
  conn->streamManager->queueWindowUpdate(stream->id);
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      *conn->version,
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_FALSE(conn->streamManager->hasWindowUpdates());

  EXPECT_EQ(1, conn->outstandingPackets.size());
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;

  auto packetNum = folly::variant_match(
      packet.header, [](const auto& h) { return h.getPacketSequenceNum(); });
  markPacketLoss(*conn, packet, false, packetNum);
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
        *conn, TimePoint(i * 100ms), false, folly::none, PacketType::OneRtt);
  }
  // Some packets are already acked
  conn->lossState.srtt = 400ms;
  conn->lossState.lrtt = 350ms;
  conn->outstandingPackets.erase(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 2,
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData) + 5);
  auto lossEvent = detectLossPackets<decltype(testingLossMarkFunc(lostPacket))>(
      *conn,
      largestSent,
      testingLossMarkFunc(lostPacket),
      TimePoint(900ms),
      PacketNumberSpace::AppData);
  EXPECT_EQ(2, lossEvent->largestLostPacketNum.value());
  EXPECT_EQ(TimePoint(900ms), lossEvent->lossTime);
  // Packet 1,2 should be marked as loss
  EXPECT_EQ(lostPacket.size(), 2);
  EXPECT_EQ(lostPacket.front(), 1);
  EXPECT_EQ(lostPacket.back(), 2);

  // Packet 6, 7 should remain in outstanding packet list
  EXPECT_EQ(2, conn->outstandingPackets.size());
  auto packetNum = folly::variant_match(
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)
          ->packet.header,
      [](const auto& h) { return h.getPacketSequenceNum(); });
  EXPECT_EQ(packetNum, 6);
  EXPECT_TRUE(conn->lossState.appDataLossTime);
}

TEST_F(QuicLossFunctionsTest, LossTimePreemptsCryptoTimer) {
  std::vector<PacketNum> lostPackets;
  auto conn = createConn();
  conn->lossState.srtt = 100ms;
  conn->lossState.lrtt = 100ms;
  auto expectedDelayUntilLost = 900000us / 8;
  auto sendTime = Clock::now();
  // Send two:
  sendPacket(*conn, sendTime, false, folly::none, PacketType::Handshake);
  PacketNum second = sendPacket(
      *conn, sendTime + 1ms, false, folly::none, PacketType::Handshake);
  auto lossTime = sendTime + 50ms;
  detectLossPackets<decltype(testingLossMarkFunc(lostPackets))>(
      *conn,
      second,
      testingLossMarkFunc(lostPackets),
      lossTime,
      PacketNumberSpace::Handshake);
  EXPECT_TRUE(lostPackets.empty());
  EXPECT_TRUE(conn->lossState.handshakeLossTime.hasValue());
  EXPECT_EQ(
      expectedDelayUntilLost + sendTime,
      conn->lossState.handshakeLossTime.value());

  MockClock::mockNow = [=]() { return sendTime; };
  auto alarm = calculateAlarmDuration<MockClock>(*conn);
  EXPECT_EQ(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          expectedDelayUntilLost),
      alarm.first);
  EXPECT_EQ(LossState::AlarmMethod::EarlyRetransmitOrReordering, alarm.second);
  // Manual set lossState. Calling setLossDetectionAlarm requries a Timeout
  conn->lossState.currentAlarmMethod = alarm.second;

  // Second packet gets acked:
  getAckState(*conn, PacketNumberSpace::Handshake).largestAckedByPeer = second;
  conn->outstandingPackets.pop_back();
  MockClock::mockNow = [=]() { return sendTime + expectedDelayUntilLost + 5s; };
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPackets)), MockClock>(
      *conn, testingLossMarkFunc(lostPackets));
  EXPECT_EQ(1, lostPackets.size());
  EXPECT_FALSE(conn->lossState.handshakeLossTime.hasValue());
  EXPECT_TRUE(conn->outstandingPackets.empty());
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
    sendPacket(*conn, startTime, false, folly::none, PacketType::OneRtt);
    setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
    startTime += 1ms;
  }
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _)).Times(0);
  EXPECT_CALL(*transportInfoCb_, onPTO());
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPackets)), MockClock>(
      *conn, testingLossMarkFunc(lostPackets));
  EXPECT_EQ(1, conn->lossState.ptoCount);
  // Hey PTOs are not losses either from now on
  EXPECT_TRUE(lostPackets.empty());
}

TEST_F(
    QuicLossFunctionsTest,
    WhenHandshakeOutstandingAlarmMarksAllHandshakeAsLoss) {
  auto conn = createConn();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());
  std::vector<PacketNum> lostPackets;
  PacketNum expectedLargestLostNum = 0;
  conn->lossState.currentAlarmMethod = LossState::AlarmMethod::Handshake;
  for (auto i = 0; i < 10; i++) {
    // Half are handshakes
    auto sentPacketNum = sendPacket(
        *conn,
        TimePoint(100ms),
        false,
        folly::none,
        (i % 2 ? PacketType::OneRtt : PacketType::Handshake));
    expectedLargestLostNum = std::max(
        expectedLargestLostNum, i % 2 ? sentPacketNum : expectedLargestLostNum);
  }
  uint64_t expectedLostBytes = std::accumulate(
      conn->outstandingPackets.begin(),
      conn->outstandingPackets.end(),
      0,
      [](uint64_t num, const OutstandingPacket& packet) {
        return packet.isHandshake ? num + packet.encodedSize : num;
      });
  EXPECT_CALL(
      *rawCongestionController, onRemoveBytesFromInflight(expectedLostBytes))
      .Times(1);
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPackets)), Clock>(
      *conn, testingLossMarkFunc(lostPackets));

  // Half are lost
  EXPECT_EQ(5, lostPackets.size());
  EXPECT_EQ(1, conn->lossState.handshakeAlarmCount);
  EXPECT_EQ(5, conn->lossState.timeoutBasedRtxCount);
  EXPECT_EQ(conn->pendingEvents.numProbePackets, 0);
  EXPECT_EQ(5, conn->lossState.rtxCount);
}

TEST_F(QuicLossFunctionsTest, HandshakeAlarmWithOneRttCipher) {
  auto conn = createClientConn();
  conn->oneRttWriteCipher = createNoOpAead();
  conn->lossState.currentAlarmMethod = LossState::AlarmMethod::Handshake;
  std::vector<PacketNum> lostPackets;
  sendPacket(
      *conn, TimePoint(100ms), false, folly::none, PacketType::Handshake);
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPackets)), Clock>(
      *conn, testingLossMarkFunc(lostPackets));

  // Half should be marked as loss
  EXPECT_EQ(lostPackets.size(), 1);
  EXPECT_EQ(conn->lossState.handshakeAlarmCount, 1);
  EXPECT_EQ(conn->pendingEvents.numProbePackets, kPacketToSendForPTO);
}

TEST_F(QuicLossFunctionsTest, PureAckSkipsCongestionControl) {
  std::vector<PacketNum> lostPacket;
  auto conn = createConn();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());

  for (int i = 0; i < 5; ++i) {
    bool pureAck = (i == 3);
    sendPacket(*conn, TimePoint(), pureAck, folly::none, PacketType::Handshake);
  }

  // Verify that bytes for pure ack pkt won't be counted in lost bytes
  auto sumNoPureAckBytes = std::accumulate(
      conn->outstandingPackets.begin(),
      conn->outstandingPackets.end(),
      0,
      [](uint64_t bytes, const OutstandingPacket& p) {
        if (p.pureAck) {
          return bytes;
        }
        return bytes + p.encodedSize;
      });

  // Ack for packet 9 arrives
  auto lossEvent = detectLossPackets<decltype(testingLossMarkFunc(lostPacket))>(
      *conn,
      9,
      testingLossMarkFunc(lostPacket),
      TimePoint(80ms),
      PacketNumberSpace::Handshake);
  EXPECT_EQ(5, lossEvent->largestLostPacketNum.value());
  EXPECT_EQ(sumNoPureAckBytes, lossEvent->lostBytes);
  EXPECT_EQ(TimePoint(80ms), lossEvent->lossTime);
  EXPECT_EQ(conn->outstandingHandshakePacketsCount, 0);
}

TEST_F(QuicLossFunctionsTest, EmptyOutstandingNoTimeout) {
  auto conn = createConn();
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  setLossDetectionAlarm(*conn, timeout);
}

TEST_F(QuicLossFunctionsTest, AlarmDurationHandshakeOutstanding) {
  auto conn = createConn();
  conn->lossState.maxAckDelay = 25ms;
  TimePoint lastPacketSentTime = Clock::now();
  std::chrono::milliseconds packetSentDelay = 10ms;
  auto thisMoment = lastPacketSentTime + packetSentDelay;
  MockClock::mockNow = [=]() { return thisMoment; };
  sendPacket(
      *conn, lastPacketSentTime, false, folly::none, PacketType::Handshake);

  MockClock::mockNow = [=]() { return thisMoment; };
  auto duration = calculateAlarmDuration<MockClock>(*conn);
  EXPECT_EQ(kDefaultInitialRtt * 2 - packetSentDelay + 25ms, duration.first);
  EXPECT_EQ(duration.second, LossState::AlarmMethod::Handshake);

  conn->lossState.srtt = 100ms;
  duration = calculateAlarmDuration<MockClock>(*conn);
  EXPECT_EQ(
      std::chrono::duration_cast<std::chrono::milliseconds>(225ms) -
          packetSentDelay,
      duration.first);

  conn->lossState.maxAckDelay = 45ms;
  conn->lossState.handshakeAlarmCount = 2;
  duration = calculateAlarmDuration<MockClock>(*conn);
  EXPECT_EQ(
      std::chrono::duration_cast<std::chrono::milliseconds>(980ms) -
          packetSentDelay,
      duration.first);
}

TEST_F(QuicLossFunctionsTest, AlarmDurationHasLossTime) {
  auto conn = createConn();
  TimePoint lastPacketSentTime = Clock::now();
  auto thisMoment = lastPacketSentTime;
  MockClock::mockNow = [=]() { return thisMoment; };
  conn->lossState.appDataLossTime = thisMoment + 100ms;
  conn->lossState.srtt = 200ms;
  conn->lossState.lrtt = 150ms;

  sendPacket(*conn, lastPacketSentTime, false, folly::none, PacketType::OneRtt);
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
  conn->lossState.appDataLossTime = lastPacketSentTime + 100ms;
  conn->lossState.srtt = 200ms;
  conn->lossState.lrtt = 150ms;

  sendPacket(*conn, lastPacketSentTime, false, folly::none, PacketType::OneRtt);
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
  sendPacket(*conn, lastPacketSentTime, false, folly::none, PacketType::OneRtt);
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
  auto countingLossVisitor = [&](auto& /* conn */,
                                 auto& /* packet */,
                                 bool processed,
                                 PacketNum /* currentPacketNum */) {
    if (!processed) {
      lossVisitorCount++;
    }
  };
  // Send 5 packets, so when we ack the last one, we mark the first one loss
  PacketNum lastSent;
  for (size_t i = 0; i < 5; i++) {
    lastSent =
        sendPacket(*conn, Clock::now(), false, folly::none, PacketType::OneRtt);
  }
  detectLossPackets(
      *conn,
      lastSent,
      countingLossVisitor,
      TimePoint(100ms),
      PacketNumberSpace::AppData);
  EXPECT_EQ(1, lossVisitorCount);
}

TEST_F(QuicLossFunctionsTest, SkipLossVisitor) {
  auto conn = createConn();
  conn->congestionController.reset();
  // make srtt large so delayUntilLost won't kick in
  conn->lossState.srtt = 1000000000us;
  uint16_t lossVisitorCount = 0;
  auto countingLossVisitor = [&](auto& /* conn */,
                                 auto& /* packet */,
                                 bool processed,
                                 PacketNum /* currentPacketNum */) {
    if (!processed) {
      lossVisitorCount++;
    }
  };
  // Send 5 packets, so when we ack the last one, we mark the first one loss
  PacketNum lastSent;
  for (size_t i = 0; i < 5; i++) {
    lastSent = conn->ackStates.appDataAckState.nextPacketNum;
    sendPacket(*conn, Clock::now(), false, lastSent, PacketType::OneRtt);
  }
  detectLossPackets(
      *conn,
      lastSent,
      countingLossVisitor,
      TimePoint(100ms),
      PacketNumberSpace::AppData);
  EXPECT_EQ(0, lossVisitorCount);
}

TEST_F(QuicLossFunctionsTest, NoDoubleProcess) {
  auto conn = createConn();
  conn->congestionController.reset();
  // make srtt large so delayUntilLost won't kick in
  conn->lossState.srtt = 1000000000us;

  uint16_t lossVisitorCount = 0;
  auto countingLossVisitor = [&](auto& /* conn */,
                                 auto& /* packet */,
                                 bool processed,
                                 PacketNum /* currentPacketNum */) {
    if (!processed) {
      lossVisitorCount++;
    }
  };
  // Send 6 packets, so when we ack the last one, we mark the first two loss
  PacketNum lastSent;
  PacketEvent event = 0;
  for (size_t i = 0; i < 6; i++) {
    lastSent =
        sendPacket(*conn, Clock::now(), false, event, PacketType::OneRtt);
  }
  EXPECT_EQ(6, conn->outstandingPackets.size());
  // Add the PacketEvent to the outstandingPacketEvents set
  conn->outstandingPacketEvents.insert(event);

  // Ack the last sent packet. Despite two losses, lossVisitor only visit one
  // packet
  detectLossPackets(
      *conn,
      lastSent,
      countingLossVisitor,
      TimePoint(100ms),
      PacketNumberSpace::AppData);
  EXPECT_EQ(1, lossVisitorCount);
  EXPECT_EQ(4, conn->outstandingPackets.size());
}

TEST_F(QuicLossFunctionsTest, DetectPacketLossClonedPacketsCounter) {
  auto conn = createConn();
  auto packet1 = conn->ackStates.appDataAckState.nextPacketNum;
  sendPacket(*conn, Clock::now(), false, packet1, PacketType::OneRtt);
  sendPacket(*conn, Clock::now(), false, folly::none, PacketType::OneRtt);
  sendPacket(*conn, Clock::now(), false, folly::none, PacketType::OneRtt);
  sendPacket(*conn, Clock::now(), false, folly::none, PacketType::OneRtt);
  auto ackedPacket =
      sendPacket(*conn, Clock::now(), false, folly::none, PacketType::OneRtt);
  auto noopLossMarker = [](auto&, auto&, bool, PacketNum) {};
  detectLossPackets<decltype(noopLossMarker)>(
      *conn,
      ackedPacket,
      noopLossMarker,
      Clock::now(),
      PacketNumberSpace::AppData);
  EXPECT_EQ(0, conn->outstandingClonedPacketsCount);
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossProcessedPacket) {
  MockAsyncUDPSocket socket(&evb);
  auto conn = createConn();
  ASSERT_TRUE(conn->outstandingPackets.empty());
  ASSERT_TRUE(conn->outstandingPacketEvents.empty());
  auto stream1 = conn->streamManager->createNextBidirectionalStream().value();
  auto buf = folly::IOBuf::copyBuffer("I wrestled by the sea.");
  auto stream2 = conn->streamManager->createNextBidirectionalStream().value();
  conn->streamManager->queueWindowUpdate(stream2->id);
  conn->pendingEvents.connWindowUpdate = true;
  auto nextPacketNum = conn->ackStates.appDataAckState.nextPacketNum;
  // writeQuicPacket will call writeQuicDataToSocket which will also take care
  // of sending the MaxStreamDataFrame for stream2
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
  ASSERT_EQ(1, conn->outstandingPackets.size());
  ASSERT_TRUE(conn->outstandingPacketEvents.empty());
  uint32_t streamDataCounter = 0, streamWindowUpdateCounter = 0,
           connWindowUpdateCounter = 0;
  for (const auto& frame :
       getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)
           ->packet.frames) {
    folly::variant_match(
        frame,
        [&](const WriteStreamFrame&) { streamDataCounter++; },
        [&](const MaxStreamDataFrame&) { streamWindowUpdateCounter++; },
        [&](const MaxDataFrame&) { connWindowUpdateCounter++; },
        [](const auto&) { ASSERT_TRUE(false); });
  }
  EXPECT_EQ(1, streamDataCounter);
  EXPECT_EQ(1, streamWindowUpdateCounter);
  EXPECT_EQ(1, connWindowUpdateCounter);
  // Force this packet to be a processed clone
  markPacketLoss(*conn, packet, true, nextPacketNum);
  EXPECT_EQ(1, stream1->retransmissionBuffer.size());
  EXPECT_TRUE(stream1->lossBuffer.empty());

  // Window update though, will still be marked loss
  EXPECT_TRUE(conn->streamManager->pendingWindowUpdate(stream2->id));
  EXPECT_TRUE(conn->pendingEvents.connWindowUpdate);
}

TEST_F(QuicLossFunctionsTest, TestTotalPTOCount) {
  auto conn = createConn();
  conn->lossState.totalPTOCount = 100;
  EXPECT_CALL(*transportInfoCb_, onPTO());
  onPTOAlarm(*conn);
  EXPECT_EQ(101, conn->lossState.totalPTOCount);
}

TEST_F(QuicLossFunctionsTest, TestExceedsMaxPTOThrows) {
  auto conn = createConn();
  conn->transportSettings.maxNumPTOs = 3;
  EXPECT_CALL(*transportInfoCb_, onPTO()).Times(3);
  onPTOAlarm(*conn);
  onPTOAlarm(*conn);
  EXPECT_THROW(onPTOAlarm(*conn), QuicInternalException);
}

TEST_F(QuicLossFunctionsTest, TotalLossCount) {
  auto conn = createConn();
  conn->congestionController = nullptr;
  PacketNum largestSent = 0;
  for (int i = 0; i < 10; i++) {
    largestSent =
        sendPacket(*conn, Clock::now(), false, folly::none, PacketType::OneRtt);
  }
  EXPECT_EQ(10, conn->outstandingPackets.size());
  uint32_t lostPackets = 0;
  auto countingLossVisitor = [&](auto& /* conn */,
                                 auto& /* packet */,
                                 bool processed,
                                 PacketNum /* currentPacketNum */) {
    if (!processed) {
      lostPackets++;
    }
  };

  conn->lossState.rtxCount = 135;
  detectLossPackets(
      *conn,
      largestSent,
      countingLossVisitor,
      TimePoint(100ms),
      PacketNumberSpace::AppData);
  EXPECT_EQ(135 + lostPackets, conn->lossState.rtxCount);
}

TEST_F(QuicLossFunctionsTest, TestZeroRttRejected) {
  auto conn = createConn();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn->congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(Return());
  // By adding an associatedEvent that doesn't exist in the
  // outstandingPacketEvents, they are all processed and will skip lossVisitor
  for (auto i = 0; i < 2; i++) {
    sendPacket(*conn, TimePoint(), false, folly::none, PacketType::OneRtt);
    sendPacket(*conn, TimePoint(), false, folly::none, PacketType::ZeroRtt);
  }
  EXPECT_FALSE(conn->outstandingPackets.empty());
  EXPECT_EQ(4, conn->outstandingPackets.size());
  std::vector<std::pair<PacketNum, bool>> lostPackets;
  // onRemoveBytesFromInflight should still happen
  EXPECT_CALL(*rawCongestionController, onRemoveBytesFromInflight(_)).Times(1);
  markZeroRttPacketsLost(
      *conn, [&lostPackets](auto&, auto&, bool processed, PacketNum packetNum) {
        lostPackets.emplace_back(packetNum, processed);
      });
  EXPECT_EQ(2, conn->outstandingPackets.size());
  EXPECT_EQ(lostPackets.size(), 2);
  for (auto lostPacket : lostPackets) {
    EXPECT_FALSE(lostPacket.second);
  }
  for (size_t i = 0; i < conn->outstandingPackets.size(); ++i) {
    auto longHeader =
        boost::get<LongHeader>(&conn->outstandingPackets[i].packet.header);
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
  // By adding an associatedEvent that doesn't exist in the
  // outstandingPacketEvents, they are all processed and will skip lossVisitor
  std::set<PacketNum> zeroRttPackets;
  folly::Optional<PacketNum> lastPacket;
  for (auto i = 0; i < 2; i++) {
    lastPacket =
        sendPacket(*conn, TimePoint(), false, lastPacket, PacketType::ZeroRtt);
    zeroRttPackets.emplace(*lastPacket);
  }
  zeroRttPackets.emplace(
      sendPacket(*conn, TimePoint(), false, folly::none, PacketType::ZeroRtt));
  for (auto zeroRttPacketNum : zeroRttPackets) {
    lastPacket = sendPacket(
        *conn, TimePoint(), false, zeroRttPacketNum, PacketType::OneRtt);
  }

  EXPECT_EQ(6, conn->outstandingPackets.size());
  ASSERT_EQ(conn->outstandingClonedPacketsCount, 6);
  ASSERT_EQ(conn->outstandingPacketEvents.size(), 2);

  std::vector<std::pair<PacketNum, bool>> lostPackets;
  // onRemoveBytesFromInflight should still happen
  EXPECT_CALL(*rawCongestionController, onRemoveBytesFromInflight(_)).Times(1);
  markZeroRttPacketsLost(
      *conn, [&lostPackets](auto&, auto&, bool processed, PacketNum packetNum) {
        lostPackets.emplace_back(packetNum, processed);
      });
  ASSERT_EQ(conn->outstandingPacketEvents.size(), 0);
  EXPECT_EQ(3, conn->outstandingPackets.size());
  EXPECT_EQ(lostPackets.size(), 3);
  ASSERT_EQ(conn->outstandingClonedPacketsCount, 3);
  size_t numProcessed = 0;
  for (auto lostPacket : lostPackets) {
    numProcessed += lostPacket.second;
  }
  EXPECT_EQ(numProcessed, 1);
  for (size_t i = 0; i < conn->outstandingPackets.size(); ++i) {
    auto longHeader =
        boost::get<LongHeader>(&conn->outstandingPackets[i].packet.header);
    EXPECT_FALSE(
        longHeader &&
        longHeader->getProtectionType() == ProtectionType::ZeroRtt);
  }
}

TEST_F(QuicLossFunctionsTest, PTOLargerThanMaxDelay) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.lossState.maxAckDelay = 20s;
  EXPECT_GE(calculatePTO(conn), 20s);
}

TEST_F(QuicLossFunctionsTest, TimeThreshold) {
  auto conn = createConn();
  conn->lossState.srtt = 10ms;
  auto referenceTime = Clock::now();
  auto packet1 = sendPacket(
      *conn, referenceTime - 10ms, false, folly::none, PacketType::OneRtt);
  auto packet2 = sendPacket(
      *conn,
      referenceTime + conn->lossState.srtt / 2,
      false,
      folly::none,
      PacketType::OneRtt);
  auto lossVisitor = [&](const auto& /*conn*/,
                         const auto& /*packet*/,
                         bool,
                         PacketNum packetNum) {
    EXPECT_EQ(packet1, packetNum);
  };
  detectLossPackets<decltype(lossVisitor)>(
      *conn,
      packet2,
      lossVisitor,
      referenceTime + conn->lossState.srtt * 9 / 8 + 5ms,
      PacketNumberSpace::AppData);
}

TEST_P(QuicLossFunctionsTest, CappedShiftNoCrash) {
  auto conn = createConn();
  conn->lossState.handshakeAlarmCount =
      std::numeric_limits<decltype(conn->lossState.handshakeAlarmCount)>::max();
  sendPacket(*conn, Clock::now(), false, folly::none, PacketType::Handshake);
  ASSERT_GT(conn->outstandingHandshakePacketsCount, 0);
  calculateAlarmDuration(*conn);

  conn->lossState.handshakeAlarmCount = 0;
  conn->outstandingHandshakePacketsCount = 0;
  conn->outstandingPackets.clear();
  conn->lossState.ptoCount =
      std::numeric_limits<decltype(conn->lossState.ptoCount)>::max();
  sendPacket(*conn, Clock::now(), false, folly::none, PacketType::OneRtt);
  calculateAlarmDuration(*conn);
}

TEST_F(QuicLossFunctionsTest, PersistentCongestion) {
  auto conn = createConn();
  auto currentTime = Clock::now();
  conn->lossState.srtt = 1s;
  EXPECT_TRUE(isPersistentCongestion(*conn, currentTime - 10s, currentTime));
  EXPECT_TRUE(isPersistentCongestion(*conn, currentTime - 3s, currentTime));
  EXPECT_TRUE(isPersistentCongestion(
      *conn, currentTime - (1s * kPersistentCongestionThreshold), currentTime));
  EXPECT_FALSE(isPersistentCongestion(
      *conn,
      currentTime - (1s * kPersistentCongestionThreshold) + 1us,
      currentTime));
  EXPECT_FALSE(isPersistentCongestion(*conn, currentTime - 2s, currentTime));
  EXPECT_FALSE(isPersistentCongestion(*conn, currentTime - 100ms, currentTime));

  conn->lossState.rttvar = 2s;
  conn->lossState.maxAckDelay = 5s;
  EXPECT_TRUE(isPersistentCongestion(*conn, currentTime - 42s, currentTime));
  EXPECT_TRUE(isPersistentCongestion(*conn, currentTime - 43s, currentTime));
  EXPECT_FALSE(
      isPersistentCongestion(*conn, currentTime - 42s + 1ms, currentTime));
  EXPECT_FALSE(isPersistentCongestion(*conn, currentTime - 100us, currentTime));
}

INSTANTIATE_TEST_CASE_P(
    QuicLossFunctionsTests,
    QuicLossFunctionsTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));

} // namespace test
} // namespace quic
