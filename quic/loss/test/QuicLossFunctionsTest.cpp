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

#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <folly/io/async/test/MockTimeoutManager.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/test/TestUtils.h>
#include <quic/d6d/test/Mocks.h>
#include <quic/dsr/Types.h>
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
          &quic::OutstandingPacket::lossReorderDistance,
          testing::Property(
              &folly::Optional<uint32_t>::hasValue,
              testing::Eq(lostByReorder))),
      testing::Field(
          &quic::OutstandingPacket::lossTimeoutDividend,
          testing::Property(
              &folly::Optional<quic::DurationRep>::hasValue,
              testing::Eq(lostByTimeout))),
      testing::Field(
          &quic::OutstandingPacket::packet,
          testing::Field(
              &quic::RegularPacket::header,
              testing::Property(
                  &quic::PacketHeader::getPacketSequenceNum, packetNum))));
}
} // namespace

namespace quic {
namespace test {

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

struct PMTUBlackholeDetectionTestFixture; // Forward declaration

class QuicLossFunctionsTest : public TestWithParam<PacketNumberSpace> {
 public:
  void SetUp() override {
    aead = createNoOpAead();
    headerCipher = createNoOpHeaderCipher();
    quicStats_ = std::make_unique<MockQuicStats>();
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
    socket_ = std::make_unique<MockQuicSocket>();
  }

  PacketNum sendPacket(
      QuicConnectionStateBase& conn,
      TimePoint time,
      folly::Optional<PacketEvent> associatedEvent,
      PacketType packetType,
      bool isD6DProbe = false,
      folly::Optional<uint16_t> forcedSize = folly::none);

  std::unique_ptr<QuicServerConnectionState> createConn() {
    auto conn = std::make_unique<QuicServerConnectionState>(
        FizzServerQuicHandshakeContext::Builder().build());
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
    conn->statsCallback = quicStats_.get();
    // create a serverConnectionId that is different from the client connId
    // with bits for processId and workerId set to 0
    ServerConnectionIdParams params(0, 0, 0);
    conn->connIdAlgo = connIdAlgo_.get();
    conn->serverConnectionId = *connIdAlgo_->encodeConnectionId(params);
    // for canSetLossTimerForAppData()
    conn->oneRttWriteCipher = createNoOpAead();
    conn->observerContainer =
        std::make_shared<SocketObserverContainer>(socket_.get());
    return conn;
  }

  std::unique_ptr<QuicClientConnectionState> createClientConn() {
    auto conn = std::make_unique<QuicClientConnectionState>(
        FizzClientQuicHandshakeContext::Builder().build());
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
    conn->statsCallback = quicStats_.get();
    // create a serverConnectionId that is different from the client connId
    // with bits for processId and workerId set to 0
    ServerConnectionIdParams params(0, 0, 0);
    conn->serverConnectionId = *connIdAlgo_.get()->encodeConnectionId(params);
    return conn;
  }

  void runDetectPMTUBlackholeTest(
      QuicConnectionStateBase* conn,
      PMTUBlackholeDetectionTestFixture fixture);

  EventBase evb;
  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
  MockLossTimeout timeout;
  std::unique_ptr<MockQuicStats> quicStats_;
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  std::unique_ptr<MockQuicSocket> socket_;

  auto getLossPacketMatcher(
      PacketNum packetNum,
      bool lossByReorder,
      bool lossByTimeout) {
    return MockLegacyObserver::getLossPacketMatcher(
        packetNum, lossByReorder, lossByTimeout);
  }
};

auto testingLossMarkFunc(std::vector<PacketNum>& lostPackets) {
  return [&lostPackets](auto& /* conn */, auto& packet, bool processed) {
    if (!processed) {
      auto packetNum = packet.header.getPacketSequenceNum();
      lostPackets.push_back(packetNum);
    }
  };
}

PacketNum QuicLossFunctionsTest::sendPacket(
    QuicConnectionStateBase& conn,
    TimePoint time,
    folly::Optional<PacketEvent> associatedEvent,
    PacketType packetType,
    bool isD6DProbe,
    folly::Optional<uint16_t> forcedSize) {
  folly::Optional<PacketHeader> header;
  bool isHandshake = false;
  switch (packetType) {
    case PacketType::Initial:
      header = LongHeader(
          LongHeader::Types::Initial,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          conn.ackStates.initialAckState.nextPacketNum,
          *conn.version);
      isHandshake = true;
      break;
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
  builder.encodePacketHeader();
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
  if (packet.header) {
    encodedSize += packet.header->computeChainDataLength();
  }
  if (packet.body) {
    encodedSize += packet.body->computeChainDataLength();
    encodedBodySize += packet.body->computeChainDataLength();
  }
  auto outstandingPacket = OutstandingPacket(
      packet.packet,
      time,
      encodedSize,
      encodedBodySize,
      isHandshake,
      isD6DProbe,
      encodedSize,
      encodedBodySize,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  outstandingPacket.associatedEvent = associatedEvent;
  conn.lossState.lastRetransmittablePacketSentTime = time;
  if (conn.congestionController) {
    conn.congestionController->onPacketSent(outstandingPacket);
  }
  if (associatedEvent) {
    conn.outstandings.clonedPacketCount[packetNumberSpace]++;
    // Simulates what the real writer does.
    auto it = std::find_if(
        conn.outstandings.packets.begin(),
        conn.outstandings.packets.end(),
        [&associatedEvent](const auto& packet) {
          auto packetNum = packet.packet.header.getPacketSequenceNum();
          auto packetNumSpace = packet.packet.header.getPacketNumberSpace();
          return packetNum == associatedEvent->packetNumber &&
              packetNumSpace == associatedEvent->packetNumberSpace;
        });
    if (it != conn.outstandings.packets.end()) {
      if (!it->associatedEvent) {
        conn.outstandings.packetEvents.emplace(*associatedEvent);
        conn.outstandings.clonedPacketCount[packetNumberSpace]++;
        it->associatedEvent = *associatedEvent;
      }
    }
  } else {
    conn.outstandings.packetCount[packetNumberSpace]++;
  }
  conn.outstandings.packets.emplace_back(std::move(outstandingPacket));
  conn.lossState.largestSent = getNextPacketNum(conn, packetNumberSpace);
  increaseNextPacketNum(conn, packetNumberSpace);
  conn.pendingEvents.setLossDetectionAlarm = true;
  if (isD6DProbe) {
    ++conn.d6d.outstandingProbes;
    conn.d6d.lastProbe =
        D6DProbePacket(encodedSize, conn.lossState.largestSent.value());
  }
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
  PacketEvent packetEvent1(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  sendPacket(*conn, Clock::now(), packetEvent1, PacketType::OneRtt);
  PacketEvent packetEvent2(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  sendPacket(*conn, Clock::now(), packetEvent2, PacketType::OneRtt);
  PacketEvent packetEvent3(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  sendPacket(*conn, Clock::now(), packetEvent3, PacketType::OneRtt);
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicLossFunctionsTest, HasDataToWrite) {
  auto conn = createConn();
  // There needs to be at least one outstanding packet.
  sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
  conn->streamManager->addLoss(1);
  conn->pendingEvents.setLossDetectionAlarm = true;
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(2);
  EXPECT_CALL(timeout, scheduleLossTimeout(_)).Times(1);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicLossFunctionsTest, D6DProbeDoesNotSetLossDetectionAlarms) {
  auto conn = createConn();
  sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt, true);
  conn->pendingEvents.setLossDetectionAlarm = true;
  EXPECT_CALL(timeout, cancelLossTimeout()).Times(1);
  EXPECT_CALL(timeout, scheduleLossTimeout(_)).Times(0);
  setLossDetectionAlarm(*conn, timeout);
  EXPECT_FALSE(conn->pendingEvents.setLossDetectionAlarm);
}

TEST_F(QuicLossFunctionsTest, D6DProbeExcludedInLossEvent) {
  auto conn = createConn();
  // 0 rtt means all packets are automatically lost upon sending
  conn->lossState.srtt = 0s;
  conn->lossState.lrtt = 0s;
  auto currentTime = Clock::now();
  auto firstPacketNum =
      sendPacket(*conn, currentTime, folly::none, PacketType::OneRtt, true);
  auto secondPacketNum =
      sendPacket(*conn, currentTime, folly::none, PacketType::OneRtt, true);
  ASSERT_GT(secondPacketNum, firstPacketNum);
  ASSERT_EQ(2, conn->outstandings.packets.size());
  auto lossVisitor = [](auto&, auto&, bool) { ASSERT_FALSE(true); };
  auto lossEvent = detectLossPackets(
      *conn,
      secondPacketNum,
      lossVisitor,
      Clock::now(),
      PacketNumberSpace::AppData);
  // We should not set loss timer for un-acked d6d probes
  ASSERT_FALSE(earliestLossTimer(*conn).first.has_value());
  ASSERT_FALSE(lossEvent);
}

TEST_F(QuicLossFunctionsTest, NonExclusiveD6DProbeLossIncludedInLossEvent) {
  auto conn = createConn();
  // 0 rtt means all packets are automatically lost upon sending
  conn->lossState.srtt = 0s;
  conn->lossState.lrtt = 0s;
  conn->d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  auto currentTime = Clock::now();
  auto firstPacketNum =
      sendPacket(*conn, currentTime, folly::none, PacketType::OneRtt, true);
  auto secondPacketNum =
      sendPacket(*conn, currentTime, folly::none, PacketType::OneRtt, false);
  ASSERT_GT(secondPacketNum, firstPacketNum);
  ASSERT_EQ(2, conn->outstandings.packets.size());
  auto lossVisitor = [&](auto&, auto& packet, bool) {
    EXPECT_EQ(packet.header.getPacketSequenceNum(), secondPacketNum);
  };
  auto lossEvent = detectLossPackets(
      *conn,
      secondPacketNum + 1,
      lossVisitor,
      Clock::now(),
      PacketNumberSpace::AppData);
  // We should not set loss timer for un-acked d6d probes
  ASSERT_TRUE(lossEvent.hasValue());
  ASSERT_FALSE(earliestLossTimer(*conn).first.has_value());
  ASSERT_EQ(lossEvent->lostPackets, 1);
}

struct PMTUBlackholeDetectionTestFixture {
  uint32_t beginPMTU;
  uint32_t endPMTU;
  size_t threshold;
  bool hasLossEvent;
  uint64_t lostBytes;
  uint32_t lostPackets;
  std::chrono::seconds window;
  PacketNum largestAckedPacketNum;
  std::chrono::microseconds detectLossTimeDelta;
  std::chrono::microseconds largestLostTimeDelta;
  std::chrono::microseconds smallestLostTimeDelta;
  D6DMachineState beginState;
  D6DMachineState endState;

  struct PacketSpec {
    std::chrono::microseconds timeDelta;
    bool isD6DProbe;
    uint32_t encodedSize;
  };
  std::vector<PacketSpec> packetSpecs;
};

void QuicLossFunctionsTest::runDetectPMTUBlackholeTest(
    QuicConnectionStateBase* conn,
    PMTUBlackholeDetectionTestFixture fixture) {
  // 0 rtt means all packets are automatically lost upon sending
  conn->lossState.srtt = 0s;
  conn->lossState.lrtt = 0s;
  conn->d6d.state = D6DMachineState::BASE;
  conn->d6d.currentProbeSize = fixture.beginPMTU;
  conn->udpSendPacketLen = fixture.beginPMTU;
  conn->d6d.thresholdCounter =
      std::make_unique<WindowedCounter<uint64_t, uint64_t>>(
          std::chrono::microseconds(fixture.window).count(), fixture.threshold);
  conn->d6d.raiser = std::make_unique<MockProbeSizeRaiser>();
  conn->d6d.state = fixture.beginState;
  auto currentTime = Clock::now();
  for (auto& spec : fixture.packetSpecs) {
    sendPacket(
        *conn,
        currentTime + spec.timeDelta,
        folly::none,
        PacketType::OneRtt,
        spec.isD6DProbe,
        spec.encodedSize);
  }
  auto lossVisitor = [](auto&, auto&, bool) {};
  ASSERT_EQ(conn->outstandings.packets.size(), fixture.packetSpecs.size());
  auto lossEvent = detectLossPackets(
      *conn,
      fixture.largestAckedPacketNum,
      lossVisitor,
      currentTime + fixture.detectLossTimeDelta,
      PacketNumberSpace::AppData);
  EXPECT_EQ(lossEvent.has_value(), fixture.hasLossEvent);
  if (fixture.hasLossEvent) {
    EXPECT_EQ(lossEvent->lostPackets, fixture.lostPackets);
    EXPECT_EQ(lossEvent->lostBytes, fixture.lostBytes);
    EXPECT_EQ(
        lossEvent->largestLostSentTime.value(),
        currentTime + fixture.largestLostTimeDelta);
    EXPECT_EQ(
        lossEvent->smallestLostSentTime.value(),
        currentTime + fixture.smallestLostTimeDelta);
    EXPECT_EQ(conn->d6d.state, fixture.endState);
    EXPECT_EQ(conn->d6d.currentProbeSize, fixture.endPMTU);
    EXPECT_EQ(conn->udpSendPacketLen, fixture.endPMTU);
  }
}

TEST_F(QuicLossFunctionsTest, DetectPMTUBlackholeAllNonProbes) {
  // clang-format off
  PMTUBlackholeDetectionTestFixture fixture {
    1400,                             // beginPMTU
    kDefaultUDPSendPacketLen,         // endPMTU
    3,                                // threshold
    true,                             // hasLossEvent
    1400 * 3,                         // lostBytes
    3,                                // lostPackets
    10s,                              // window
    3 + kReorderingThreshold,         // largestAckedPacketNum
    11s,                              // detectLossTimeDelta
    10s,                              // largestLostTimeDelta
    0s,                               // smallestLostTimeDelta
    D6DMachineState::SEARCH_COMPLETE, // beginState
    D6DMachineState::BASE,            // beginState
    {                                 // packetSpecs
      {0s, false, 1400},
      {1s, false, 1400},
      {10s, false, 1400},
    }
  };
  // clang-format on
  auto conn = createConn();
  runDetectPMTUBlackholeTest(conn.get(), fixture);
}

TEST_F(QuicLossFunctionsTest, DetectPMTUBlackholeAllProbes) {
  // clang-format off
  PMTUBlackholeDetectionTestFixture fixture {
    1400,                             // beginPMTU
    1400,                             // endPMTU
    3,                                // threshold
    false,                            // hasLossEvent
    0,                                // lostBytes
    0,                                // lostPackets
    10s,                              // window
    3 + kReorderingThreshold,         // largestAckedPacketNum
    11s,                              // detectLossTimeDelta
    10s,                              // largestLostTimeDelta
    0s,                               // smallestLostTimeDelta
    D6DMachineState::SEARCH_COMPLETE, // beginState
    D6DMachineState::SEARCH_COMPLETE, // beginState
    {                                 // packetSpecs
      {0s, true, 1400},
      {1s, true, 1400},
      {10s, true, 1400},
    }
  };
  // clang-format on
  auto conn = createConn();
  runDetectPMTUBlackholeTest(conn.get(), fixture);
}

TEST_F(QuicLossFunctionsTest, DetectPMTUBlackholeSparseProbes) {
  // clang-format off
  PMTUBlackholeDetectionTestFixture fixture {
    1400,                             // beginPMTU
    1400,                             // endPMTU
    3,                                // threshold
    true,                             // hasLossEvent
    1400 * 5 + 200,                   // lostBytes
    6,                                // lostPackets
    10s,                              // window
    6 + kReorderingThreshold,         // largestAckedPacketNum
    23s,                              // detectLossTimeDelta
    22s,                              // largestLostTimeDelta
    0s,                               // smallestLostTimeDelta
    D6DMachineState::SEARCH_COMPLETE, // beginState
    D6DMachineState::SEARCH_COMPLETE, // beginState
    {                                 // packetSpecs
      {0s, false, 1400},
      {1s, false, 1400},
      {11s, false, 1400},
      {10s, false, 200},
      {12s, false, 1400},
      {22s, false, 1400}
    }
  };
  // clang-format on
  auto conn = createConn();
  runDetectPMTUBlackholeTest(conn.get(), fixture);
}

TEST_F(QuicLossFunctionsTest, DetectPMTUBlackholeRandomData) {
  // clang-format off
  PMTUBlackholeDetectionTestFixture fixture {
    1400,                                 // beginPMTU
    1400,                                 // endPMTU
    3,                                    // threshold
    true,                                 // hasLossEvent
    876 + 249 + 1291 + 1400 * 4 + 1109,   // lostBytes
    8,                                    // lostPackets
    10s,                                  // window
    9 + kReorderingThreshold,             // largestAckedPacketNum
    90s,                                  // detectLossTimeDelta
    83s,                                  // largestLostTimeDelta
    5s,                                   // smallestLostTimeDelta
    D6DMachineState::SEARCHING,           // beginState
    D6DMachineState::SEARCHING,           // beginState
    {                                     // packetSpecs
      { 5s, false, 876 },
      { 15s, false, 249 },
      { 19s, false, 1291 },
      { 31s, false, 1400 },
      { 40s, true, 1400 },
      { 51s, false, 1400 },
      { 61s, false, 1400 },
      { 73s, false, 1400 },
      { 83s, false, 1109 },
      { 85s, true, 1400 }
    }
  };
  // clang-format on
  auto conn = createConn();
  runDetectPMTUBlackholeTest(conn.get(), fixture);
}

TEST_F(QuicLossFunctionsTest, ClearEarlyRetranTimer) {
  auto conn = createConn();
  // make delayUntilLoss relatively large
  conn->lossState.srtt = 1s;
  conn->lossState.lrtt = 1s;
  auto currentTime = Clock::now();
  auto firstPacketNum =
      sendPacket(*conn, currentTime, folly::none, PacketType::Initial);
  auto secondPacketNum =
      sendPacket(*conn, currentTime, folly::none, PacketType::Initial);
  ASSERT_GT(secondPacketNum, firstPacketNum);
  ASSERT_EQ(2, conn->outstandings.packets.size());
  // detectLossPackets will set lossTime on Initial space.
  auto lossVisitor = [](auto&, auto&, bool) { ASSERT_FALSE(true); };
  detectLossPackets(
      *conn,
      secondPacketNum,
      lossVisitor,
      Clock::now(),
      PacketNumberSpace::Initial);
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
  processAckFrame(
      *conn,
      PacketNumberSpace::Initial,
      ackFrame,
      [&](auto&, auto&, auto&) {},
      lossVisitor,
      Clock::now());

  // Send out a AppData packet that isn't retransmittable
  sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
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

  sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
  MockClock::mockNow = []() { return TimePoint(123ms); };
  std::vector<PacketNum> lostPacket;
  MockClock::mockNow = []() { return TimePoint(23ms); };
  EXPECT_CALL(*quicStats_, onPTO());
  setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
  EXPECT_EQ(LossState::AlarmMethod::PTO, conn->lossState.currentAlarmMethod);
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPacket)), MockClock>(
      *conn, testingLossMarkFunc(lostPacket));
  EXPECT_EQ(conn->lossState.ptoCount, 1);
  EXPECT_TRUE(conn->pendingEvents.setLossDetectionAlarm);
  // PTO shouldn't mark loss
  EXPECT_TRUE(lostPacket.empty());

  MockClock::mockNow = []() { return TimePoint(3ms); };
  EXPECT_CALL(*quicStats_, onPTO());
  sendPacket(*conn, TimePoint(), folly::none, PacketType::OneRtt);
  setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _)).Times(0);
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPacket)), MockClock>(
      *conn, testingLossMarkFunc(lostPacket));
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
  // By adding an associatedEvent that doesn't exist in the
  // outstandings.packetEvents, they are all processed and will skip lossVisitor
  for (auto i = 0; i < 10; i++) {
    PacketEvent packetEvent(PacketNumberSpace::AppData, i);
    sendPacket(*conn, TimePoint(), packetEvent, PacketType::OneRtt);
  }
  EXPECT_EQ(10, conn->outstandings.packets.size());
  std::vector<PacketNum> lostPackets;
  EXPECT_CALL(*rawCongestionController, onRemoveBytesFromInflight(_)).Times(0);
  EXPECT_CALL(*quicStats_, onPTO());
  onPTOAlarm(*conn);
  EXPECT_EQ(10, conn->outstandings.packets.size());
  EXPECT_TRUE(lostPackets.empty());
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLoss) {
  folly::EventBase evb;
  MockAsyncUDPSocket socket(&evb);
  auto conn = createConn();
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(2);
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream2Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);
  auto stream2 = conn->streamManager->findStream(stream2Id);
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

  EXPECT_EQ(1, conn->outstandings.packets.size());
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  markPacketLoss(*conn, packet, false);
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream2->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream1->lossBuffer.size(), 1);
  EXPECT_EQ(stream2->lossBuffer.size(), 1);

  auto& buffer = stream1->lossBuffer.front();
  EXPECT_EQ(buffer.offset, 0);
  IOBufEqualTo eq;
  EXPECT_TRUE(eq(buf, buffer.data.move()));
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossMerge) {
  folly::EventBase evb;
  MockAsyncUDPSocket socket(&evb);
  auto conn = createConn();
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);

  auto buf1 = buildRandomInputData(20);
  writeDataToQuicStream(*stream1, buf1->clone(), false);
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      *conn->version,
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, conn->outstandings.packets.size());

  auto buf2 = buildRandomInputData(20);
  writeDataToQuicStream(*stream1, buf2->clone(), false);
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      *conn->version,
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(2, conn->outstandings.packets.size());

  auto& packet1 =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  auto packetNum = packet1.header.getPacketSequenceNum();
  markPacketLoss(*conn, packet1, false);
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  EXPECT_EQ(stream1->lossBuffer.size(), 1);
  auto& packet2 =
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  packetNum = packet2.header.getPacketSequenceNum();
  markPacketLoss(*conn, packet2, false);
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 0);
  EXPECT_EQ(stream1->lossBuffer.size(), 1);

  auto combined = buf1->clone();
  combined->prependChain(buf2->clone());
  auto& buffer = stream1->lossBuffer.front();
  EXPECT_EQ(buffer.offset, 0);
  IOBufEqualTo eq;
  EXPECT_TRUE(eq(combined, buffer.data.move()));
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossNoMerge) {
  folly::EventBase evb;
  MockAsyncUDPSocket socket(&evb);
  auto conn = createConn();
  EXPECT_CALL(*quicStats_, onNewQuicStream()).Times(1);
  auto stream1Id =
      conn->streamManager->createNextBidirectionalStream().value()->id;
  auto stream1 = conn->streamManager->findStream(stream1Id);

  auto buf1 = buildRandomInputData(20);
  writeDataToQuicStream(*stream1, buf1->clone(), false);
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      *conn->version,
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, conn->outstandings.packets.size());

  auto buf2 = buildRandomInputData(20);
  writeDataToQuicStream(*stream1, buf2->clone(), false);
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      *conn->version,
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(2, conn->outstandings.packets.size());

  auto buf3 = buildRandomInputData(20);
  writeDataToQuicStream(*stream1, buf3->clone(), false);
  writeQuicDataToSocket(
      socket,
      *conn,
      *conn->clientConnectionId,
      *conn->serverConnectionId,
      *aead,
      *headerCipher,
      *conn->version,
      conn->transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(3, conn->outstandings.packets.size());

  auto& packet1 =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  auto packetNum = packet1.header.getPacketSequenceNum();
  markPacketLoss(*conn, packet1, false);
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 2);
  EXPECT_EQ(stream1->lossBuffer.size(), 1);
  auto& packet3 =
      getLastOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  packetNum = packet3.header.getPacketSequenceNum();
  markPacketLoss(*conn, packet3, false);
  EXPECT_EQ(stream1->retransmissionBuffer.size(), 1);
  EXPECT_EQ(stream1->lossBuffer.size(), 2);

  auto& buffer1 = stream1->lossBuffer[0];
  EXPECT_EQ(buffer1.offset, 0);
  IOBufEqualTo eq;
  EXPECT_TRUE(eq(buf1, buffer1.data.move()));

  auto& buffer3 = stream1->lossBuffer[1];
  EXPECT_EQ(buffer3.offset, 40);
  EXPECT_TRUE(eq(buf3, buffer3.data.move()));
}

TEST_F(QuicLossFunctionsTest, RetxBufferSortedAfterLoss) {
  folly::EventBase evb;
  MockAsyncUDPSocket socket(&evb);
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
  auto packet = conn->outstandings.packets[folly::Random::rand32() % 3];
  markPacketLoss(*conn, packet.packet, false);
  EXPECT_EQ(2, stream->retransmissionBuffer.size());
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
  sendRstSMHandler(*stream1, GenericApplicationErrorCode::UNKNOWN);

  markPacketLoss(*conn, packet, false);

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

  auto testingLossMarkFunc = [&lostPacket](auto& /*conn*/, auto& packet, bool) {
    auto packetNum = packet.header.getPacketSequenceNum();
    lostPacket.push_back(packetNum);
  };
  for (int i = 0; i < 6; ++i) {
    sendPacket(*conn, Clock::now(), folly::none, PacketType::Handshake);
  }
  EXPECT_EQ(6, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  // Assume some packets are already acked
  for (auto iter =
           getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake) + 2;
       iter <
       getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake) + 5;
       iter++) {
    if (iter->metadata.isHandshake) {
      conn->outstandings.packetCount[PacketNumberSpace::Handshake]--;
    }
  }
  auto firstHandshakeOpIter =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::Handshake);
  conn->outstandings.packets.erase(
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
      conn->ackStates.handshakeAckState.nextPacketNum++,
      conn->version.value());
  RegularQuicWritePacket outstandingRegularPacket(std::move(longHeader));
  auto now = Clock::now();
  conn->outstandings.packets.emplace_back(
      outstandingRegularPacket,
      now,
      0,
      0,
      false,
      0,
      0,
      0,
      0,
      LossState(),
      0,
      OutstandingPacketMetadata::DetailsPerStream());
  conn->outstandings.packetCount[PacketNumberSpace::Handshake]++;

  bool testLossMarkFuncCalled = false;
  auto testLossMarkFunc = [&](auto& /* conn */, auto&, bool) {
    testLossMarkFuncCalled = true;
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
  handleAckForLoss(
      *conn, testLossMarkFunc, ackEvent, PacketNumberSpace::Handshake);

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

  sendPacket(*conn, TimePoint(), folly::none, PacketType::OneRtt);

  ReadAckFrame ackFrame;
  ackFrame.largestAcked = conn->lossState.largestSent.value_or(0);
  ackFrame.ackBlocks.emplace_back(
      conn->lossState.largestSent.value_or(0),
      conn->lossState.largestSent.value_or(0));

  bool testLossMarkFuncCalled = false;
  auto testLossMarkFunc = [&](auto& /* conn */, auto&, bool) {
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

  EXPECT_EQ(conn->outstandings.packets.size(), 1);
  EXPECT_TRUE(conn->pendingEvents.resets.empty());
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;
  markPacketLoss(*conn, packet, false);

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
  for (auto& frame : packet2.frames) {
    auto resetFrame = frame.asRstStreamFrame();
    if (!resetFrame) {
      continue;
    }
    EXPECT_EQ(stream->id, resetFrame->streamId);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, resetFrame->errorCode);
    EXPECT_EQ(currentOffset, resetFrame->offset);
    rstFound = true;
  }
  EXPECT_TRUE(rstFound);
}

TEST_F(QuicLossFunctionsTest, ReorderingThresholdChecksSamePacketNumberSpace) {
  auto conn = createConn();
  uint16_t lossVisitorCount = 0;
  auto countingLossVisitor =
      [&](auto& /* conn */, auto& /* packet */, bool processed) {
        if (!processed) {
          lossVisitorCount++;
        }
      };
  PacketNum latestSent = 0;
  for (size_t i = 0; i < conn->lossState.reorderingThreshold + 1; i++) {
    latestSent =
        sendPacket(*conn, Clock::now(), folly::none, PacketType::Handshake);
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

  EXPECT_EQ(1, conn->outstandings.packets.size());
  auto& packet =
      getFirstOutstandingPacket(*conn, PacketNumberSpace::AppData)->packet;

  markPacketLoss(*conn, packet, false);
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
        *conn, TimePoint(i * 100ms), folly::none, PacketType::OneRtt);
  }
  // Some packets are already acked
  conn->lossState.srtt = 400ms;
  conn->lossState.lrtt = 350ms;
  conn->outstandings.packets.erase(
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
  sendPacket(*conn, sendTime, folly::none, PacketType::Handshake);
  PacketNum second =
      sendPacket(*conn, sendTime + 1ms, folly::none, PacketType::Handshake);
  auto lossTime = sendTime + 50ms;
  detectLossPackets<decltype(testingLossMarkFunc(lostPackets))>(
      *conn,
      second,
      testingLossMarkFunc(lostPackets),
      lossTime,
      PacketNumberSpace::Handshake);
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
  // Manual set lossState. Calling setLossDetectionAlarm requries a Timeout
  conn->lossState.currentAlarmMethod = alarm.second;

  // Second packet gets acked:
  getAckState(*conn, PacketNumberSpace::Handshake).largestAckedByPeer = second;
  conn->outstandings.packets.pop_back();
  MockClock::mockNow = [=]() { return sendTime + expectedDelayUntilLost + 5s; };
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPackets)), MockClock>(
      *conn, testingLossMarkFunc(lostPackets));
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
    sendPacket(*conn, startTime, folly::none, PacketType::OneRtt);
    setLossDetectionAlarm<decltype(timeout), MockClock>(*conn, timeout);
    startTime += 1ms;
  }
  EXPECT_CALL(*rawCongestionController, onPacketAckOrLoss(_, _)).Times(0);
  EXPECT_CALL(*quicStats_, onPTO());
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPackets)), MockClock>(
      *conn, testingLossMarkFunc(lostPackets));
  EXPECT_EQ(1, conn->lossState.ptoCount);
  // Hey PTOs are not losses either from now on
  EXPECT_TRUE(lostPackets.empty());
}

TEST_F(QuicLossFunctionsTest, PTOWithHandshakePackets) {
  auto conn = createConn();
  conn->handshakeWriteCipher = createNoOpAead();
  conn->handshakeWriteHeaderCipher = createNoOpHeaderCipher();
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
        folly::none,
        (i % 2 ? PacketType::OneRtt : PacketType::Handshake));
    expectedLargestLostNum = std::max(
        expectedLargestLostNum, i % 2 ? sentPacketNum : expectedLargestLostNum);
  }
  EXPECT_CALL(*quicStats_, onPTO());
  // Verify packet count doesn't change across PTO.
  auto originalPacketCount = conn->outstandings.packetCount;
  onLossDetectionAlarm<decltype(testingLossMarkFunc(lostPackets)), Clock>(
      *conn, testingLossMarkFunc(lostPackets));
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

  sendPacket(*conn, lastPacketSentTime, folly::none, PacketType::OneRtt);
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

  sendPacket(*conn, lastPacketSentTime, folly::none, PacketType::OneRtt);
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
  sendPacket(*conn, lastPacketSentTime, folly::none, PacketType::OneRtt);
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
      [&](auto& /* conn */, auto& /* packet */, bool processed) {
        if (!processed) {
          lossVisitorCount++;
        }
      };
  // Send 5 packets, so when we ack the last one, we mark the first one loss
  PacketNum lastSent;
  for (size_t i = 0; i < 5; i++) {
    lastSent = sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
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
  auto countingLossVisitor =
      [&](auto& /* conn */, auto& /* packet */, bool processed) {
        if (!processed) {
          lossVisitorCount++;
        }
      };
  // Send 5 packets, so when we ack the last one, we mark the first one loss
  PacketNum lastSent;
  for (size_t i = 0; i < 5; i++) {
    lastSent = conn->ackStates.appDataAckState.nextPacketNum;
    PacketEvent packetEvent(PacketNumberSpace::AppData, lastSent);
    sendPacket(*conn, Clock::now(), packetEvent, PacketType::OneRtt);
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
  auto countingLossVisitor =
      [&](auto& /* conn */, auto& /* packet */, bool processed) {
        if (!processed) {
          lossVisitorCount++;
        }
      };
  // Send 6 packets, so when we ack the last one, we mark the first two loss
  EXPECT_EQ(1, conn->ackStates.appDataAckState.nextPacketNum);
  PacketNum lastSent;
  lastSent = sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  PacketEvent event(PacketNumberSpace::AppData, lastSent);
  for (size_t i = 0; i < 6; i++) {
    lastSent = sendPacket(*conn, Clock::now(), event, PacketType::OneRtt);
  }
  EXPECT_EQ(7, conn->outstandings.packets.size());
  EXPECT_EQ(1, conn->outstandings.packetCount[PacketNumberSpace::AppData]);
  // Add the PacketEvent to the outstandings.packetEvents set
  conn->outstandings.packetEvents.insert(event);

  // Ack the last sent packet. Despite three losses, lossVisitor only visit one
  // packet
  detectLossPackets(
      *conn,
      lastSent,
      countingLossVisitor,
      TimePoint(100ms),
      PacketNumberSpace::AppData);
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
  PacketEvent packetEvent1(
      PacketNumberSpace::AppData,
      conn->ackStates.appDataAckState.nextPacketNum);
  sendPacket(*conn, Clock::now(), packetEvent1, PacketType::OneRtt);
  sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
  sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
  sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
  auto ackedPacket =
      sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
  auto noopLossMarker = [](auto&, auto&, bool) {};
  detectLossPackets<decltype(noopLossMarker)>(
      *conn,
      ackedPacket,
      noopLossMarker,
      Clock::now(),
      PacketNumberSpace::AppData);
  EXPECT_EQ(0, conn->outstandings.numClonedPackets());
}

TEST_F(QuicLossFunctionsTest, TestMarkPacketLossProcessedPacket) {
  MockAsyncUDPSocket socket(&evb);
  auto conn = createConn();
  ASSERT_TRUE(conn->outstandings.packets.empty());
  ASSERT_TRUE(conn->outstandings.packetEvents.empty());
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
  ASSERT_TRUE(conn->outstandings.packetEvents.empty());
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
  markPacketLoss(*conn, packet, true);
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
  onPTOAlarm(*conn);
  EXPECT_EQ(101, conn->lossState.totalPTOCount);
}

TEST_F(QuicLossFunctionsTest, TestExceedsMaxPTOThrows) {
  auto conn = createConn();
  auto mockQLogger = std::make_shared<MockQLogger>(VantagePoint::Server);
  conn->qLogger = mockQLogger;
  conn->transportSettings.maxNumPTOs = 3;
  for (int i = 1; i <= 3; i++) {
    EXPECT_CALL(*mockQLogger, addLossAlarm(0, i, 0, kPtoAlarm));
  }
  EXPECT_CALL(*quicStats_, onPTO()).Times(3);
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
        sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
  }
  EXPECT_EQ(10, conn->outstandings.packets.size());
  uint32_t lostPackets = 0;
  auto countingLossVisitor =
      [&](auto& /* conn */, auto& /* packet */, bool processed) {
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
  // outstandings.packetEvents, they are all processed and will skip lossVisitor
  for (auto i = 0; i < 2; i++) {
    sendPacket(*conn, TimePoint(), folly::none, PacketType::OneRtt);
    sendPacket(*conn, TimePoint(), folly::none, PacketType::ZeroRtt);
  }
  EXPECT_FALSE(conn->outstandings.packets.empty());
  EXPECT_EQ(4, conn->outstandings.packets.size());
  std::vector<bool> lostPackets;
  // onRemoveBytesFromInflight should still happen
  EXPECT_CALL(*rawCongestionController, onRemoveBytesFromInflight(_)).Times(1);
  markZeroRttPacketsLost(*conn, [&lostPackets](auto&, auto&, bool processed) {
    lostPackets.emplace_back(processed);
  });
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
  // By adding an associatedEvent that doesn't exist in the
  // outstandings.packetEvents, they are all processed and will skip lossVisitor
  std::set<PacketNum> zeroRttPackets;
  folly::Optional<PacketEvent> lastPacketEvent;
  for (auto i = 0; i < 2; i++) {
    auto packetNum =
        sendPacket(*conn, TimePoint(), lastPacketEvent, PacketType::ZeroRtt);
    lastPacketEvent = PacketEvent(PacketNumberSpace::AppData, packetNum);
    zeroRttPackets.emplace(packetNum);
  }
  zeroRttPackets.emplace(
      sendPacket(*conn, TimePoint(), folly::none, PacketType::ZeroRtt));
  for (auto zeroRttPacketNum : zeroRttPackets) {
    PacketEvent zeroRttPacketEvent(
        PacketNumberSpace::AppData, zeroRttPacketNum);
    sendPacket(*conn, TimePoint(), zeroRttPacketEvent, PacketType::OneRtt);
  }

  EXPECT_EQ(6, conn->outstandings.packets.size());
  ASSERT_EQ(conn->outstandings.numClonedPackets(), 6);
  ASSERT_EQ(conn->outstandings.packetEvents.size(), 2);
  ASSERT_EQ(2, conn->outstandings.packetCount[PacketNumberSpace::AppData]);

  std::vector<bool> lostPackets;
  // onRemoveBytesFromInflight should still happen
  EXPECT_CALL(*rawCongestionController, onRemoveBytesFromInflight(_)).Times(1);
  markZeroRttPacketsLost(*conn, [&lostPackets](auto&, auto&, bool processed) {
    lostPackets.emplace_back(processed);
  });
  ASSERT_EQ(conn->outstandings.packetEvents.size(), 0);
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
      sendPacket(*conn, referenceTime - 10ms, folly::none, PacketType::OneRtt);
  auto packet2 = sendPacket(
      *conn,
      referenceTime + conn->lossState.srtt / 2,
      folly::none,
      PacketType::OneRtt);
  auto lossVisitor = [&](const auto& /*conn*/, const auto& packet, bool) {
    EXPECT_EQ(packet1, packet.header.getPacketSequenceNum());
  };
  detectLossPackets<decltype(lossVisitor)>(
      *conn,
      packet2,
      lossVisitor,
      referenceTime + conn->lossState.srtt * 9 / 8 + 5ms,
      PacketNumberSpace::AppData);
}

TEST_F(QuicLossFunctionsTest, OutstandingInitialCounting) {
  auto conn = createConn();
  // Simplify the test by never triggering timer threshold
  conn->lossState.srtt = 100s;
  PacketNum largestSent = 0;
  while (largestSent < 10) {
    largestSent =
        sendPacket(*conn, Clock::now(), folly::none, PacketType::Initial);
  }
  EXPECT_EQ(10, conn->outstandings.packetCount[PacketNumberSpace::Initial]);
  auto noopLossVisitor =
      [&](auto& /* conn */, auto& /* packet */, bool /* processed */
      ) {};
  detectLossPackets(
      *conn,
      largestSent,
      noopLossVisitor,
      TimePoint(100ms),
      PacketNumberSpace::Initial);
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
        sendPacket(*conn, Clock::now(), folly::none, PacketType::Handshake);
  }
  EXPECT_EQ(10, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
  auto noopLossVisitor =
      [&](auto& /* conn */, auto& /* packet */, bool /* processed */
      ) {};
  detectLossPackets(
      *conn,
      largestSent,
      noopLossVisitor,
      TimePoint(100ms),
      PacketNumberSpace::Handshake);
  // [1, 6] are removed, [7, 10] are still in OP list
  EXPECT_EQ(4, conn->outstandings.packetCount[PacketNumberSpace::Handshake]);
}

TEST_P(QuicLossFunctionsTest, CappedShiftNoCrash) {
  auto conn = createConn();
  conn->outstandings.reset();
  conn->lossState.ptoCount =
      std::numeric_limits<decltype(conn->lossState.ptoCount)>::max();
  sendPacket(*conn, Clock::now(), folly::none, PacketType::OneRtt);
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
  ack.ackedPackets.push_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(1)
          .setOutstandingPacketMetadata(OutstandingPacketMetadata(
              currentTime + 12s /* sentTime */,
              0 /* encodedSize */,
              0 /* encodedBodySize */,
              false /* isHandshake */,
              false /* isD6DProbe */,
              0 /* totalBytesSent */,
              0 /* totalBodyBytesSent */,
              0 /* inflightBytes */,
              0 /* numOutstanding */,
              LossState() /* lossState */,
              0 /* writeCount */,
              OutstandingPacketMetadata::DetailsPerStream()))
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
  ack.ackedPackets.push_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(1)
          .setOutstandingPacketMetadata(OutstandingPacketMetadata(
              currentTime + 4s /* sentTime */,
              0 /* encodedSize */,
              0 /* encodedBodySize */,
              false /* isHandshake */,
              false /* isD6DProbe */,
              0 /* totalBytesSent */,
              0 /* totalBodyBytesSent */,
              0 /* inflightBytes */,
              0 /* numOutstanding */,
              LossState() /* lossState */,
              0 /* writeCount */,
              OutstandingPacketMetadata::DetailsPerStream()))
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
  ack.ackedPackets.push_back(
      CongestionController::AckEvent::AckPacket::Builder()
          .setPacketNum(1)
          .setOutstandingPacketMetadata(OutstandingPacketMetadata(
              currentTime + 12s /* sentTime */,
              0 /* encodedSize */,
              0 /* encodedBodySize */,
              false /* isHandshake */,
              false /* isD6DProbe */,
              0 /* totalBytesSent */,
              0 /* totalBodyBytesSent */,
              0 /* inflightBytes */,
              0 /* numOutstanding */,
              LossState() /* lossState */,
              0 /* writeCount */,
              OutstandingPacketMetadata::DetailsPerStream()))
          .setDetailsPerStream(AckEvent::AckPacket::DetailsPerStream())
          .build());

  EXPECT_FALSE(isPersistentCongestion(
      folly::none, currentTime + 1s, currentTime + 8s, ack));
}

TEST_F(QuicLossFunctionsTest, ObserverLossEventReorder) {
  auto conn = createConn();

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::lossEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  conn->observerContainer->addObserver(obs1.get());

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent =
        sendPacket(*conn, TimePoint(i * 10ms), folly::none, PacketType::OneRtt);
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
  detectLossPackets(
      *conn,
      largestSent + 1,
      [](auto&, auto&, bool) {},
      checkTime,
      PacketNumberSpace::AppData);
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

  conn->observerContainer->removeObserver(obs1.get());
}

TEST_F(QuicLossFunctionsTest, ObserverLossEventTimeout) {
  auto conn = createConn();

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::lossEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  conn->observerContainer->addObserver(obs1.get());

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent =
        sendPacket(*conn, TimePoint(i * 10ms), folly::none, PacketType::OneRtt);
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
  detectLossPackets(
      *conn,
      largestSent + 1,
      [](auto&, auto&, bool) {},
      checkTime,
      PacketNumberSpace::AppData);
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

  conn->observerContainer->removeObserver(obs1.get());
}

TEST_F(QuicLossFunctionsTest, ObserverLossEventTimeoutAndReorder) {
  auto conn = createConn();

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::lossEvents);
  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  conn->observerContainer->addObserver(obs1.get());

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent =
        sendPacket(*conn, TimePoint(i * 10ms), folly::none, PacketType::OneRtt);
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
  detectLossPackets(
      *conn,
      largestSent + 1,
      [](auto&, auto&, bool) {},
      checkTime,
      PacketNumberSpace::AppData);
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

  conn->observerContainer->removeObserver(obs1.get());
}

TEST_F(QuicLossFunctionsTest, TotalPacketsMarkedLostByReordering) {
  auto conn = createConn();
  auto noopLossVisitor = [](auto&, auto&, bool) {};

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent =
        sendPacket(*conn, TimePoint(i * 10ms), folly::none, PacketType::OneRtt);
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

  detectLossPackets(
      *conn,
      largestSent + 1,
      noopLossVisitor,
      checkTime,
      PacketNumberSpace::AppData);

  // Sent 7 packets, out of 0, 1, 2, 3, 4, 5, 6 -- we deleted (acked) 2,3,4
  // 0, 1, and 5 should be marked lost due to reordering, none due to timeout
  // 6 is outstanding / on the wire still (no determination made)
  EXPECT_EQ(3, conn->lossState.totalPacketsMarkedLost);
  EXPECT_EQ(0, conn->lossState.totalPacketsMarkedLostByPto);
  EXPECT_EQ(3, conn->lossState.totalPacketsMarkedLostByReorderingThreshold);
}

TEST_F(QuicLossFunctionsTest, TotalPacketsMarkedLostByPto) {
  auto conn = createConn();
  auto noopLossVisitor = [](auto&, auto&, bool) {};

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent =
        sendPacket(*conn, TimePoint(i * 10ms), folly::none, PacketType::OneRtt);
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

  detectLossPackets(
      *conn,
      largestSent + 1,
      noopLossVisitor,
      checkTime,
      PacketNumberSpace::AppData);

  // All 7 packets should be marked as lost by PTO
  EXPECT_EQ(7, conn->lossState.totalPacketsMarkedLost);
  EXPECT_EQ(7, conn->lossState.totalPacketsMarkedLostByPto);
  EXPECT_EQ(0, conn->lossState.totalPacketsMarkedLostByReorderingThreshold);
}

TEST_F(QuicLossFunctionsTest, TotalPacketsMarkedLostByPtoPartial) {
  auto conn = createConn();
  auto noopLossVisitor = [](auto&, auto&, bool) {};

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent =
        sendPacket(*conn, TimePoint(i * 10ms), folly::none, PacketType::OneRtt);
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

  detectLossPackets(
      *conn,
      largestSent + 1,
      noopLossVisitor,
      checkTime,
      PacketNumberSpace::AppData);

  // Sent 7 packets, out of 0, 1, 2, 3, 4, 5, 6 -- we deleted (acked) 2,3,4
  // 0, 1, 5, and 6 should be marked lost due to timeout, none due to reordering
  EXPECT_EQ(4, conn->lossState.totalPacketsMarkedLost);
  EXPECT_EQ(4, conn->lossState.totalPacketsMarkedLostByPto);
  EXPECT_EQ(0, conn->lossState.totalPacketsMarkedLostByReorderingThreshold);
}

TEST_F(QuicLossFunctionsTest, TotalPacketsMarkedLostByPtoAndReordering) {
  auto conn = createConn();
  auto noopLossVisitor = [](auto&, auto&, bool) {};

  // send 7 packets
  PacketNum largestSent = 0;
  for (int i = 0; i < 7; ++i) {
    largestSent =
        sendPacket(*conn, TimePoint(i * 10ms), folly::none, PacketType::OneRtt);
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

  detectLossPackets(
      *conn,
      largestSent + 1,
      noopLossVisitor,
      checkTime,
      PacketNumberSpace::AppData);

  // Sent 7 packets, out of 0, 1, 2, 3, 4, 5, 6 -- we deleted (acked) 2,3,4
  // 0, 1, and 5 should be marked lost due to reordering AND timeout
  // 6 should be marked as lost due to timeout only
  EXPECT_EQ(4, conn->lossState.totalPacketsMarkedLost);
  EXPECT_EQ(4, conn->lossState.totalPacketsMarkedLostByPto);
  EXPECT_EQ(3, conn->lossState.totalPacketsMarkedLostByReorderingThreshold);
}

TEST_F(QuicLossFunctionsTest, LossVisitorDSRTest) {
  auto conn = createConn();
  auto* stream = conn->streamManager->createNextBidirectionalStream().value();
  stream->dsrSender = std::make_unique<MockDSRPacketizationRequestSender>();
  writeDataToQuicStream(*stream, folly::IOBuf::copyBuffer("grape"), false);
  writeBufMetaToQuicStream(*stream, BufferMeta(1000), true);
  auto bufMetaStartingOffset = stream->writeBufMeta.offset;
  ASSERT_EQ(1000, stream->writeBufMeta.length);
  ASSERT_TRUE(stream->writeBufMeta.eof);
  ASSERT_EQ(bufMetaStartingOffset + 1000, *stream->finalWriteOffset);
  // Send real data
  handleStreamWritten(
      *conn,
      *stream,
      0,
      bufMetaStartingOffset,
      false,
      0 /* PacketNum */,
      PacketNumberSpace::AppData);
  ASSERT_EQ(0, stream->writeBuffer.chainLength());
  auto retxIter = stream->retransmissionBuffer.find(0);
  ASSERT_NE(stream->retransmissionBuffer.end(), retxIter);
  ASSERT_EQ(0, retxIter->second->offset);
  ASSERT_FALSE(retxIter->second->eof);
  ASSERT_TRUE(folly::IOBufEqualTo()(
      *folly::IOBuf::copyBuffer("grape"), *retxIter->second->data.front()));
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
  conn->streamManager->updateLossStreams(*stream);
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
  conn->streamManager->updateLossStreams(*stream);
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
  conn->streamManager->updateLossStreams(*stream);
  EXPECT_FALSE(conn->streamManager->hasLoss());
  EXPECT_TRUE(conn->streamManager->writableDSRStreams().empty());

  // Lose the 1st dsr packet:
  RegularQuicWritePacket packet1(PacketHeader(ShortHeader(
      ProtectionType::KeyPhaseZero, conn->serverConnectionId.value(), 1)));
  WriteStreamFrame frame1(stream->id, bufMetaStartingOffset, 200, false);
  frame1.fromBufMeta = true;
  packet1.frames.push_back(frame1);
  markPacketLoss(*conn, packet1, false /* processed */);
  EXPECT_EQ(1, stream->lossBufMetas.size());
  const auto& lostBufMeta1 = stream->lossBufMetas.front();
  EXPECT_EQ(bufMetaStartingOffset, lostBufMeta1.offset);
  EXPECT_EQ(200, lostBufMeta1.length);
  EXPECT_FALSE(lostBufMeta1.eof);
  EXPECT_EQ(2, stream->retransmissionBufMetas.size());
  EXPECT_TRUE(conn->streamManager->hasLoss());
  EXPECT_FALSE(conn->streamManager->writableDSRStreams().empty());

  // Lose the 3rd dsr packet:
  RegularQuicWritePacket packet3(PacketHeader(ShortHeader(
      ProtectionType::KeyPhaseZero, conn->serverConnectionId.value(), 3)));
  WriteStreamFrame frame3(stream->id, bufMetaStartingOffset + 600, 400, true);
  frame3.fromBufMeta = true;
  packet3.frames.push_back(frame3);
  markPacketLoss(*conn, packet3, false /* processed */);
  EXPECT_EQ(2, stream->lossBufMetas.size());
  const auto& lostBufMeta2 = stream->lossBufMetas.back();
  EXPECT_EQ(bufMetaStartingOffset + 600, lostBufMeta2.offset);
  EXPECT_EQ(400, lostBufMeta2.length);
  EXPECT_TRUE(lostBufMeta2.eof);
  EXPECT_EQ(1, stream->retransmissionBufMetas.size());
  EXPECT_TRUE(conn->streamManager->hasLoss());
  EXPECT_FALSE(conn->streamManager->writableDSRStreams().empty());

  // Lose the 3nd dsr packet, it should be merged together with the first
  // element in the lossBufMetas:
  RegularQuicWritePacket packet2(PacketHeader(ShortHeader(
      ProtectionType::KeyPhaseZero, conn->serverConnectionId.value(), 2)));
  WriteStreamFrame frame2(stream->id, bufMetaStartingOffset + 200, 400, false);
  frame2.fromBufMeta = true;
  packet2.frames.push_back(frame2);
  markPacketLoss(*conn, packet2, false /* processed */);
  EXPECT_EQ(2, stream->lossBufMetas.size());
  const auto& lostBufMeta3 = stream->lossBufMetas.front();
  EXPECT_EQ(bufMetaStartingOffset, lostBufMeta3.offset);
  EXPECT_EQ(600, lostBufMeta3.length);
  EXPECT_FALSE(lostBufMeta3.eof);
  EXPECT_EQ(0, stream->retransmissionBufMetas.size());
  EXPECT_TRUE(conn->streamManager->hasLoss());
  EXPECT_FALSE(conn->streamManager->writableDSRStreams().empty());
}

INSTANTIATE_TEST_SUITE_P(
    QuicLossFunctionsTests,
    QuicLossFunctionsTest,
    Values(
        PacketNumberSpace::Initial,
        PacketNumberSpace::Handshake,
        PacketNumberSpace::AppData));

} // namespace test
} // namespace quic
