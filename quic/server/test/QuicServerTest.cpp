/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/QuicServer.h>
#include <folly/futures/Promise.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/api/test/MockQuicStats.h>
#include <quic/api/test/Mocks.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicHeaderCodec.h>
#include <quic/common/test/TestUtils.h>
#include <quic/server/handshake/StatelessResetGenerator.h>
#include <quic/server/test/Mocks.h>

using namespace testing;
using namespace folly;
using namespace folly::io;

const folly::SocketAddress kClientAddr("1.2.3.4", 1234);

namespace quic {
namespace {
using PacketDropReason = QuicTransportStatsCallback::PacketDropReason;
} // namespace
namespace test {

MATCHER_P(BufMatches, buf, "") {
  folly::IOBufEqualTo eq;
  return eq(*arg, buf);
}

class TestingEventBaseObserver : public folly::EventBaseObserver {
 public:
  uint32_t getSampleRate() const override {
    return 0; // Always sample
  }

  void loopSample(int64_t, int64_t) override {
    observerCalled_ = true;
  }

  bool observerCalled() const noexcept {
    return observerCalled_;
  }

 private:
  bool observerCalled_{false};
};

/**
 * QuicServerWorker test without a connection to drive any real behavior. Use
 * QuicServerWorkerTest for most cases.
 */
class SimpleQuicServerWorkerTest : public Test {
 protected:
  std::unique_ptr<QuicServerWorker> worker_;
  folly::EventBase eventbase_;
  std::shared_ptr<MockWorkerCallback> workerCb_;
  folly::test::MockAsyncUDPSocket* rawSocket_{nullptr};
};

TEST_F(SimpleQuicServerWorkerTest, DontFragment) {
  auto sock = std::make_unique<folly::test::MockAsyncUDPSocket>(&eventbase_);
  rawSocket_ = sock.get();
  DCHECK(sock->getEventBase());
  EXPECT_CALL(*sock, getNetworkSocket())
      .WillRepeatedly(Return(folly::NetworkSocket()));
  workerCb_ = std::make_shared<MockWorkerCallback>();
  worker_ = std::make_unique<QuicServerWorker>(workerCb_);
  worker_->setSocket(std::move(sock));
  folly::SocketAddress addr("::1", 0);
  // We check versions in bind()
  worker_->setSupportedVersions({QuicVersion::MVFST});
  EXPECT_CALL(*rawSocket_, dontFragment(true)).Times(1);
  worker_->bind(addr);
}

std::unique_ptr<folly::IOBuf> createData(size_t size) {
  std::string data;
  data.resize(size);
  return folly::IOBuf::copyBuffer(data);
}

class QuicServerWorkerTest : public Test {
 public:
  void SetUp() override {
    fakeAddress_ = folly::SocketAddress("111.111.111.111", 44444);
    auto sock = std::make_unique<folly::test::MockAsyncUDPSocket>(&eventbase_);
    DCHECK(sock->getEventBase());
    socketPtr_ = sock.get();
    workerCb_ = std::make_shared<MockWorkerCallback>();
    worker_ = std::make_unique<QuicServerWorker>(workerCb_);
    auto transportInfoCb = std::make_unique<MockQuicStats>();
    TransportSettings settings;
    settings.statelessResetTokenSecret = getRandSecret();
    worker_->setTransportSettings(settings);
    worker_->setSocket(std::move(sock));
    worker_->setWorkerId(42);
    worker_->setProcessId(ProcessId::ONE);
    worker_->setHostId(hostId_);
    worker_->setTransportInfoCallback(std::move(transportInfoCb));
    worker_->setConnectionIdAlgo(std::make_unique<DefaultConnectionIdAlgo>());
    worker_->setCongestionControllerFactory(
        std::make_shared<DefaultCongestionControllerFactory>());
    transportInfoCb_ = (MockQuicStats*)worker_->getTransportInfoCallback();

    auto cb = [&](const folly::SocketAddress& addr,
                  std::unique_ptr<RoutingData>& routingData,
                  std::unique_ptr<NetworkData>& networkData) {
      worker_->dispatchPacketData(
          addr, std::move(*routingData.get()), std::move(*networkData.get()));
    };

    EXPECT_CALL(*workerCb_, routeDataToWorkerLong(_, _, _))
        .WillRepeatedly(Invoke(cb));

    socketFactory_ = std::make_unique<MockQuicUDPSocketFactory>();
    EXPECT_CALL(*socketFactory_, _make(_, _)).WillRepeatedly(Return(nullptr));
    worker_->setNewConnectionSocketFactory(socketFactory_.get());
    MockConnectionCallback connCb;
    auto mockSock =
        std::make_unique<folly::test::MockAsyncUDPSocket>(&eventbase_);
    EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));
    transport_.reset(new MockQuicTransport(
        worker_->getEventBase(), std::move(mockSock), connCb, nullptr));
    factory_ = std::make_unique<MockQuicServerTransportFactory>();
    EXPECT_CALL(*transport_, getEventBase())
        .WillRepeatedly(Return(&eventbase_));
    EXPECT_CALL(*transport_, getOriginalPeerAddress())
        .WillRepeatedly(ReturnRef(kClientAddr));
    EXPECT_CALL(*transport_, hasShutdown())
        .WillRepeatedly(ReturnPointee(&hasShutdown_));
    worker_->setTransportFactory(factory_.get());
  }

  void createQuicConnection(
      const folly::SocketAddress& addr,
      ConnectionId connId,
      MockQuicTransport::Ptr transportOverride = nullptr);

  void expectConnectionCreation(
      const folly::SocketAddress& addr,
      ConnectionId connId,
      MockQuicTransport::Ptr transportOverride = nullptr);

  void testSendReset(
      Buf packet,
      ConnectionId connId,
      ShortHeader shortHeader,
      QuicTransportStatsCallback::PacketDropReason dropReason);

 protected:
  folly::SocketAddress fakeAddress_;
  std::unique_ptr<QuicServerWorker> worker_;
  folly::EventBase eventbase_;
  MockQuicTransport::Ptr transport_;
  std::shared_ptr<MockWorkerCallback> workerCb_;
  std::unique_ptr<MockQuicServerTransportFactory> factory_;
  std::unique_ptr<MockQuicUDPSocketFactory> listenerSocketFactory_;
  std::unique_ptr<MockQuicUDPSocketFactory> socketFactory_;
  MockQuicStats* transportInfoCb_{nullptr};
  folly::test::MockAsyncUDPSocket* socketPtr_{nullptr};
  uint16_t hostId_{49};
  bool hasShutdown_{false};
};

void QuicServerWorkerTest::expectConnectionCreation(
    const folly::SocketAddress& addr,
    ConnectionId connId,
    MockQuicTransport::Ptr transportOverride) {
  MockQuicTransport::Ptr transport = transport_;
  if (transportOverride) {
    transport = transportOverride;
  }
  EXPECT_CALL(*factory_, _make(_, _, _, _)).WillOnce(Return(transport));
  EXPECT_CALL(*transport, setSupportedVersions(_));
  EXPECT_CALL(*transport, setOriginalPeerAddress(addr));
  EXPECT_CALL(*transport, setRoutingCallback(worker_.get()));
  EXPECT_CALL(*transport, setConnectionIdAlgo(_));
  EXPECT_CALL(*transport, setServerConnectionIdParams(_))
      .WillOnce(Invoke([connId](ServerConnectionIdParams params) {
        EXPECT_EQ(*params.clientConnId, connId);
        EXPECT_EQ(params.processId, 1);
        EXPECT_EQ(params.workerId, 42);
      }));
  EXPECT_CALL(*transport, setTransportSettings(_));
  EXPECT_CALL(*transport, accept());
  EXPECT_CALL(*transport, setTransportInfoCallback(transportInfoCb_));
}

void QuicServerWorkerTest::createQuicConnection(
    const folly::SocketAddress& addr,
    ConnectionId connId,
    MockQuicTransport::Ptr transportOverride) {
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  RoutingData routingData(HeaderForm::Long, true, true, connId, connId);

  auto data = createData(kMinInitialPacketSize + 10);
  MockQuicTransport::Ptr transport = transport_;
  if (transportOverride) {
    transport = transportOverride;
  }
  expectConnectionCreation(addr, connId, transport);
  EXPECT_CALL(*transport, onNetworkData(addr, BufMatches(*data)));
  worker_->dispatchPacketData(
      addr, std::move(routingData), NetworkData(data->clone(), Clock::now()));

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_EQ(addrMap.count(std::make_pair(addr, connId)), 1);
  eventbase_.loop();
}

void QuicServerWorkerTest::testSendReset(
    Buf packet,
    ConnectionId,
    ShortHeader shortHeader,
    QuicTransportStatsCallback::PacketDropReason dropReason) {
  EXPECT_CALL(*transportInfoCb_, onPacketDropped(dropReason)).Times(1);
  // should write reset packet
  EXPECT_CALL(*transportInfoCb_, onWrite(_)).Times(1);
  EXPECT_CALL(*transportInfoCb_, onPacketSent()).Times(1);

  // verify that the packet that gets written is stateless reset packet
  EXPECT_CALL(*socketPtr_, write(_, _))
      .WillOnce(Invoke([&](const folly::SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& buf) {
        QuicReadCodec codec(QuicNodeType::Client);
        auto aead = createNoOpAead();
        // Make the decrypt fail
        EXPECT_CALL(*aead, _tryDecrypt(_, _, _))
            .WillRepeatedly(
                Invoke([&](auto&, auto, auto) { return folly::none; }));
        codec.setOneRttReadCipher(std::move(aead));
        codec.setOneRttHeaderCipher(test::createNoOpHeaderCipher());
        StatelessResetToken token = generateStatelessResetToken();
        codec.setStatelessResetToken(token);
        AckStates ackStates;
        auto packetQueue = bufToQueue(buf->clone());
        auto res = codec.parsePacket(packetQueue, ackStates);
        bool isReset = folly::variant_match(
            res,
            [](StatelessReset&) { return true; },
            [](auto&) { return false; });
        EXPECT_TRUE(isReset);
        return buf->computeChainDataLength();
      }));

  RoutingData routingData(
      HeaderForm::Short,
      false,
      false,
      shortHeader.getConnectionId(),
      folly::none);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(packet->clone(), Clock::now()));
  eventbase_.loop();
}

TEST_F(QuicServerWorkerTest, HostIdMismatchTestReset) {
  auto data = folly::IOBuf::copyBuffer("data");
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  PacketNum num = 2;
  // create packet with connId with different hostId encoded
  ShortHeader shortHeaderConnId(
      ProtectionType::KeyPhaseZero, getTestConnectionId(hostId_ + 1), num);
  testSendReset(
      std::move(data),
      getTestConnectionId(hostId_ + 1),
      std::move(shortHeaderConnId),
      QuicTransportStatsCallback::PacketDropReason::ROUTING_ERROR_WRONG_HOST);
}

TEST_F(QuicServerWorkerTest, NoConnFoundTestReset) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto data = folly::IOBuf::copyBuffer("data");
  PacketNum num = 2;
  // create packet with connId with different hostId encoded
  worker_->stopPacketForwarding();
  ShortHeader shortHeaderConnId(
      ProtectionType::KeyPhaseZero, getTestConnectionId(hostId_), num);
  testSendReset(
      std::move(data),
      getTestConnectionId(hostId_),
      std::move(shortHeaderConnId),
      QuicTransportStatsCallback::PacketDropReason::CONNECTION_NOT_FOUND);
}

TEST_F(QuicServerWorkerTest, QuicServerNewConnection) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  auto data = folly::IOBuf::copyBuffer("data");
  PacketNum num = 2;
  ShortHeader shortHeaderConnId(
      ProtectionType::KeyPhaseZero, getTestConnectionId(hostId_), num);

  // Routing by connid before conn id available on a short packet.
  EXPECT_CALL(*transportInfoCb_, onPacketDropped(_)).Times(1);

  RoutingData routingData(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId.getConnectionId(),
      folly::none);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now()));
  eventbase_.loop();

  EXPECT_CALL(*transportInfoCb_, onNewConnection());
  worker_->onConnectionIdAvailable(transport_, getTestConnectionId(hostId_));
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_EQ(connIdMap.count(getTestConnectionId(hostId_)), 1);

  EXPECT_CALL(*transport_, getClientConnectionId())
      .WillRepeatedly(Return(getTestConnectionId(hostId_)));
  worker_->onConnectionIdBound(transport_);

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_EQ(
      addrMap.count(std::make_pair(kClientAddr, getTestConnectionId(hostId_))),
      0);

  // routing by connid after connid available.
  EXPECT_CALL(*transport_, onNetworkData(kClientAddr, BufMatches(*data)));
  RoutingData routingData2(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId.getConnectionId(),
      folly::none);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData2),
      NetworkData(data->clone(), Clock::now()));
  eventbase_.loop();

  // routing by address after transport_'s connid available, but before
  // transport2's connid available.
  ConnectionId connId2({2, 4, 5, 6});
  folly::SocketAddress clientAddr2("2.3.4.5", 2345);
  MockConnectionCallback connCb;
  auto mockSock =
      std::make_unique<folly::test::MockAsyncUDPSocket>(&eventbase_);

  EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  MockQuicTransport::Ptr transport2 = std::make_shared<MockQuicTransport>(
      worker_->getEventBase(), std::move(mockSock), connCb, nullptr);
  EXPECT_CALL(*transport2, getEventBase()).WillRepeatedly(Return(&eventbase_));
  EXPECT_CALL(*transport2, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));
  createQuicConnection(clientAddr2, connId2, transport2);

  ShortHeader shortHeaderConnId2(ProtectionType::KeyPhaseZero, connId2, num);

  // Will be dropped
  EXPECT_CALL(*transportInfoCb_, onPacketDropped(_)).Times(1);
  RoutingData routingData3(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId2.getConnectionId(),
      folly::none);
  worker_->dispatchPacketData(
      clientAddr2,
      std::move(routingData3),
      NetworkData(data->clone(), Clock::now()));
  eventbase_.loop();

  EXPECT_CALL(*transportInfoCb_, onConnectionClose(_)).Times(2);
  worker_->onConnectionUnbound(
      std::make_pair(kClientAddr, getTestConnectionId(hostId_)),
      getTestConnectionId(hostId_));
  worker_->onConnectionUnbound(std::make_pair(clientAddr2, connId2), connId2);
  EXPECT_EQ(connIdMap.count(getTestConnectionId(hostId_)), 0);
  EXPECT_EQ(
      addrMap.count(std::make_pair(kClientAddr, getTestConnectionId(hostId_))),
      0);
}

TEST_F(QuicServerWorkerTest, InitialPacketTooSmall) {
  auto data = createData(kMinInitialPacketSize - 100);
  auto connId = getTestConnectionId(hostId_);
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial,
      getTestConnectionId(hostId_ + 1),
      connId,
      num,
      version);
  EXPECT_CALL(*factory_, _make(_, _, _, _)).Times(0);
  EXPECT_CALL(*transportInfoCb_, onPacketDropped(_));
  RoutingData routingData(
      HeaderForm::Long,
      true,
      true,
      header.getDestinationConnId(),
      header.getSourceConnId());
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now()));
  eventbase_.loop();
}

TEST_F(QuicServerWorkerTest, QuicShedTest) {
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  worker_->onConnectionIdAvailable(transport_, getTestConnectionId(hostId_));
  EXPECT_CALL(*transport_, getClientConnectionId())
      .WillRepeatedly(Return(getTestConnectionId(hostId_)));
  transport_->setShedConnection();
  EXPECT_CALL(
      *transport_,
      closeNow(Eq(std::make_pair(
          QuicErrorCode(TransportErrorCode::SERVER_BUSY),
          std::string("shedding under load")))));
  worker_->onConnectionIdBound(transport_);
  worker_->onConnectionUnbound(
      std::make_pair(kClientAddr, getTestConnectionId(hostId_)),
      getTestConnectionId(hostId_));
}

TEST_F(QuicServerWorkerTest, ZeroLengthConnectionId) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto connId = ConnectionId(std::vector<uint8_t>());
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  EXPECT_CALL(*transportInfoCb_, onPacketDropped(_)).Times(0);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, header, 0 /* largestAcked */);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  worker_->handleNetworkData(kClientAddr, std::move(packet), Clock::now());
  eventbase_.loop();
}

TEST_F(QuicServerWorkerTest, ConnectionIdTooShort) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto connId = ConnectionId::createWithoutChecks({1});
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  EXPECT_CALL(*transportInfoCb_, onPacketDropped(_));

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, header, 0 /* largestAcked */);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  worker_->handleNetworkData(kClientAddr, std::move(packet), Clock::now());
  eventbase_.loop();
}

TEST_F(QuicServerWorkerTest, ShutdownQuicServer) {
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  EXPECT_CALL(*transportInfoCb_, onNewConnection());
  worker_->onConnectionIdAvailable(transport_, getTestConnectionId(hostId_));
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_EQ(connIdMap.count(getTestConnectionId(hostId_)), 1);

  EXPECT_CALL(*transportInfoCb_, onConnectionClose(_));
  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(2);
  EXPECT_CALL(*transport_, setTransportInfoCallback(nullptr)).Times(2);
  EXPECT_CALL(*transport_, close(_)).WillRepeatedly(Invoke([this](auto) {
    hasShutdown_ = true;
  }));
  std::thread t([&] { eventbase_.loopForever(); });
  worker_->shutdownAllConnections(LocalErrorCode::SHUTTING_DOWN);
  eventbase_.terminateLoopSoon();
  t.join();
}

TEST_F(QuicServerWorkerTest, PacketAfterShutdown) {
  std::thread t([&] { eventbase_.loopForever(); });
  worker_->shutdownAllConnections(LocalErrorCode::SHUTTING_DOWN);
  auto connId = getTestConnectionId(hostId_);
  PacketNum packetNum = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial, connId, connId, packetNum, version);
  EXPECT_CALL(*factory_, _make(_, _, _, _)).Times(0);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, header, 0 /* largestAcked */);
  auto packet = packetToBuf(std::move(builder).buildPacket());
  worker_->handleNetworkData(kClientAddr, std::move(packet), Clock::now());
  eventbase_.terminateLoopSoon();
  t.join();
}

TEST_F(QuicServerWorkerTest, DestroyQuicServer) {
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  EXPECT_CALL(*transportInfoCb_, onNewConnection());
  worker_->onConnectionIdAvailable(transport_, getTestConnectionId(hostId_));
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_EQ(connIdMap.count(getTestConnectionId(hostId_)), 1);

  EXPECT_CALL(*transportInfoCb_, onConnectionClose(_));
  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(2);
  EXPECT_CALL(*transport_, setTransportInfoCallback(nullptr)).Times(2);
  EXPECT_CALL(*transport_, close(_)).WillRepeatedly(Invoke([this](auto) {
    hasShutdown_ = true;
  }));
  std::thread t([&] { eventbase_.loopForever(); });
  worker_.reset();
  eventbase_.terminateLoopSoon();
  t.join();
}

auto createInitialStream(
    ConnectionId srcConnId,
    ConnectionId destConnId,
    StreamId streamId,
    folly::IOBuf& data,
    QuicVersion version,
    LongHeader::Types pktHeaderType = LongHeader::Types::Initial) {
  PacketNum packetNum = 1;
  LongHeader header(pktHeaderType, srcConnId, destConnId, packetNum, version);
  LongHeader headerRetry(
      pktHeaderType,
      srcConnId,
      destConnId,
      packetNum,
      version,
      IOBuf::copyBuffer("this is a retry token :)"),
      getTestConnectionId());
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen,
      pktHeaderType == LongHeader::Types::Retry ? std::move(headerRetry)
                                                : std::move(header),
      0 /* largestAcked */);
  StreamFrameMetaData streamFrame;
  streamFrame.hasMoreFrames = true;
  streamFrame.id = streamId;
  streamFrame.offset = 0;
  streamFrame.fin = true;
  streamFrame.data = data.clone();
  writeStreamFrame(streamFrame, builder);
  return packetToBuf(std::move(builder).buildPacket());
}

auto createInitialStream(
    StreamId streamId,
    folly::IOBuf& data,
    QuicVersion version,
    LongHeader::Types pktHeaderType = LongHeader::Types::Initial) {
  return createInitialStream(
      getTestConnectionId(),
      getTestConnectionId(1),
      streamId,
      data,
      version,
      pktHeaderType);
}

std::unique_ptr<folly::IOBuf> writeTestDataOnWorkersBuf(
    ConnectionId srcConnId,
    ConnectionId destConnId,
    size_t& lenOut,
    QuicServerWorker* worker,
    LongHeader::Types pktHeaderType = LongHeader::Types::Initial) {
  StreamId id = 1;
  auto buf = folly::IOBuf::copyBuffer("hello, world!");
  auto packet = createInitialStream(
      srcConnId, destConnId, id, *buf, MVFST1, pktHeaderType);
  packet->coalesce();
  auto data = std::move(packet);
  uint8_t* workerBuf = nullptr;
  size_t workerBufLen = 0;
  worker->getReadBuffer((void**)&workerBuf, &workerBufLen);
  lenOut = std::min(workerBufLen, data->computeChainDataLength());
  memcpy(workerBuf, data->buffer(), lenOut);
  return data;
}

ConnectionId createConnIdForServer(ProcessId server) {
  auto connIdAlgo = std::make_unique<DefaultConnectionIdAlgo>();
  uint8_t processId = (server == ProcessId::ONE) ? 1 : 0;
  ServerConnectionIdParams params(0, processId, 0);
  params.clientConnId.assign(getTestConnectionId());
  return connIdAlgo->encodeConnectionId(params);
}

class QuicServerWorkerTakeoverTest : public Test {
 public:
  void SetUp() override {
    auto sock = std::make_unique<folly::test::MockAsyncUDPSocket>(&evb_);
    DCHECK(sock->getEventBase());
    EXPECT_CALL(*sock, getNetworkSocket())
        .WillRepeatedly(Return(folly::NetworkSocket()));
    EXPECT_CALL(*sock, pauseRead());
    takeoverWorkerCb_ = std::make_shared<MockWorkerCallback>();
    takeoverWorker_ = std::make_unique<QuicServerWorker>(takeoverWorkerCb_);
    takeoverWorker_->setSupportedVersions(supportedVersions);
    takeoverWorker_->setSocket(std::move(sock));
    takeoverSocketFactory_ = std::make_unique<MockQuicUDPSocketFactory>();
    takeoverWorker_->setNewConnectionSocketFactory(
        takeoverSocketFactory_.get());
    factory_ = std::make_unique<MockQuicServerTransportFactory>();
    takeoverWorker_->setTransportFactory(factory_.get());
    auto transportInfoCb = std::make_unique<MockQuicStats>();
    takeoverWorker_->setConnectionIdAlgo(
        std::make_unique<DefaultConnectionIdAlgo>());
    takeoverWorker_->setTransportInfoCallback(std::move(transportInfoCb));
    transportInfoCb_ =
        (MockQuicStats*)takeoverWorker_->getTransportInfoCallback();

    auto takeoverSock =
        std::make_unique<folly::test::MockAsyncUDPSocket>(&evb_);
    takeoverSocket_ = takeoverSock.get();
    folly::SocketAddress takeoverAddr;
    EXPECT_CALL(*takeoverSocket_, bind(_));
    EXPECT_CALL(*takeoverSocket_, resumeRead(_));
    takeoverWorker_->allowBeingTakenOver(std::move(takeoverSock), takeoverAddr);
  }

  void testPacketForwarding(Buf data, size_t len, ConnectionId connId);

  void testNoPacketForwarding(Buf data, size_t len, ConnectionId connId);

 protected:
  std::unique_ptr<QuicServerWorker> takeoverWorker_;
  std::shared_ptr<MockWorkerCallback> takeoverWorkerCb_;
  folly::test::MockAsyncUDPSocket* takeoverSocket_;
  folly::EventBase evb_;
  folly::IOBufEqualTo eq;
  folly::SocketAddress clientAddr{"1.2.3.4", 49};
  std::unique_ptr<MockQuicUDPSocketFactory> takeoverSocketFactory_;
  std::unique_ptr<MockQuicServerTransportFactory> factory_;
  MockQuicStats* transportInfoCb_{nullptr};
  std::vector<QuicVersion> supportedVersions{QuicVersion::MVFST, MVFST1};
  uint16_t clientHostId_{25};
};

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverNoForwarding) {
  ConnectionId connId = createConnIdForServer(ProcessId::ONE),
               clientConnId = getTestConnectionId(clientHostId_);
  takeoverWorker_->setProcessId(ProcessId::ONE);
  size_t len{0};
  auto data = writeTestDataOnWorkersBuf(
      clientConnId, connId, len, takeoverWorker_.get());
  // enable packet forwarding
  takeoverWorker_->startPacketForwarding(folly::SocketAddress("0", 0));

  // this packet belongs to this server, so it should write unaltered packet
  // to the actual client. Also test different variations in header type Also
  // verify that the packet is not forwarded for all packet types
  testNoPacketForwarding(
      writeTestDataOnWorkersBuf(
          clientConnId,
          connId,
          len,
          takeoverWorker_.get(),
          LongHeader::Types::Initial),
      len,
      connId);
  testNoPacketForwarding(
      writeTestDataOnWorkersBuf(
          clientConnId,
          connId,
          len,
          takeoverWorker_.get(),
          LongHeader::Types::Retry),
      len,
      connId);
  testNoPacketForwarding(
      writeTestDataOnWorkersBuf(
          clientConnId,
          connId,
          len,
          takeoverWorker_.get(),
          LongHeader::Types::Handshake),
      len,
      connId);
  testNoPacketForwarding(
      writeTestDataOnWorkersBuf(
          clientConnId,
          connId,
          len,
          takeoverWorker_.get(),
          LongHeader::Types::ZeroRtt),
      len,
      connId);
}

void QuicServerWorkerTakeoverTest::testNoPacketForwarding(
    Buf /* data */,
    size_t len,
    ConnectionId /* connId */) {
  auto cb = [&](const folly::SocketAddress& addr,
                std::unique_ptr<RoutingData>& /* routingData */,
                std::unique_ptr<NetworkData>& /* networkData */) {
    EXPECT_EQ(addr.getIPAddress(), clientAddr.getIPAddress());
    EXPECT_EQ(addr.getPort(), clientAddr.getPort());
  };
  EXPECT_CALL(*takeoverWorkerCb_, routeDataToWorkerLong(_, _, _))
      .WillOnce(Invoke(cb));
  EXPECT_CALL(*transportInfoCb_, onPacketReceived());
  EXPECT_CALL(*transportInfoCb_, onRead(len));
  EXPECT_CALL(*transportInfoCb_, onPacketForwarded()).Times(0);
  takeoverWorker_->onDataAvailable(clientAddr, len, false);
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverForwarding) {
  // now try for packets that belongs to different server
  ConnectionId connId = createConnIdForServer(ProcessId::ZERO),
               clientConnId = getTestConnectionId(clientHostId_);
  takeoverWorker_->setProcessId(ProcessId::ONE);
  size_t len{0};
  // Test the packet forwarding works for all packet type expect Initial
  auto pkt = writeTestDataOnWorkersBuf(
      clientConnId,
      connId,
      len,
      takeoverWorker_.get(),
      LongHeader::Types::Retry);
  testPacketForwarding(std::move(pkt), len, connId);

  pkt = writeTestDataOnWorkersBuf(
      clientConnId,
      connId,
      len,
      takeoverWorker_.get(),
      LongHeader::Types::Handshake);
  testPacketForwarding(std::move(pkt), len, connId);

  pkt = writeTestDataOnWorkersBuf(
      clientConnId,
      connId,
      len,
      takeoverWorker_.get(),
      LongHeader::Types::ZeroRtt);
  testPacketForwarding(std::move(pkt), len, connId);
  // verify that the Initial packet type is not forwarded even if the
  // server-bit is different
  pkt = writeTestDataOnWorkersBuf(
      clientConnId,
      connId,
      len,
      takeoverWorker_.get(),
      LongHeader::Types::Initial);
  testNoPacketForwarding(std::move(pkt), len, connId);
}

void QuicServerWorkerTakeoverTest::testPacketForwarding(
    Buf data,
    size_t len,
    ConnectionId connId) {
  auto writeSock = std::make_unique<folly::test::MockAsyncUDPSocket>(&evb_);
  EXPECT_CALL(*takeoverSocketFactory_, _make(_, _))
      .WillOnce(Return(writeSock.get()));
  EXPECT_CALL(*writeSock, bind(_));
  EXPECT_CALL(*writeSock, write(_, _))
      .WillOnce(Invoke([&](const SocketAddress& /* unused */,
                           const std::unique_ptr<folly::IOBuf>& writtenData) {
        // the writtenData contains actual client address + time of ack + data
        EXPECT_FALSE(eq(*data, *writtenData));
        // extract and verify the encoded client address
        folly::io::Cursor cursor(writtenData.get());
        uint32_t protocotVersion = (cursor.readBE<uint32_t>());
        EXPECT_EQ(protocotVersion, 0x0000001);
        uint16_t addrLen = (cursor.readBE<uint16_t>());
        struct sockaddr* sockaddr = nullptr;
        std::pair<const uint8_t*, size_t> addrData = cursor.peek();
        EXPECT_GE(addrData.second, addrLen);
        sockaddr = (struct sockaddr*)addrData.first;
        cursor.skip(addrLen);

        folly::SocketAddress actualClient;
        actualClient.setFromSockaddr(sockaddr, addrLen);
        EXPECT_EQ(actualClient.getIPAddress(), clientAddr.getIPAddress());
        EXPECT_EQ(actualClient.getPort(), clientAddr.getPort());
        auto pktReceiveEpoch = cursor.readBE<uint64_t>();

        // the encoded time should be strictly less than 'now'
        EXPECT_LT(pktReceiveEpoch, Clock::now().time_since_epoch().count());

        // skip to the start of the packet
        writtenData->trimStart(
            sizeof(uint32_t) + sizeof(uint16_t) + addrLen + sizeof(uint64_t));
        EXPECT_TRUE(eq(*data, *writtenData));
        // parse header and check connId to verify the integrity of the packet
        auto parsedHeader = parseHeader(*writtenData);
        auto& header = parsedHeader->parsedHeader->header;
        const auto& connectionId = folly::variant_match(
            header,
            [](const LongHeader& longHeader) {
              return longHeader.getDestinationConnId();
            },
            [](const ShortHeader& shortHeader) {
              return shortHeader.getConnectionId();
            });
        EXPECT_EQ(connId, connectionId);
        return data->computeChainDataLength();
      }));
  takeoverWorker_->startPacketForwarding(folly::SocketAddress("0", 0));

  auto cb = [&](const folly::SocketAddress& client,
                std::unique_ptr<RoutingData>& routingData,
                std::unique_ptr<NetworkData>& networkData) {
    takeoverWorker_->dispatchPacketData(
        client, std::move(*routingData.get()), std::move(*networkData.get()));
  };
  EXPECT_CALL(*takeoverWorkerCb_, routeDataToWorkerLong(_, _, _))
      .WillOnce(Invoke(cb));
  EXPECT_CALL(*transportInfoCb_, onPacketReceived());
  EXPECT_CALL(*transportInfoCb_, onRead(len));
  EXPECT_CALL(*transportInfoCb_, onPacketForwarded()).Times(1);
  takeoverWorker_->onDataAvailable(clientAddr, len, false);
  takeoverWorker_->stopPacketForwarding();
  // release this resource since MockQuicUDPSocketFactory::_make() hands its
  // ownership to it's caller (i.e. QuicServerWorker)
  writeSock.release();
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverProcessForwardedPkt) {
  // packet belongs to different server
  ConnectionId connId = createConnIdForServer(ProcessId::ZERO),
               clientConnId = getTestConnectionId(clientHostId_);
  takeoverWorker_->setProcessId(ProcessId::ONE);
  size_t len{0};
  auto data = writeTestDataOnWorkersBuf(
      clientConnId,
      connId,
      len,
      takeoverWorker_.get(),
      LongHeader::Types::Handshake);
  takeoverWorker_->startPacketForwarding(folly::SocketAddress("0", 0));

  // the packet will be forwarded
  auto writeSock = std::make_unique<folly::test::MockAsyncUDPSocket>(&evb_);
  EXPECT_CALL(*takeoverSocketFactory_, _make(_, _))
      .WillOnce(Return(writeSock.get()));
  EXPECT_CALL(*writeSock, bind(_));
  EXPECT_CALL(*writeSock, write(_, _))
      .WillOnce(Invoke([&](const SocketAddress& client,
                           const std::unique_ptr<folly::IOBuf>& writtenData) {
        // the writtenData contains actual client address + time of ack + data
        EXPECT_FALSE(eq(*data, *writtenData));

        // flip the server id to 'own' the packet (else it'll keep forwarding)
        takeoverWorker_->setProcessId(ProcessId::ZERO);

        // now invoke the Takeover Handler callback
        folly::AsyncUDPSocket::ReadCallback* takeoverCb =
            takeoverWorker_->getTakeoverHandlerCallback();
        uint8_t* workerBuf = nullptr;
        size_t workerBufLen = 0;
        takeoverCb->getReadBuffer((void**)&workerBuf, &workerBufLen);
        writtenData->coalesce();
        size_t bufLen =
            std::min(workerBufLen, writtenData->computeChainDataLength());
        memcpy(workerBuf, writtenData->buffer(), bufLen);

        // test processing of the forwarded packet
        auto cb = [&](const folly::SocketAddress& addr,
                      std::unique_ptr<RoutingData>& /* routingData */,
                      std::unique_ptr<NetworkData>& networkData) {
          // verify that it is the original client address
          EXPECT_EQ(addr.getIPAddress(), clientAddr.getIPAddress());
          EXPECT_EQ(addr.getPort(), clientAddr.getPort());
          // the original data should be extracted after processing takeover
          // protocol related information
          EXPECT_TRUE(eq(*data, *(networkData->data)));
        };
        EXPECT_CALL(*takeoverWorkerCb_, routeDataToWorkerLong(_, _, _))
            .WillOnce(Invoke(cb));

        takeoverCb->onDataAvailable(client, bufLen, false);
        return bufLen;
      }));
  auto workerCb = [&](const folly::SocketAddress& client,
                      std::unique_ptr<RoutingData>& routingData,
                      std::unique_ptr<NetworkData>& networkData) {
    takeoverWorker_->dispatchPacketData(
        client, std::move(*routingData.get()), std::move(*networkData.get()));
  };
  EXPECT_CALL(*takeoverWorkerCb_, routeDataToWorkerLong(_, _, _))
      .WillOnce(Invoke(workerCb));
  EXPECT_CALL(*transportInfoCb_, onPacketReceived());
  EXPECT_CALL(*transportInfoCb_, onRead(len));
  EXPECT_CALL(*transportInfoCb_, onPacketForwarded()).Times(1);
  EXPECT_CALL(*transportInfoCb_, onForwardedPacketReceived()).Times(1);
  EXPECT_CALL(*transportInfoCb_, onForwardedPacketProcessed()).Times(1);
  takeoverWorker_->onDataAvailable(clientAddr, len, false);
  // release this resource since MockQuicUDPSocketFactory::_make() hands its
  // ownership to it's caller (i.e. QuicServerWorker)
  writeSock.release();
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverCbReadClose) {
  folly::AsyncUDPSocket::ReadCallback* takeoverCb =
      takeoverWorker_->getTakeoverHandlerCallback();
  takeoverCb->onReadClosed();
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverCbReadError) {
  folly::AsyncUDPSocket::ReadCallback* takeoverCb =
      takeoverWorker_->getTakeoverHandlerCallback();
  EXPECT_CALL(*takeoverSocket_, pauseRead());
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::AsyncSocketExceptionType::UNKNOWN, "");
  takeoverCb->onReadError(ex);
}

class QuicServerTest : public Test {
 public:
  void SetUp() override {
    auto factory = std::make_unique<MockQuicServerTransportFactory>();
    factory_ = factory.get();
    server_ = QuicServer::createQuicServer();
    server_->setQuicServerTransportFactory(std::move(factory));
    server_->setFizzContext(quic::test::createServerCtx());
    server_->setHostId(serverHostId_);
    transportSettings_.advertisedInitialConnectionWindowSize =
        kDefaultConnectionWindowSize * 2;
    transportSettings_.advertisedInitialBidiLocalStreamWindowSize =
        kDefaultStreamWindowSize * 2;
    transportSettings_.advertisedInitialBidiRemoteStreamWindowSize =
        kDefaultStreamWindowSize * 2;
    transportSettings_.advertisedInitialUniStreamWindowSize =
        kDefaultStreamWindowSize * 2;
    transportSettings_.statelessResetTokenSecret = getRandSecret();
    server_->setTransportSettings(transportSettings_);
    server_->setConnectionIdAlgoFactory(
        std::make_unique<DefaultConnectionIdAlgoFactory>());
  }

  void TearDown() override {
    server_->shutdown();
  }

  void setUpTransportFactoryForWorkers(std::vector<folly::EventBase*> evbs) {
    for (auto ev : evbs) {
      EXPECT_TRUE(server_->isInitialized());
      server_->addTransportFactory(ev, factory_);
    }
  }

  folly::SocketAddress initializeServer(
      std::vector<folly::EventBase*> evbs,
      MockQuicStats* stats = nullptr) {
    folly::SocketAddress addr("::1", 0);
    // test that the transportStatsFactory works as expected

    auto transportStatsFactory = std::make_unique<MockQuicStatsFactory>();
    transportStatsFactory_ = transportStatsFactory.get();
    server_->setTransportStatsCallbackFactory(std::move(transportStatsFactory));

    if (stats) {
      CHECK_EQ(evbs.size(), 1);
      EXPECT_CALL(*transportStatsFactory_, make(_))
          .WillRepeatedly(Invoke([stats = std::move(stats)](folly::EventBase*) {
            return std::unique_ptr<MockQuicStats>(stats);
          }));
    } else {
      EXPECT_CALL(*transportStatsFactory_, make(_))
          .WillRepeatedly(Invoke([&](folly::EventBase* /* unused */) {
            auto mockInfoCb = std::make_unique<MockQuicStats>();
            return mockInfoCb;
          }));
    }
    if (evbs.empty()) {
      server_->start(addr, 2);
    } else {
      server_->initialize(addr, evbs);
      server_->start();
      setUpTransportFactoryForWorkers(evbs);
    }

    server_->waitUntilInitialized();
    return server_->getAddress();
  }

  std::shared_ptr<MockQuicTransport> createNewTransport(
      folly::EventBase* eventBase,
      folly::AsyncUDPSocket& client,
      folly::SocketAddress serverAddr) {
    // create payload
    StreamId id = 1;
    auto clientConnId = getTestConnectionId(clientHostId_),
         serverConnId = getTestConnectionId(serverHostId_);
    auto buf = createData(kMinInitialPacketSize);
    auto packet = createInitialStream(
        clientConnId, serverConnId, id, *buf, QuicVersion::MVFST);
    auto data = std::move(packet);
    std::mutex m;
    std::condition_variable cv;
    bool calledOnNetworkData = false;

    // create mock transport
    std::shared_ptr<MockQuicTransport> transport;
    eventBase->runInEventBaseThreadAndWait([&] {
      MockConnectionCallback cb;
      auto mockSock =
          std::make_unique<folly::test::MockAsyncUDPSocket>(eventBase);
      EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(serverAddr));
      transport = std::make_shared<MockQuicTransport>(
          eventBase, std::move(mockSock), cb, quic::test::createServerCtx());
    });

    auto makeTransport = [&](
        folly::EventBase * evb,
        std::unique_ptr<folly::AsyncUDPSocket>& /* socket */,
        const folly::SocketAddress&,
        std::shared_ptr<const fizz::server::FizzServerContext>) noexcept {
      // set proper expectations for the transport after its creation
      EXPECT_CALL(*transport, getEventBase()).WillRepeatedly(Return(evb));
      EXPECT_CALL(*transport, setTransportInfoCallback(_))
          .WillOnce(Invoke([&](QuicTransportStatsCallback* infoCallback) {
            CHECK(infoCallback);
          }));
      EXPECT_CALL(*transport, setTransportSettings(_))
          .WillRepeatedly(Invoke([&](auto transportSettings) {
            EXPECT_EQ(
                transportSettings_.advertisedInitialBidiLocalStreamWindowSize,
                transportSettings.advertisedInitialBidiLocalStreamWindowSize);
            EXPECT_EQ(
                transportSettings_.advertisedInitialBidiRemoteStreamWindowSize,
                transportSettings.advertisedInitialBidiRemoteStreamWindowSize);
            EXPECT_EQ(
                transportSettings_.advertisedInitialUniStreamWindowSize,
                transportSettings.advertisedInitialUniStreamWindowSize);
            EXPECT_EQ(
                transportSettings_.advertisedInitialConnectionWindowSize,
                transportSettings.advertisedInitialConnectionWindowSize);
          }));
      ON_CALL(*transport, onNetworkData(_, _))
          .WillByDefault(Invoke([&, expected = data.get()](auto, auto buf) {
            EXPECT_TRUE(folly::IOBufEqualTo()(*buf, *expected));
            std::unique_lock<std::mutex> lg(m);
            calledOnNetworkData = true;
            cv.notify_one();
          }));
      return transport;
    };
    EXPECT_CALL(*factory_, _make(_, _, _, _)).WillOnce(Invoke(makeTransport));
    // send packets to the server
    std::unique_lock<std::mutex> lg(m);
    size_t tries = 0;
    if (!calledOnNetworkData && tries < 3) {
      tries++;
      auto ret = client.write(serverAddr, data->clone());
      CHECK_EQ(ret, data->computeChainDataLength());
      cv.wait_until(lg, std::chrono::system_clock::now() + 1s, [&] {
        return calledOnNetworkData;
      });
    }
    CHECK(calledOnNetworkData);
    return transport;
  }

  std::unique_ptr<folly::AsyncUDPSocket> makeUdpClient() {
    folly::SocketAddress addr2("::1", 0);
    std::unique_ptr<folly::AsyncUDPSocket> client;
    evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
      client =
          std::make_unique<folly::AsyncUDPSocket>(evbThread_.getEventBase());
      client->bind(addr2);
    });
    return client;
  }

  void closeUdpClient(std::unique_ptr<folly::AsyncUDPSocket> client) {
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { client->close(); });
  }

  void runTest(std::vector<folly::EventBase*> evbs) {
    auto serverAddr = initializeServer(evbs);
    auto client = makeUdpClient();
    folly::EventBase* evb = server_->getWorkerEvbs().back();
    auto transport = createNewTransport(evb, *client, serverAddr);
    EXPECT_CALL(*transport, setTransportInfoCallback(nullptr));
    EXPECT_CALL(*transport, setRoutingCallback(nullptr));
    EXPECT_CALL(*transport, closeNow(_));
    mockStats_.reset();
    server_->shutdown();
    closeUdpClient(std::move(client));
    // cleanup transport
    transport->getEventBase()->runInEventBaseThreadAndWait(
        [&] { transport.reset(); });
  }

  void testReset(Buf packet);

 protected:
  folly::ScopedEventBaseThread evbThread_;
  std::shared_ptr<QuicServer> server_;
  MockQuicServerTransportFactory* factory_;
  TransportSettings transportSettings_;
  MockQuicStatsFactory* transportStatsFactory_;
  folly::ThreadLocalPtr<MockQuicStats> mockStats_;
  uint16_t clientHostId_{0}, serverHostId_{1};
}; // namespace test

TEST_F(QuicServerTest, NetworkTest) {
  runTest(std::vector<folly::EventBase*>());
}

TEST_F(QuicServerTest, OtherEvbs) {
  folly::ScopedEventBaseThread evbThread;
  auto evb = evbThread.getEventBase();
  std::vector<folly::EventBase*> evbs{evb};
  runTest(evbs);
}

TEST_F(QuicServerTest, DontRouteDataAfterShutdown) {
  folly::ScopedEventBaseThread evbThread;
  std::vector<folly::EventBase*> evbs;
  evbs.emplace_back(evbThread.getEventBase());
  MockQuicStats* stats = new MockQuicStats();
  auto serverAddr = initializeServer(evbs, stats);
  auto client = makeUdpClient();
  auto transport =
      createNewTransport(evbThread.getEventBase(), *client, serverAddr);
  EXPECT_CALL(*transport, setTransportInfoCallback(nullptr));

  EXPECT_CALL(*transport, closeNow(_)).WillOnce(InvokeWithoutArgs([&] {
    PacketNum packetNum = 1;
    QuicVersion version = QuicVersion::MVFST;
    ConnectionId connId = getTestConnectionId();
    LongHeader header(
        LongHeader::Types::Initial,
        getTestConnectionId(1),
        connId,
        packetNum,
        version);
    // Simulate receiving a packet before the worker shutdown.

    EXPECT_CALL(*stats, onPacketDropped(PacketDropReason::SERVER_SHUTDOWN));
    NetworkData networkData(folly::IOBuf::copyBuffer("wat"), Clock::now());
    RoutingData routingData(
        HeaderForm::Long,
        true,
        true,
        header.getDestinationConnId(),
        header.getSourceConnId());
    server_->routeDataToWorker(
        kClientAddr, std::move(routingData), std::move(networkData));
  }));
  std::thread t([&] { server_->shutdown(); });
  t.join();
  closeUdpClient(std::move(client));
  // cleanup transport
  transport->getEventBase()->runInEventBaseThreadAndWait(
      [&] { transport.reset(); });
}

class QuicServerTakeoverTest : public Test {
 public:
  void SetUp() override {
    transportSettings_.advertisedInitialConnectionWindowSize =
        kDefaultConnectionWindowSize * 2;
    transportSettings_.advertisedInitialBidiLocalStreamWindowSize =
        kDefaultStreamWindowSize * 2;
    transportSettings_.advertisedInitialBidiRemoteStreamWindowSize =
        kDefaultStreamWindowSize * 2;
    transportSettings_.advertisedInitialUniStreamWindowSize =
        kDefaultStreamWindowSize * 2;
    setUpServer(oldServer_, ProcessId::ZERO);
    setUpServer(newServer_, ProcessId::ONE);
  }

  void setUpServer(std::shared_ptr<QuicServer>& server, ProcessId id) {
    auto factory = std::make_unique<MockQuicServerTransportFactory>();
    if (id == ProcessId::ZERO) {
      oldFactory_ = factory.get();
    } else {
      newFactory_ = factory.get();
    }
    server = QuicServer::createQuicServer();
    server->setQuicServerTransportFactory(std::move(factory));
    server->setFizzContext(quic::test::createServerCtx());
    server->setTransportSettings(transportSettings_);
    server->setProcessId(id);
  }

  std::shared_ptr<MockQuicTransport> initTransport(
      MockQuicServerTransportFactory* factory,
      ConnectionId& clientConnId,
      Buf& data,
      folly::Baton<>& baton) {
    std::shared_ptr<MockQuicTransport> transport;
    MockConnectionCallback cb;
    auto makeTransport = [&](
        folly::EventBase * eventBase,
        std::unique_ptr<folly::AsyncUDPSocket> & socket,
        const folly::SocketAddress&,
        std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept {
      transport = std::make_shared<MockQuicTransport>(
          eventBase, std::move(socket), cb, ctx);
      // setup expectations
      EXPECT_CALL(*transport, getEventBase()).WillRepeatedly(Return(eventBase));
      EXPECT_CALL(*transport, setTransportSettings(_));
      EXPECT_CALL(*transport, accept());
      EXPECT_CALL(*transport, setSupportedVersions(_));
      EXPECT_CALL(*transport, setRoutingCallback(_));
      EXPECT_CALL(*transport, setOriginalPeerAddress(_));
      EXPECT_CALL(*transport, setTransportInfoCallback(_));
      EXPECT_CALL(*transport, setServerConnectionIdParams(_))
          .WillOnce(Invoke([&](ServerConnectionIdParams params) {
            EXPECT_EQ(*params.clientConnId, clientConnId);
            EXPECT_EQ(params.processId, 0);
            EXPECT_EQ(params.workerId, 0);
          }));
      EXPECT_CALL(*transport, onNetworkData(_, _))
          .WillOnce(Invoke([&, expected = data.get()](auto, auto buf) {
            EXPECT_TRUE(folly::IOBufEqualTo()(*buf, *expected));
            baton.post();
          }));
      return transport;
    };
    EXPECT_CALL(*factory, _make(_, _, _, _)).WillOnce(Invoke(makeTransport));
    return transport;
  }

  void runTest(
      std::vector<folly::EventBase*> evbs1,
      std::vector<folly::EventBase*> evbs2) {
    folly::Baton<> b;
    ConnectionId clientConnId = getTestConnectionId(clientHostId_);
    // create a packet to send to the old server and verify that it accepts it
    StreamId id = 1;
    auto buf = createData(kMinInitialPacketSize);
    ConnectionId connId = createConnIdForServer(ProcessId::ZERO);
    auto packet =
        createInitialStream(clientConnId, connId, id, *buf, QuicVersion::MVFST);
    auto data = std::move(packet);
    auto transportCbForOldServer =
        initTransport(oldFactory_, clientConnId, data, b);
    folly::SocketAddress addr("::1", 0);
    // setup mock transport stats factory
    auto transportStatsFactory = std::make_unique<MockQuicStatsFactory>();
    auto makeCbForOldServer = [&](folly::EventBase* /* unused */) {
      oldTransInfoCb_ = new MockQuicStats();
      std::unique_ptr<MockQuicStats> transportInfoCb;
      transportInfoCb.reset(oldTransInfoCb_);
      return transportInfoCb;
    };
    EXPECT_CALL(*transportStatsFactory, make(_))
        .WillOnce(Invoke(makeCbForOldServer));
    oldServer_->setTransportStatsCallbackFactory(
        std::move(transportStatsFactory));

    oldServer_->initialize(addr, evbs1);
    oldServer_->start();
    oldServer_->waitUntilInitialized();
    for (auto ev : evbs1) {
      oldServer_->addTransportFactory(ev, oldFactory_);
    }
    auto serverAddr = oldServer_->getAddress();
    folly::SocketAddress takeoverAddr("::1", 0);
    oldServer_->allowBeingTakenOver(takeoverAddr);

    folly::SocketAddress clientAddr("::1", 0);
    std::unique_ptr<folly::AsyncUDPSocket> client;
    evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
      client =
          std::make_unique<folly::AsyncUDPSocket>(evbThread_.getEventBase());
      client->bind(clientAddr);
    });
    // send packet to the server and wait
    EXPECT_CALL(*oldTransInfoCb_, onPacketReceived());
    EXPECT_CALL(*oldTransInfoCb_, onRead(_));
    client->write(serverAddr, data->clone());
    b.wait();

    // spin another server and verify that the old server gets the packet
    // that is routed to the new server
    int takeoverListeningFd = oldServer_->getTakeoverHandlerSocketFD();
    newServer_->setListeningFDs(oldServer_->getAllListeningSocketFDs());
    folly::SocketAddress newAddr("::1", 0);
    // setup mock transport stats factory
    transportStatsFactory = std::make_unique<MockQuicStatsFactory>();
    auto makeCbForNewServer = [&](folly::EventBase* /* unused */) {
      newTransInfoCb_ = new MockQuicStats();
      std::unique_ptr<MockQuicStats> transportInfoCb;
      transportInfoCb.reset(newTransInfoCb_);
      return transportInfoCb;
    };
    EXPECT_CALL(*transportStatsFactory, make(_))
        .WillOnce(Invoke(makeCbForNewServer));
    newServer_->setTransportStatsCallbackFactory(
        std::move(transportStatsFactory));

    newServer_->initialize(newAddr, evbs2);
    newServer_->start();
    newServer_->waitUntilInitialized();
    for (auto ev : evbs2) {
      newServer_->addTransportFactory(ev, newFactory_);
    }
    folly::SocketAddress destAddr;
    destAddr.setFromLocalAddress(
        folly::NetworkSocket::fromFd(takeoverListeningFd));
    newServer_->startPacketForwarding(destAddr);
    auto newServerAddr = newServer_->getAddress();

    packet = createInitialStream(
        clientConnId,
        connId,
        id,
        *buf,
        QuicVersion::MVFST,
        LongHeader::Types::Retry);
    data = std::move(packet);

    folly::Baton<> b1;
    // onNetworkData(_, _) shouldn't be called on the newServer_ transport,
    // but should be routed to oldServer_
    EXPECT_CALL(*transportCbForOldServer, onNetworkData(_, _))
        .WillOnce(Invoke([&, expected = data.get()](auto, auto buf) {
          EXPECT_TRUE(folly::IOBufEqualTo()(*buf, *expected));
          b1.post();
        }));
    // new quic server receives the packet and forwards it
    EXPECT_CALL(*newTransInfoCb_, onPacketReceived());
    EXPECT_CALL(*newTransInfoCb_, onRead(_));
    EXPECT_CALL(*newTransInfoCb_, onPacketForwarded());
    EXPECT_CALL(*newTransInfoCb_, onPacketProcessed()).Times(0);
    // verify takeover related counters on the old quic server
    EXPECT_CALL(*oldTransInfoCb_, onForwardedPacketReceived());
    EXPECT_CALL(*oldTransInfoCb_, onForwardedPacketProcessed());
    // the old server should then handle it as usual
    EXPECT_CALL(*oldTransInfoCb_, onPacketDropped(_)).Times(0);

    // pause the old server so that we can deterministically route to the new
    // server
    oldServer_->pauseRead();
    client->write(newServerAddr, data->clone());
    b1.wait();
    b1.reset();

    EXPECT_CALL(*transportCbForOldServer, setRoutingCallback(nullptr));
    EXPECT_CALL(*transportCbForOldServer, closeNow(_));

    // Disable packet forwarding on the new server and send packet
    // This packet should be dropped since it's not an initial packet
    newServer_->stopPacketForwarding(0ms);
    std::atomic<bool> posted{false};
    EXPECT_CALL(*newTransInfoCb_, onPacketReceived())
        .WillRepeatedly(Invoke([&] {
          if (posted) {
            return;
          }
          posted = true;
          b1.post();
        }));
    EXPECT_CALL(*newTransInfoCb_, onRead(_)).Times(AtLeast(1));
    EXPECT_CALL(*newTransInfoCb_, onPacketForwarded()).Times(0);
    EXPECT_CALL(*newTransInfoCb_, onPacketDropped(_)).Times(AtLeast(1));
    client->write(newServerAddr, data->clone());
    client->write(newServerAddr, data->clone());

    b1.wait();

    EXPECT_CALL(*transportCbForOldServer, setTransportInfoCallback(nullptr));
    oldServer_->shutdown();
    // 'transport' never gets created for the newServer_
    // so no callback on closeNow()
    newServer_->shutdown();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { client->close(); });
    // cleanup transport
    transportCbForOldServer->getEventBase()->runInEventBaseThreadAndWait(
        [&] { transportCbForOldServer.reset(); });
  }

 protected:
  folly::ScopedEventBaseThread evbThread_;
  std::shared_ptr<QuicServer> oldServer_;
  std::shared_ptr<QuicServer> newServer_;
  MockQuicServerTransportFactory* oldFactory_;
  MockQuicServerTransportFactory* newFactory_;
  MockQuicStats* oldTransInfoCb_;
  MockQuicStats* newTransInfoCb_;
  TransportSettings transportSettings_;
  MockQuicStatsFactory* transportStatsFactory_;
  uint16_t clientHostId_{25};
};

TEST_F(QuicServerTakeoverTest, TakeoverTest) {
  folly::ScopedEventBaseThread evbThread1;
  auto evb1 = evbThread1.getEventBase();
  std::vector<folly::EventBase*> evbs1{evb1};
  folly::ScopedEventBaseThread evbThread2;
  auto evb2 = evbThread2.getEventBase();
  std::vector<folly::EventBase*> evbs2{evb2};
  runTest(evbs1, evbs2);
}

struct UDPReader : public folly::AsyncUDPSocket::ReadCallback {
  UDPReader() {
    bufPromise_ =
        std::make_unique<folly::Promise<std::unique_ptr<folly::IOBuf>>>();
  }

  ~UDPReader() override = default;

  void start(EventBase* evb, SocketAddress addr) {
    evb_ = evb;
    evb_->runInEventBaseThreadAndWait([&] {
      client = std::make_unique<folly::AsyncUDPSocket>(evb_);
      client->bind(addr);
      client->resumeRead(this);
    });
  }

  AsyncUDPSocket& getSocket() {
    return *client;
  }

  void getReadBuffer(void** buf, size_t* len) noexcept override {
    if (!buf_) {
      buf_ = IOBuf::create(kDefaultUDPReadBufferSize);
    }
    *buf = buf_->writableData();
    *len = kDefaultUDPReadBufferSize;
  }

  void onDataAvailable(
      const folly::SocketAddress&,
      size_t len,
      bool truncated) noexcept override {
    std::lock_guard<std::mutex> guard(bufLock_);
    if (truncated) {
      bufPromise_->setException(std::runtime_error("truncated buf"));
      return;
    }
    if (bufPromise_) {
      buf_->append(len);
      bufPromise_->setValue(std::move(buf_));
    }
  }

  void onReadError(const AsyncSocketException& ex) noexcept override {
    std::lock_guard<std::mutex> guard(bufLock_);
    if (bufPromise_) {
      bufPromise_->setException(ex);
    }
  }

  void onReadClosed() noexcept override {
    if (bufPromise_) {
      bufPromise_->setException(std::runtime_error("closed"));
    }
  }

  folly::Future<std::unique_ptr<folly::IOBuf>> readOne() {
    std::lock_guard<std::mutex> guard(bufLock_);
    if (!bufPromise_) {
      bufPromise_ =
          std::make_unique<folly::Promise<std::unique_ptr<folly::IOBuf>>>();
    }
    return bufPromise_->getFuture().ensure([&]() { bufPromise_ = nullptr; });
  }

 private:
  std::unique_ptr<folly::IOBuf> buf_;
  std::mutex bufLock_;
  std::unique_ptr<folly::Promise<std::unique_ptr<folly::IOBuf>>> bufPromise_;
  std::unique_ptr<folly::AsyncUDPSocket> client;
  EventBase* evb_;
};

TEST_F(QuicServerTest, NetworkTestVersionNegotiation) {
  folly::SocketAddress addr("::1", 0);
  server_->start(addr, 2);
  server_->waitUntilInitialized();
  auto testingObserver = std::make_shared<TestingEventBaseObserver>();
  server_->setEventBaseObserver(testingObserver);
  auto serverAddr = server_->getAddress();

  folly::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    server_->shutdown();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_),
       serverConnId = getTestConnectionId(serverHostId_);
  auto buf = folly::IOBuf::copyBuffer("hello");
  auto packet =
      createInitialStream(clientConnId, serverConnId, id, *buf, MVFST1);
  auto data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());

  auto serverData = reader->readOne().get();

  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  AckStates ackStates;

  auto packetQueue = bufToQueue(std::move(serverData));
  auto rawPacket = codec->parsePacket(packetQueue, ackStates);
  auto quicPacket = boost::get<QuicPacket>(rawPacket);
  auto versionPacket = boost::get<VersionNegotiationPacket>(quicPacket);

  EXPECT_EQ(versionPacket.destinationConnectionId, clientConnId);
  EXPECT_TRUE(testingObserver->observerCalled());
}

TEST_F(QuicServerTest, TestRejectNewConnections) {
  // test that Version Negotiation fails if the server is rejecting all
  // new connections
  folly::SocketAddress addr("::1", 0);
  server_->start(addr, 2);
  server_->waitUntilInitialized();
  server_->rejectNewConnections(true);
  auto testingObserver = std::make_shared<TestingEventBaseObserver>();
  server_->setEventBaseObserver(testingObserver);
  auto serverAddr = server_->getAddress();

  folly::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    server_->shutdown();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_),
       serverConnId = getTestConnectionId(serverHostId_);
  auto buf = folly::IOBuf::copyBuffer("hello");
  auto packet =
      createInitialStream(clientConnId, serverConnId, id, *buf, MVFST1);
  auto data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());

  auto serverData = reader->readOne().get();

  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  AckStates ackStates;

  auto packetQueue = bufToQueue(std::move(serverData));
  auto rawPacket = codec->parsePacket(packetQueue, ackStates);
  auto quicPacket = boost::get<QuicPacket>(rawPacket);
  auto versionPacket = boost::get<VersionNegotiationPacket>(quicPacket);

  EXPECT_EQ(versionPacket.destinationConnectionId, clientConnId);
  EXPECT_EQ(versionPacket.sourceConnectionId, serverConnId);
  EXPECT_TRUE(testingObserver->observerCalled());
  EXPECT_EQ(versionPacket.versions.size(), 1);
  EXPECT_EQ(versionPacket.versions.at(0), QuicVersion::MVFST_INVALID);

  // Then reset the reject flag and check that we get a valid version instead
  server_->rejectNewConnections(false);

  buf = folly::IOBuf::copyBuffer("hello");
  packet = createInitialStream(clientConnId, serverConnId, id, *buf, MVFST1);
  data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());

  serverData = reader->readOne().get();

  packetQueue = bufToQueue(std::move(serverData));
  rawPacket = codec->parsePacket(packetQueue, ackStates);
  quicPacket = boost::get<QuicPacket>(rawPacket);
  versionPacket = boost::get<VersionNegotiationPacket>(quicPacket);

  EXPECT_EQ(versionPacket.destinationConnectionId, clientConnId);
  EXPECT_EQ(versionPacket.sourceConnectionId, serverConnId);
  EXPECT_TRUE(testingObserver->observerCalled());
  EXPECT_GE(versionPacket.versions.size(), 1);
  EXPECT_NE(versionPacket.versions.at(0), QuicVersion::MVFST_INVALID);
}

TEST_F(QuicServerTest, NetworkTestHealthCheck) {
  folly::SocketAddress addr("::1", 0);
  std::string healthCheckToken = "health";
  std::string notHealthCheckToken = "health2";

  server_->setHealthCheckToken(healthCheckToken);

  server_->start(addr, 2);
  server_->waitUntilInitialized();
  auto serverAddr = server_->getAddress();

  folly::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    server_->shutdown();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };
  reader->getSocket().write(serverAddr, IOBuf::copyBuffer(healthCheckToken));
  auto serverData = reader->readOne().get();
  EXPECT_EQ(serverData->moveToFbString().toStdString(), std::string("OK"));

  reader->getSocket().write(serverAddr, IOBuf::copyBuffer(notHealthCheckToken));
  EXPECT_THROW(reader->readOne().get(20ms), folly::FutureTimeout);
}

void QuicServerTest::testReset(Buf packet) {
  folly::SocketAddress addr("::1", 0);
  server_->start(addr, 2);
  server_->waitUntilInitialized();
  auto testingObserver = std::make_shared<TestingEventBaseObserver>();
  server_->setEventBaseObserver(testingObserver);
  auto serverAddr = server_->getAddress();

  folly::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    server_->shutdown();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
  };

  reader->getSocket().write(serverAddr, packet->clone());

  auto serverData = reader->readOne().get(1000ms);
  EXPECT_LE(serverData->computeChainDataLength(), kDefaultUDPSendPacketLen);

  QuicReadCodec codec(QuicNodeType::Client);
  auto aead = createNoOpAead();
  // Make the decrypt fail
  EXPECT_CALL(*aead, _tryDecrypt(_, _, _))
      .WillRepeatedly(Invoke([&](auto&, auto, auto) { return folly::none; }));
  codec.setOneRttReadCipher(std::move(aead));
  codec.setOneRttHeaderCipher(test::createNoOpHeaderCipher());
  StatelessResetToken token = generateStatelessResetToken();
  codec.setStatelessResetToken(token);
  AckStates ackStates;
  auto packetQueue = bufToQueue(serverData->clone());
  auto res = codec.parsePacket(packetQueue, ackStates);
  bool isReset = folly::variant_match(
      res, [](StatelessReset&) { return true; }, [](auto&) { return false; });
  EXPECT_TRUE(isReset);
}

TEST_F(QuicServerTest, NetworkTestReset) {
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_),
       serverConnId = getTestConnectionId(serverHostId_);
  PacketNum packetNum = 20;
  auto buf = folly::IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      clientConnId,
      serverConnId,
      packetNum,
      id,
      *buf,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  auto data = std::move(packet);
  testReset(data->clone());
}

TEST_F(QuicServerTest, NetworkTestResetLargePacket) {
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_),
       serverConnId = getTestConnectionId(serverHostId_);
  PacketNum packetNum = 20;
  auto buf = folly::IOBuf::create(kDefaultUDPSendPacketLen + 3);
  buf->append(kDefaultUDPSendPacketLen + 3);
  auto packet = packetToBuf(createStreamPacket(
      clientConnId,
      serverConnId,
      packetNum,
      id,
      *buf,
      0 /* cipherOverhead */,
      0 /* largestAcked */));
  testReset(std::move(packet));
}

TEST_F(QuicServerTest, NetworkTestResetLongHeader) {
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_),
       serverConnId = getTestConnectionId(serverHostId_);
  PacketNum packetNum = 20;
  auto buf = folly::IOBuf::copyBuffer("hello");
  auto packet = packetToBuf(createStreamPacket(
      clientConnId,
      serverConnId,
      packetNum,
      id,
      *buf,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST)));
  EXPECT_THROW(testReset(std::move(packet)), folly::FutureTimeout);
}

TEST_F(QuicServerTest, ZeroRttPacketRoute) {
  folly::ScopedEventBaseThread evbThread;
  auto evb = evbThread.getEventBase();
  std::vector<folly::EventBase*> evbs{evb};

  folly::SocketAddress addr("::1", 0);
  server_->start(addr, 1);
  server_->waitUntilInitialized();
  auto testingObserver = std::make_shared<TestingEventBaseObserver>();
  server_->setEventBaseObserver(testingObserver);

  setUpTransportFactoryForWorkers(evbs);
  std::shared_ptr<MockQuicTransport> transport;
  MockConnectionCallback cb;
  folly::Baton<> b;
  // create payload
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_),
       serverConnId = getTestConnectionId(serverHostId_);
  auto buf = createData(kMinInitialPacketSize + 10);
  auto packet = createInitialStream(
      clientConnId, serverConnId, id, *buf, QuicVersion::MVFST);
  auto data = std::move(packet);

  auto makeTransport = [&](
      folly::EventBase * eventBase,
      std::unique_ptr<folly::AsyncUDPSocket> & socket,
      const folly::SocketAddress&,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept {
    transport = std::make_shared<MockQuicTransport>(
        eventBase, std::move(socket), cb, ctx);
    EXPECT_CALL(*transport, getEventBase()).WillRepeatedly(Return(eventBase));
    EXPECT_CALL(*transport, setSupportedVersions(_));
    EXPECT_CALL(*transport, setOriginalPeerAddress(_));
    EXPECT_CALL(*transport, setTransportSettings(_));
    EXPECT_CALL(*transport, setServerConnectionIdParams(_));
    EXPECT_CALL(*transport, accept());
    // post baton upon receiving the data
    EXPECT_CALL(*transport, onNetworkData(_, _))
        .WillOnce(Invoke([&, expected = data.get()](auto, auto buf) {
          EXPECT_TRUE(folly::IOBufEqualTo()(*buf, *expected));
          b.post();
        }));
    return transport;
  };
  EXPECT_CALL(*factory_, _make(_, _, _, _)).WillOnce(Invoke(makeTransport));

  auto serverAddr = server_->getAddress();

  folly::SocketAddress addr2("::1", 0);

  std::unique_ptr<UDPReader> reader = std::make_unique<UDPReader>();
  reader->start(evbThread_.getEventBase(), addr2);

  SCOPE_EXIT {
    server_->shutdown();
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { reader->getSocket().close(); });
    transport->getEventBase()->runInEventBaseThreadAndWait(
        [&] { transport.reset(); });
  };

  // send an initial packet - that should create a new 'connection'
  reader->getSocket().write(serverAddr, data->clone());
  b.wait();

  // now send 0-rtt packet, and verify that it gets routed properly
  PacketNum packetNum = 20;
  packet = packetToBuf(createStreamPacket(
      clientConnId,
      serverConnId,
      packetNum,
      id,
      *buf,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST)));
  data = std::move(packet);
  folly::Baton<> b1;
  auto verifyZeroRtt = [&](
      const folly::SocketAddress& peer, const folly::IOBuf* rcvdPkt) noexcept {
    EXPECT_EQ(peer, reader->getSocket().address());
    EXPECT_TRUE(folly::IOBufEqualTo()(*rcvdPkt, *data));
    b1.post();
  };
  EXPECT_CALL(*transport, onNetworkData(_, _)).WillOnce(Invoke(verifyZeroRtt));
  reader->getSocket().write(serverAddr, data->clone());
  b1.wait();
}

} // namespace test
} // namespace quic
