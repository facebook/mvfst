/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/QuicServer.h>

#include <folly/futures/Promise.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/api/test/Mocks.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/QuicHeaderCodec.h>
#include <quic/codec/test/Mocks.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/server/AcceptObserver.h>
#include <quic/server/SlidingWindowRateLimiter.h>
#include <quic/server/handshake/StatelessResetGenerator.h>
#include <quic/server/handshake/TokenGenerator.h>
#include <quic/server/test/Mocks.h>
#include <quic/state/test/MockQuicStats.h>

using namespace testing;
using namespace folly;

using OnDataAvailableParams =
    quic::QuicAsyncUDPSocketWrapper::ReadCallback::OnDataAvailableParams;

const folly::SocketAddress kClientAddr("1.2.3.4", 1234);
const folly::SocketAddress kClientAddr2("1.2.3.5", 1235);
const folly::SocketAddress kClientAddr3("1.2.3.6", 1236);

namespace quic {
namespace test {

MATCHER_P(NetworkDataMatches, networkData, "") {
  for (size_t i = 0; i < arg.packets.size(); ++i) {
    folly::IOBufEqualTo eq;
    bool equals = eq(*arg.packets[i], networkData);
    if (equals) {
      return true;
    }
  }
  return false;
}

/**
 * QuicServerWorker test without a connection to drive any real behavior. Use
 * QuicServerWorkerTest for most cases.
 */
class SimpleQuicServerWorkerTest : public Test {
 protected:
  folly::EventBase eventbase_;
  std::unique_ptr<QuicServerWorker> worker_;
  std::shared_ptr<MockWorkerCallback> workerCb_;
  folly::test::MockAsyncUDPSocket* rawSocket_{nullptr};
};

TEST_F(SimpleQuicServerWorkerTest, RejectCid) {
  folly::SocketAddress addr("::1", 0);
  auto mockSock =
      std::make_unique<folly::test::MockAsyncUDPSocket>(&eventbase_);
  EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(addr));
  MockConnectionSetupCallback mockConnectionSetupCallback;
  MockConnectionCallback mockConnectionCallback;
  MockQuicTransport::Ptr transportPtr = std::make_shared<MockQuicTransport>(
      &eventbase_,
      std::move(mockSock),
      &mockConnectionSetupCallback,
      &mockConnectionCallback,
      nullptr);
  workerCb_ = std::make_shared<NiceMock<MockWorkerCallback>>();
  worker_ = std::make_unique<QuicServerWorker>(workerCb_);
  worker_->setSocket(
      std::make_unique<folly::test::MockAsyncUDPSocket>(&eventbase_));
  auto includeCid = getTestConnectionId(0);
  auto excludeCid = getTestConnectionId(1);
  EXPECT_FALSE(worker_->rejectConnectionId(includeCid));
  EXPECT_FALSE(worker_->rejectConnectionId(excludeCid));

  worker_->onConnectionIdAvailable(transportPtr, includeCid);

  EXPECT_TRUE(worker_->rejectConnectionId(includeCid));
  EXPECT_FALSE(worker_->rejectConnectionId(excludeCid));

  QuicServerTransport::SourceIdentity sourceId(addr, includeCid);
  std::vector<ConnectionIdData> cidDataVec;
  cidDataVec.emplace_back(includeCid, 0);

  EXPECT_CALL(*transportPtr, setRoutingCallback(nullptr)).Times(1);
  worker_->onConnectionUnbound(transportPtr.get(), sourceId, cidDataVec);
  EXPECT_FALSE(worker_->rejectConnectionId(includeCid));
  EXPECT_FALSE(worker_->rejectConnectionId(excludeCid));
}

TEST_F(SimpleQuicServerWorkerTest, TurnOffPMTU) {
  auto sock =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&eventbase_);
  rawSocket_ = sock.get();
  DCHECK(sock->getEventBase());
  EXPECT_CALL(*sock, getNetworkSocket())
      .WillRepeatedly(Return(folly::NetworkSocket()));
  workerCb_ = std::make_shared<NiceMock<MockWorkerCallback>>();
  worker_ = std::make_unique<QuicServerWorker>(workerCb_);
  worker_->setSocket(std::move(sock));
  folly::SocketAddress addr("::1", 0);
  // We check versions in bind()
  worker_->setSupportedVersions({QuicVersion::MVFST});
  EXPECT_CALL(*rawSocket_, setDFAndTurnOffPMTU()).Times(1);
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
    auto sock = std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(
        &eventbase_);
    DCHECK(sock->getEventBase());
    socketPtr_ = sock.get();
    workerCb_ = std::make_shared<NiceMock<MockWorkerCallback>>();
    worker_ = std::make_unique<QuicServerWorker>(workerCb_);
    auto quicStats = std::make_unique<NiceMock<MockQuicStats>>();
    TransportSettings settings;
    settings.statelessResetTokenSecret = getRandSecret();
    tokenSecret_ = getRandSecret();
    settings.retryTokenSecret = tokenSecret_;
    worker_->setSupportedVersions({QuicVersion::MVFST});
    worker_->setTransportStatsCallback(std::move(quicStats));
    worker_->setTransportSettings(settings);
    worker_->setSocket(std::move(sock));
    worker_->setWorkerId(42);
    worker_->setProcessId(ProcessId::ONE);
    worker_->setHostId(hostId_);
    worker_->setConnectionIdAlgo(std::make_unique<DefaultConnectionIdAlgo>());
    worker_->setCongestionControllerFactory(
        std::make_shared<ServerCongestionControllerFactory>());
    quicStats_ = (MockQuicStats*)worker_->getTransportStatsCallback();

    auto cb = [&](const folly::SocketAddress& addr,
                  std::unique_ptr<RoutingData>& routingData,
                  std::unique_ptr<NetworkData>& networkData,
                  folly::Optional<QuicVersion> quicVersion,
                  bool isForwardedData) {
      worker_->dispatchPacketData(
          addr,
          std::move(*routingData.get()),
          std::move(*networkData.get()),
          std::move(quicVersion),
          isForwardedData);
    };

    EXPECT_CALL(*workerCb_, routeDataToWorkerLong(_, _, _, _, _))
        .WillRepeatedly(Invoke(cb));

    socketFactory_ = std::make_unique<MockQuicUDPSocketFactory>();
    EXPECT_CALL(*socketFactory_, _make(_, _)).WillRepeatedly(Return(nullptr));
    worker_->setNewConnectionSocketFactory(socketFactory_.get());
    NiceMock<MockConnectionSetupCallback> connSetupCb;
    NiceMock<MockConnectionCallback> connCb;
    std::unique_ptr<folly::test::MockAsyncUDPSocket> mockSock =
        std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(
            &eventbase_);
    EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));
    transport_.reset(new MockQuicTransport(
        worker_->getEventBase(),
        std::move(mockSock),
        &connSetupCb,
        &connCb,
        nullptr));
    factory_ = std::make_unique<MockQuicServerTransportFactory>();
    EXPECT_CALL(*transport_, getEventBase())
        .WillRepeatedly(Return(&eventbase_));
    EXPECT_CALL(*transport_, getOriginalPeerAddress())
        .WillRepeatedly(ReturnRef(kClientAddr));
    EXPECT_CALL(*transport_, hasShutdown())
        .WillRepeatedly(ReturnPointee(&hasShutdown_));
    worker_->setTransportFactory(factory_.get());
    EXPECT_CALL(*quicStats_, onTokenDecryptFailure()).Times(0);
  }

  void createQuicConnection(
      const folly::SocketAddress& addr,
      ConnectionId connId,
      MockQuicTransport::Ptr transportOverride = nullptr);

  void expectConnectionCreation(
      const folly::SocketAddress& addr,
      MockQuicTransport::Ptr transportOverride = nullptr);

  void testSendReset(
      Buf packet,
      ConnectionId connId,
      ShortHeader shortHeader,
      PacketDropReason dropReason);

  void expectConnCreateRefused();
  void createQuicConnectionDuringShedding(
      const folly::SocketAddress& addr,
      ConnectionId connId);

 protected:
  folly::SocketAddress fakeAddress_;
  folly::EventBase eventbase_;
  std::unique_ptr<QuicServerWorker> worker_;
  MockQuicTransport::Ptr transport_;
  std::shared_ptr<MockWorkerCallback> workerCb_;
  std::unique_ptr<MockQuicServerTransportFactory> factory_;
  std::unique_ptr<MockQuicUDPSocketFactory> listenerSocketFactory_;
  std::unique_ptr<MockQuicUDPSocketFactory> socketFactory_;
  MockQuicStats* quicStats_{nullptr};
  folly::test::MockAsyncUDPSocket* socketPtr_{nullptr};
  uint16_t hostId_{49};
  bool hasShutdown_{false};
  TokenSecret tokenSecret_;
};

void QuicServerWorkerTest::expectConnectionCreation(
    const folly::SocketAddress& addr,
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
      .WillOnce(Invoke([](ServerConnectionIdParams params) {
        EXPECT_EQ(params.processId, 1);
        EXPECT_EQ(params.workerId, 42);
      }));
  EXPECT_CALL(*transport, setTransportSettings(_));
  EXPECT_CALL(*transport, accept());
  EXPECT_CALL(*transport, setTransportStatsCallback(quicStats_));
}

void QuicServerWorkerTest::expectConnCreateRefused() {
  MockQuicTransport::Ptr transport = transport_;
  EXPECT_CALL(*factory_, _make(_, _, _, _)).WillOnce(Return(nullptr));
  EXPECT_CALL(*transport, setSupportedVersions(_)).Times(0);
  EXPECT_CALL(*transport, setOriginalPeerAddress(_)).Times(0);
  EXPECT_CALL(*transport, setRoutingCallback(worker_.get())).Times(0);
  EXPECT_CALL(*transport, setConnectionIdAlgo(_)).Times(0);
  EXPECT_CALL(*transport, setServerConnectionIdParams(_)).Times(0);
  EXPECT_CALL(*transport, setTransportSettings(_)).Times(0);
  EXPECT_CALL(*transport, accept()).Times(0);
  EXPECT_CALL(*transport, setTransportStatsCallback(quicStats_)).Times(0);
  EXPECT_CALL(*transport, onNetworkData(_, _)).Times(0);
}

void QuicServerWorkerTest::createQuicConnectionDuringShedding(
    const folly::SocketAddress& addr,
    ConnectionId connId) {
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  RoutingData routingData(HeaderForm::Long, true, false, connId, connId);

  auto data = createData(kMinInitialPacketSize + 10);
  expectConnCreateRefused();
  worker_->dispatchPacketData(
      addr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now()),
      version);

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_EQ(0, addrMap.count(std::make_pair(addr, connId)));
  eventbase_.loopIgnoreKeepAlive();
}

void QuicServerWorkerTest::createQuicConnection(
    const folly::SocketAddress& addr,
    ConnectionId connId,
    MockQuicTransport::Ptr transportOverride) {
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  RoutingData routingData(HeaderForm::Long, true, false, connId, connId);

  auto data = createData(kMinInitialPacketSize + 10);
  MockQuicTransport::Ptr transport = transport_;
  if (transportOverride) {
    transport = transportOverride;
  }
  expectConnectionCreation(addr, transport);
  EXPECT_CALL(*transport, onNetworkData(addr, NetworkDataMatches(*data)));
  worker_->dispatchPacketData(
      addr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now()),
      version);

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_EQ(addrMap.count(std::make_pair(addr, connId)), 1);
  eventbase_.loopIgnoreKeepAlive();
}

void QuicServerWorkerTest::testSendReset(
    Buf packet,
    ConnectionId,
    ShortHeader shortHeader,
    PacketDropReason dropReason) {
  EXPECT_CALL(*quicStats_, onPacketDropped(dropReason)).Times(1);
  // should write reset packet
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(1);
  EXPECT_CALL(*quicStats_, onPacketSent()).Times(1);
  EXPECT_CALL(*quicStats_, onStatelessReset()).Times(1);

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
        overridePacketWithToken(*buf, token);
        AckStates ackStates;
        auto packetQueue = bufToQueue(buf->clone());
        auto res = codec.parsePacket(packetQueue, ackStates);
        EXPECT_NE(res.statelessReset(), nullptr);
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
      NetworkData(packet->clone(), Clock::now()),
      folly::none);
  eventbase_.loopIgnoreKeepAlive();
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
      PacketDropReason::ROUTING_ERROR_WRONG_HOST);
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
      PacketDropReason::CANNOT_FORWARD_DATA);
}

TEST_F(QuicServerWorkerTest, RateLimit) {
  worker_->setRateLimiter(
      std::make_unique<SlidingWindowRateLimiter>([]() { return 2; }, 60s));
  EXPECT_CALL(*quicStats_, onConnectionRateLimited()).Times(1);

  NiceMock<MockConnectionSetupCallback> connSetupCb1;
  NiceMock<MockConnectionCallback> connCb1;
  auto mockSock1 =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&eventbase_);
  EXPECT_CALL(*mockSock1, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  MockQuicTransport::Ptr testTransport1 = std::make_shared<MockQuicTransport>(
      worker_->getEventBase(),
      std::move(mockSock1),
      &connSetupCb1,
      &connCb1,
      nullptr);
  EXPECT_CALL(*testTransport1, getEventBase())
      .WillRepeatedly(Return(&eventbase_));
  EXPECT_CALL(*testTransport1, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));
  auto connId1 = getTestConnectionId(hostId_);
  QuicVersion version = QuicVersion::MVFST;
  RoutingData routingData(HeaderForm::Long, true, false, connId1, connId1);

  auto data = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(
      *testTransport1, onNetworkData(kClientAddr, NetworkDataMatches(*data)));
  EXPECT_CALL(*factory_, _make(_, _, _, _)).WillOnce(Return(testTransport1));

  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now()),
      version);

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_EQ(addrMap.count(std::make_pair(kClientAddr, connId1)), 1);
  eventbase_.loopIgnoreKeepAlive();

  auto caddr2 = folly::SocketAddress("2.3.4.5", 1234);
  NiceMock<MockConnectionSetupCallback> connSetupCb2;
  NiceMock<MockConnectionCallback> connCb2;
  auto mockSock2 =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&eventbase_);
  EXPECT_CALL(*mockSock2, address()).WillRepeatedly(ReturnRef(caddr2));
  MockQuicTransport::Ptr testTransport2 = std::make_shared<MockQuicTransport>(
      worker_->getEventBase(),
      std::move(mockSock2),
      &connSetupCb2,
      &connCb2,
      nullptr);
  EXPECT_CALL(*testTransport2, getEventBase())
      .WillRepeatedly(Return(&eventbase_));
  EXPECT_CALL(*testTransport2, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(caddr2));
  ConnectionId connId2({2, 4, 5, 6, 7, 8, 9, 10});
  version = QuicVersion::MVFST;
  RoutingData routingData2(HeaderForm::Long, true, false, connId2, connId2);

  auto data2 = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(
      *testTransport2, onNetworkData(caddr2, NetworkDataMatches(*data2)));
  EXPECT_CALL(*factory_, _make(_, _, _, _)).WillOnce(Return(testTransport2));
  worker_->dispatchPacketData(
      caddr2,
      std::move(routingData2),
      NetworkData(data2->clone(), Clock::now()),
      version);

  EXPECT_EQ(addrMap.count(std::make_pair(caddr2, connId2)), 1);
  eventbase_.loopIgnoreKeepAlive();

  auto caddr3 = folly::SocketAddress("3.3.4.5", 1234);
  auto mockSock3 =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&eventbase_);
  ConnectionId connId3({8, 4, 5, 6, 7, 8, 9, 10});
  version = QuicVersion::MVFST;
  RoutingData routingData3(HeaderForm::Long, true, false, connId3, connId3);
  auto data3 = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(*factory_, _make(_, _, _, _)).Times(0);
  worker_->dispatchPacketData(
      caddr3,
      std::move(routingData3),
      NetworkData(data2->clone(), Clock::now()),
      version);

  EXPECT_EQ(addrMap.count(std::make_pair(caddr3, connId3)), 0);
  EXPECT_EQ(addrMap.size(), 2);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, UnfinishedHandshakeLimit) {
  worker_->setUnfinishedHandshakeLimit([]() { return 2; });
  EXPECT_CALL(*quicStats_, onConnectionRateLimited()).Times(1);

  NiceMock<MockConnectionSetupCallback> connSetupCb1;
  NiceMock<MockConnectionCallback> connCb1;
  auto mockSock1 =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&eventbase_);
  EXPECT_CALL(*mockSock1, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  MockQuicTransport::Ptr testTransport1 = std::make_shared<MockQuicTransport>(
      worker_->getEventBase(),
      std::move(mockSock1),
      &connSetupCb1,
      &connCb1,
      nullptr);
  EXPECT_CALL(*testTransport1, getEventBase())
      .WillRepeatedly(Return(&eventbase_));
  EXPECT_CALL(*testTransport1, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));
  auto connId1 = getTestConnectionId(hostId_);
  QuicVersion version = QuicVersion::MVFST;
  RoutingData routingData(HeaderForm::Long, true, false, connId1, connId1);

  auto data = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(
      *testTransport1, onNetworkData(kClientAddr, NetworkDataMatches(*data)));
  EXPECT_CALL(*factory_, _make(_, _, _, _)).WillOnce(Return(testTransport1));

  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now()),
      version);

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_EQ(addrMap.count(std::make_pair(kClientAddr, connId1)), 1);
  eventbase_.loopIgnoreKeepAlive();

  auto caddr2 = folly::SocketAddress("2.3.4.5", 1234);
  NiceMock<MockConnectionSetupCallback> connSetupCb2;
  NiceMock<MockConnectionCallback> connCb2;
  auto mockSock2 =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&eventbase_);
  EXPECT_CALL(*mockSock2, address()).WillRepeatedly(ReturnRef(caddr2));
  MockQuicTransport::Ptr testTransport2 = std::make_shared<MockQuicTransport>(
      worker_->getEventBase(),
      std::move(mockSock2),
      &connSetupCb2,
      &connCb2,
      nullptr);
  EXPECT_CALL(*testTransport2, getEventBase())
      .WillRepeatedly(Return(&eventbase_));
  EXPECT_CALL(*testTransport2, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(caddr2));
  ConnectionId connId2({2, 4, 5, 6, 7, 8, 9, 10});
  version = QuicVersion::MVFST;
  RoutingData routingData2(HeaderForm::Long, true, false, connId2, connId2);

  auto data2 = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(
      *testTransport2, onNetworkData(caddr2, NetworkDataMatches(*data2)));
  EXPECT_CALL(*factory_, _make(_, _, _, _)).WillOnce(Return(testTransport2));
  worker_->dispatchPacketData(
      caddr2,
      std::move(routingData2),
      NetworkData(data2->clone(), Clock::now()),
      version);

  EXPECT_EQ(addrMap.count(std::make_pair(caddr2, connId2)), 1);
  eventbase_.loopIgnoreKeepAlive();

  auto caddr3 = folly::SocketAddress("3.3.4.5", 1234);
  auto mockSock3 =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&eventbase_);
  ConnectionId connId3({3, 4, 5, 6, 7, 8, 9, 10});
  version = QuicVersion::MVFST;
  RoutingData routingData3(HeaderForm::Long, true, false, connId3, connId3);
  auto data3 = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(*factory_, _make(_, _, _, _)).Times(0);
  worker_->dispatchPacketData(
      caddr3,
      std::move(routingData3),
      NetworkData(data3->clone(), Clock::now()),
      version);

  EXPECT_EQ(addrMap.count(std::make_pair(caddr3, connId3)), 0);
  EXPECT_EQ(addrMap.size(), 2);
  eventbase_.loopIgnoreKeepAlive();

  // Finish a handshake.
  worker_->onHandshakeFinished();
  auto caddr4 = folly::SocketAddress("4.3.4.5", 1234);
  NiceMock<MockConnectionSetupCallback> connSetupCb4;
  NiceMock<MockConnectionCallback> connCb4;
  auto mockSock4 =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&eventbase_);
  EXPECT_CALL(*mockSock4, address()).WillRepeatedly(ReturnRef(caddr4));
  MockQuicTransport::Ptr testTransport4 = std::make_shared<MockQuicTransport>(
      worker_->getEventBase(),
      std::move(mockSock4),
      &connSetupCb4,
      &connCb4,
      nullptr);
  EXPECT_CALL(*testTransport4, getEventBase())
      .WillRepeatedly(Return(&eventbase_));
  EXPECT_CALL(*testTransport4, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(caddr4));
  ConnectionId connId4({4, 4, 5, 6, 7, 8, 9, 10});
  version = QuicVersion::MVFST;
  RoutingData routingData4(HeaderForm::Long, true, false, connId4, connId4);

  auto data4 = createData(kMinInitialPacketSize + 10);
  EXPECT_CALL(
      *testTransport4, onNetworkData(caddr4, NetworkDataMatches(*data4)));
  EXPECT_CALL(*factory_, _make(_, _, _, _)).WillOnce(Return(testTransport4));
  worker_->dispatchPacketData(
      caddr4,
      std::move(routingData4),
      NetworkData(data4->clone(), Clock::now()),
      version);

  EXPECT_EQ(addrMap.count(std::make_pair(caddr4, connId4)), 1);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, QuicServerWorkerUnbindBeforeCidAvailable) {
  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  auto mockSock =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&eventbase_);
  EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  MockQuicTransport::Ptr testTransport = std::make_shared<MockQuicTransport>(
      worker_->getEventBase(),
      std::move(mockSock),
      &connSetupCb,
      &connCb,
      nullptr);
  EXPECT_CALL(*testTransport, getEventBase())
      .WillRepeatedly(Return(&eventbase_));

  EXPECT_CALL(*testTransport, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId, testTransport);

  // Otherwise the mock of _make will hold on to a shared_ptr to the transport
  Mock::VerifyAndClearExpectations(factory_.get());

  auto& srcAddrMap = worker_->getSrcToTransportMap();
  EXPECT_EQ(1, srcAddrMap.size());
  EXPECT_EQ(srcAddrMap.begin()->second.get(), testTransport.get());
  auto& srcIdentity = srcAddrMap.begin()->first;
  auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_EQ(0, connIdMap.size());

  auto* rawTransport = testTransport.get();
  // This is fine, server worker still has at one shared_ptr in its map.
  testTransport.reset();

  EXPECT_CALL(*rawTransport, setRoutingCallback(nullptr)).Times(1);
  // Now remove it from the maps. Nothing should crash.
  auto cidDataOnHeap = std::make_shared<std::vector<ConnectionIdData>>();
  const auto& cidRef = *cidDataOnHeap;
  EXPECT_CALL(*rawTransport, customDestructor())
      .Times(1)
      .WillOnce(
          Invoke([cid = std::move(cidDataOnHeap)]() mutable { cid.reset(); }));
  worker_->onConnectionUnbound(rawTransport, srcIdentity, cidRef);
  EXPECT_EQ(0, srcAddrMap.size());
}

TEST_F(QuicServerWorkerTest, QuicServerMultipleConnIdsRouting) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  auto data = folly::IOBuf::copyBuffer("data");
  PacketNum num = 2;
  ShortHeader shortHeaderConnId(ProtectionType::KeyPhaseZero, connId, num);

  EXPECT_CALL(*quicStats_, onNewConnection());
  transport_->QuicServerTransport::setRoutingCallback(worker_.get());
  worker_.get()->onConnectionIdAvailable(transport_, connId);
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_EQ(connIdMap.count(connId), 1);

  EXPECT_CALL(*transport_, getClientChosenDestConnectionId())
      .WillRepeatedly(Return(connId));
  worker_->onConnectionIdBound(transport_);
  EXPECT_TRUE(worker_->isScheduled());
  worker_->cancelTimeout();

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_EQ(addrMap.count(std::make_pair(kClientAddr, connId)), 0);

  // routing by connid after connid available.
  EXPECT_CALL(
      *transport_, onNetworkData(kClientAddr, NetworkDataMatches(*data)))
      .Times(1);
  RoutingData routingData2(
      HeaderForm::Short, false, false, connId, folly::none);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData2),
      NetworkData(data->clone(), Clock::now()),
      folly::none);
  eventbase_.loopIgnoreKeepAlive();

  auto connId2 = connId;
  connId2.data()[7] ^= 0x1;
  worker_.get()->onConnectionIdAvailable(transport_, connId2);

  EXPECT_EQ(connIdMap.size(), 2);

  EXPECT_CALL(
      *transport_, onNetworkData(kClientAddr, NetworkDataMatches(*data)))
      .Times(1);
  RoutingData routingData3(
      HeaderForm::Short, false, false, connId2, folly::none);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData3),
      NetworkData(data->clone(), Clock::now()),
      folly::none);
  eventbase_.loopIgnoreKeepAlive();

  EXPECT_CALL(*transport_, setRoutingCallback(nullptr));
  worker_->onConnectionUnbound(
      transport_.get(),
      std::make_pair(kClientAddr, connId),
      std::vector<ConnectionIdData>{
          ConnectionIdData{connId, 0}, ConnectionIdData{connId2, 1}});
  EXPECT_EQ(connIdMap.count(connId), 0);
  EXPECT_EQ(addrMap.count(std::make_pair(kClientAddr, connId)), 0);

  // transport_ dtor is run at the end of the test, which causes
  // onConnectionUnbound to be called if the routingCallback_ is
  // still set.
  transport_->QuicServerTransport::setRoutingCallback(nullptr);
}

TEST_F(QuicServerWorkerTest, RetireConnIds) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  const auto& connIdMap = worker_->getConnectionIdMap();
  const auto& addrMap = worker_->getSrcToTransportMap();

  EXPECT_CALL(*quicStats_, onNewConnection());
  transport_->QuicServerTransport::setRoutingCallback(worker_.get());
  worker_->onConnectionIdAvailable(transport_, connId);
  EXPECT_EQ(connIdMap.count(connId), 1);

  EXPECT_CALL(*transport_, getClientChosenDestConnectionId())
      .WillRepeatedly(Return(connId));
  worker_->onConnectionIdBound(transport_);
  EXPECT_TRUE(worker_->isScheduled());
  worker_->cancelTimeout();

  EXPECT_EQ(addrMap.count(std::make_pair(kClientAddr, connId)), 0);

  // create two additional conn ids
  auto connId2 = connId;
  connId2.data()[7] ^= 0x1;
  worker_->onConnectionIdAvailable(transport_, connId2);

  auto connId3 = connId;
  connId3.data()[7] ^= 0x2;
  worker_->onConnectionIdAvailable(transport_, connId3);
  eventbase_.loopIgnoreKeepAlive();

  EXPECT_EQ(connIdMap.size(), 3);

  // retiring invalid conn id should not change map size
  auto invalidConnId = connId;
  invalidConnId.data()[0] ^= 0x1;
  worker_->onConnectionIdRetired(*transport_, invalidConnId);
  EXPECT_EQ(connIdMap.size(), 3);

  // retiring valid conn ids should decrease map size by one each time
  worker_->onConnectionIdRetired(*transport_, connId2);
  EXPECT_EQ(connIdMap.size(), 2);

  worker_->onConnectionIdRetired(*transport_, connId3);
  EXPECT_EQ(connIdMap.size(), 1);

  EXPECT_CALL(*transport_, setRoutingCallback(nullptr));
  worker_->onConnectionUnbound(
      transport_.get(),
      std::make_pair(kClientAddr, connId),
      std::vector<ConnectionIdData>{ConnectionIdData{connId, 0}});
  EXPECT_EQ(connIdMap.count(connId), 0);
  EXPECT_EQ(addrMap.count(std::make_pair(kClientAddr, connId)), 0);
  // transport_ dtor is run at the end of the test, which causes
  // onConnectionUnbound to be called if the routingCallback_ is
  // still set.
  transport_->QuicServerTransport::setRoutingCallback(nullptr);
}

TEST_F(QuicServerWorkerTest, QuicServerNewConnection) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto connId = getTestConnectionId(hostId_);
  LOG(ERROR) << "from test CID: " << int(connId.size());
  createQuicConnection(kClientAddr, connId);

  auto data = folly::IOBuf::copyBuffer("data");
  PacketNum num = 2;
  ShortHeader shortHeaderConnId(
      ProtectionType::KeyPhaseZero, getTestConnectionId(hostId_), num);

  // Routing by connid before conn id available on a short packet.
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);

  RoutingData routingData(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId.getConnectionId(),
      folly::none);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now()),
      folly::none);
  eventbase_.loopIgnoreKeepAlive();

  EXPECT_CALL(*quicStats_, onNewConnection());
  ConnectionId newConnId = getTestConnectionId(hostId_);

  transport_->QuicServerTransport::setRoutingCallback(worker_.get());
  worker_.get()->onConnectionIdAvailable(transport_, newConnId);
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_EQ(connIdMap.count(getTestConnectionId(hostId_)), 1);

  EXPECT_CALL(*transport_, getClientChosenDestConnectionId())
      .WillRepeatedly(Return(connId));
  worker_->onConnectionIdBound(transport_);
  EXPECT_TRUE(worker_->isScheduled());
  worker_->cancelTimeout();

  const auto& addrMap = worker_->getSrcToTransportMap();
  EXPECT_EQ(
      addrMap.count(std::make_pair(kClientAddr, getTestConnectionId(hostId_))),
      0);

  // routing by connid after connid available.
  EXPECT_CALL(
      *transport_, onNetworkData(kClientAddr, NetworkDataMatches(*data)));
  RoutingData routingData2(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId.getConnectionId(),
      folly::none);
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData2),
      NetworkData(data->clone(), Clock::now()),
      folly::none);
  eventbase_.loopIgnoreKeepAlive();

  // routing by address after transport_'s connid available, but before
  // transport2's connid available.
  ConnectionId connId2({2, 4, 5, 6, 7, 8, 9, 10});
  folly::SocketAddress clientAddr2("2.3.4.5", 2345);
  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  auto mockSock =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&eventbase_);

  EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  MockQuicTransport::Ptr transport2 = std::make_shared<MockQuicTransport>(
      worker_->getEventBase(),
      std::move(mockSock),
      &connSetupCb,
      &connCb,
      nullptr);
  EXPECT_CALL(*transport2, getEventBase()).WillRepeatedly(Return(&eventbase_));
  EXPECT_CALL(*transport2, getOriginalPeerAddress())
      .WillRepeatedly(ReturnRef(kClientAddr));
  createQuicConnection(clientAddr2, connId2, transport2);

  ShortHeader shortHeaderConnId2(ProtectionType::KeyPhaseZero, connId2, num);

  // Will be dropped
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);
  RoutingData routingData3(
      HeaderForm::Short,
      false,
      false,
      shortHeaderConnId2.getConnectionId(),
      folly::none);
  worker_->dispatchPacketData(
      clientAddr2,
      std::move(routingData3),
      NetworkData(data->clone(), Clock::now()),
      folly::none);
  eventbase_.loopIgnoreKeepAlive();

  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(2);
  worker_->onConnectionUnbound(
      transport_.get(),
      std::make_pair(kClientAddr, getTestConnectionId(hostId_)),
      std::vector<ConnectionIdData>{ConnectionIdData{connId, 0}});
  worker_->onConnectionUnbound(
      transport_.get(),
      std::make_pair(clientAddr2, connId2),
      std::vector<ConnectionIdData>{ConnectionIdData{connId2, 0}});
  EXPECT_EQ(connIdMap.count(getTestConnectionId(hostId_)), 0);
  EXPECT_EQ(
      addrMap.count(std::make_pair(kClientAddr, getTestConnectionId(hostId_))),
      0);

  // transport_ dtor is run at the end of the test, which causes
  // onConnectionUnbound to be called if the routingCallback_ is
  // still set.
  transport_->QuicServerTransport::setRoutingCallback(nullptr);
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
  EXPECT_CALL(*quicStats_, onPacketDropped(_));
  RoutingData routingData(
      HeaderForm::Long,
      true,
      false,
      header.getDestinationConnId(),
      header.getSourceConnId());
  worker_->dispatchPacketData(
      kClientAddr,
      std::move(routingData),
      NetworkData(data->clone(), Clock::now()),
      version);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, QuicShedTest) {
  auto connId = getTestConnectionId(hostId_);
  EXPECT_CALL(
      *quicStats_,
      onPacketDropped(
          PacketDropReason(PacketDropReason::CANNOT_MAKE_TRANSPORT)));
  folly::Optional<VersionNegotiationPacket> versionPacket;
  EXPECT_CALL(*socketPtr_, write(_, _))
      .WillOnce(Invoke([&](const SocketAddress&,
                           const std::unique_ptr<folly::IOBuf>& writtenData) {
        auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
        auto packetQueue = bufToQueue(writtenData->clone());
        versionPacket = codec->tryParsingVersionNegotiation(packetQueue);
        return packetQueue.chainLength();
      }));

  createQuicConnectionDuringShedding(kClientAddr, connId);
  EXPECT_TRUE(versionPacket.has_value());
  EXPECT_EQ(versionPacket->destinationConnectionId, connId);
}

TEST_F(QuicServerWorkerTest, BlockedSourcePort) {
  folly::SocketAddress blockedSrcPort("1.2.3.4", 443);
  worker_->setIsBlockListedSrcPort([](uint16_t port) { return port == 443; });
  auto data = createData(kDefaultUDPSendPacketLen);
  auto connId = ConnectionId(std::vector<uint8_t>());
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  EXPECT_CALL(
      *quicStats_,
      onPacketDropped(PacketDropReason(PacketDropReason::INVALID_SRC_PORT)));

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  while (builder.remainingSpaceInPkt() > 0) {
    writeFrame(PaddingFrame(), builder);
  }
  auto packet = packetToBuf(std::move(builder).buildPacket());
  worker_->handleNetworkData(blockedSrcPort, std::move(packet), Clock::now());
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ZeroLengthConnectionId) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto connId = ConnectionId(std::vector<uint8_t>());
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  while (builder.remainingSpaceInPkt() > 0) {
    writeFrame(PaddingFrame(), builder);
  }
  auto packet = packetToBuf(std::move(builder).buildPacket());
  worker_->handleNetworkData(kClientAddr, std::move(packet), Clock::now());
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ClientInitialCounting) {
  auto srcConnId = getTestConnectionId(0);
  auto destConnId = getTestConnectionId(1);
  QuicVersion version = QuicVersion::MVFST;
  PacketNum num = 1;
  LongHeader initialHeader(
      LongHeader::Types::Initial, srcConnId, destConnId, num, version);
  RegularQuicPacketBuilder initialBuilder(
      kDefaultUDPSendPacketLen, std::move(initialHeader), 0);
  initialBuilder.encodePacketHeader();
  auto initialPacket = packetToBuf(std::move(initialBuilder).buildPacket());
  EXPECT_CALL(*quicStats_, onClientInitialReceived(QuicVersion::MVFST))
      .Times(1);
  worker_->handleNetworkData(
      kClientAddr, std::move(initialPacket), Clock::now());
  eventbase_.loopIgnoreKeepAlive();

  // Initial with any packet number should also increate the counting
  PacketNum bignum = 200;
  LongHeader initialHeaderBigNum(
      LongHeader::Types::Initial, srcConnId, destConnId, bignum, version);
  RegularQuicPacketBuilder initialBuilderBigNum(
      kDefaultUDPSendPacketLen, std::move(initialHeaderBigNum), 0);
  initialBuilderBigNum.encodePacketHeader();
  auto initialPacketBigNum =
      packetToBuf(std::move(initialBuilderBigNum).buildPacket());
  EXPECT_CALL(*quicStats_, onClientInitialReceived(QuicVersion::MVFST))
      .Times(1);
  worker_->handleNetworkData(
      kClientAddr, std::move(initialPacketBigNum), Clock::now());
  eventbase_.loopIgnoreKeepAlive();

  LongHeader handshakeHeader(
      LongHeader::Types::Handshake, srcConnId, destConnId, num, version);
  RegularQuicPacketBuilder handshakeBuilder(
      kDefaultUDPSendPacketLen, std::move(handshakeHeader), 0);
  handshakeBuilder.encodePacketHeader();
  auto handshakePacket = packetToBuf(std::move(handshakeBuilder).buildPacket());
  EXPECT_CALL(*quicStats_, onClientInitialReceived(_)).Times(0);
  worker_->handleNetworkData(
      kClientAddr, std::move(handshakePacket), Clock::now());
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ConnectionIdTooShort) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto connId = ConnectionId::createWithoutChecks({1});
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(LongHeader::Types::Initial, connId, connId, num, version);
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);
  EXPECT_CALL(*quicStats_, onPacketProcessed()).Times(0);
  EXPECT_CALL(*quicStats_, onPacketSent()).Times(0);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  while (builder.remainingSpaceInPkt() > 0) {
    writeFrame(PaddingFrame(), builder);
  }
  auto packet = packetToBuf(std::move(builder).buildPacket());
  worker_->handleNetworkData(kClientAddr, std::move(packet), Clock::now());
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, FailToParseConnectionId) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto srcConnId = getTestConnectionId(0);
  auto dstConnId = getTestConnectionId(1);
  auto mockConnIdAlgo = std::make_unique<MockConnectionIdAlgo>();
  auto rawConnIdAlgo = mockConnIdAlgo.get();
  worker_->setConnectionIdAlgo(std::move(mockConnIdAlgo));

  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial, srcConnId, dstConnId, num, version);
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  while (builder.remainingSpaceInPkt() > 0) {
    writeFrame(PaddingFrame(), builder);
  }
  auto packet = packetToBuf(std::move(builder).buildPacket());
  // To force dropping path, set initial to false
  RoutingData routingData(
      HeaderForm::Long, false /* isInitial */, false, dstConnId, srcConnId);
  NetworkData networkData(std::move(packet), Clock::now());

  EXPECT_CALL(*rawConnIdAlgo, canParseNonConst(_)).WillOnce(Return(true));
  EXPECT_CALL(*rawConnIdAlgo, parseConnectionId(dstConnId))
      .WillOnce(Return(folly::makeUnexpected(QuicInternalException(
          "This CID has COVID-19", LocalErrorCode::INTERNAL_ERROR))));
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);
  EXPECT_CALL(*quicStats_, onPacketProcessed()).Times(0);
  EXPECT_CALL(*quicStats_, onPacketSent()).Times(0);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);
  worker_->dispatchPacketData(
      kClientAddr, std::move(routingData), std::move(networkData), version);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ConnectionIdTooShortDispatch) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto dstConnId = ConnectionId::createWithoutChecks({3});
  auto srcConnId = ConnectionId::createWithoutChecks({3});
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial, srcConnId, dstConnId, num, version);
  EXPECT_CALL(*factory_, _make(_, _, _, _)).Times(0);
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);
  EXPECT_CALL(*quicStats_, onPacketProcessed()).Times(0);
  EXPECT_CALL(*quicStats_, onPacketSent()).Times(0);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  while (builder.remainingSpaceInPkt() > 0) {
    writeFrame(PaddingFrame(), builder);
  }
  auto packet = packetToBuf(std::move(builder).buildPacket());
  RoutingData routingData(HeaderForm::Long, true, false, dstConnId, srcConnId);
  NetworkData networkData(std::move(packet), Clock::now());
  worker_->dispatchPacketData(
      kClientAddr, std::move(routingData), std::move(networkData), version);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ConnectionIdTooLargeDispatch) {
  auto data = createData(kDefaultUDPSendPacketLen);
  auto dstConnId = ConnectionId::createWithoutChecks({21});
  auto srcConnId = ConnectionId::createWithoutChecks({3});
  PacketNum num = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial, srcConnId, dstConnId, num, version);
  EXPECT_CALL(*factory_, _make(_, _, _, _)).Times(0);
  EXPECT_CALL(*quicStats_, onPacketDropped(_)).Times(1);
  EXPECT_CALL(*quicStats_, onPacketProcessed()).Times(0);
  EXPECT_CALL(*quicStats_, onPacketSent()).Times(0);
  EXPECT_CALL(*quicStats_, onWrite(_)).Times(0);

  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  while (builder.remainingSpaceInPkt() > 0) {
    writeFrame(PaddingFrame(), builder);
  }
  auto packet = packetToBuf(std::move(builder).buildPacket());
  RoutingData routingData(HeaderForm::Long, true, false, dstConnId, srcConnId);
  NetworkData networkData(std::move(packet), Clock::now());
  worker_->dispatchPacketData(
      kClientAddr, std::move(routingData), std::move(networkData), version);
  eventbase_.loopIgnoreKeepAlive();
}

TEST_F(QuicServerWorkerTest, ShutdownQuicServer) {
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  EXPECT_CALL(*quicStats_, onNewConnection());
  worker_->onConnectionIdAvailable(transport_, getTestConnectionId(hostId_));
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_EQ(connIdMap.count(getTestConnectionId(hostId_)), 1);

  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(2);
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr)).Times(2);
  EXPECT_CALL(*transport_, close(_)).WillRepeatedly(Invoke([this](auto) {
    hasShutdown_ = true;
  }));
  std::thread t([&] { eventbase_.loopForever(); });
  eventbase_.runInEventBaseThreadAndWait([&] { worker_.reset(); });
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
      kDefaultUDPSendPacketLen, std::move(header), 0 /* largestAcked */);
  builder.encodePacketHeader();
  auto packet = packetToBuf(std::move(builder).buildPacket());
  worker_->handleNetworkData(kClientAddr, std::move(packet), Clock::now());
  eventbase_.terminateLoopSoon();
  t.join();
}

TEST_F(QuicServerWorkerTest, DestroyQuicServer) {
  auto connId = getTestConnectionId(hostId_);
  createQuicConnection(kClientAddr, connId);

  EXPECT_CALL(*quicStats_, onNewConnection());
  worker_->onConnectionIdAvailable(transport_, getTestConnectionId(hostId_));
  const auto& connIdMap = worker_->getConnectionIdMap();
  EXPECT_EQ(connIdMap.count(getTestConnectionId(hostId_)), 1);

  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(2);
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr)).Times(2);
  EXPECT_CALL(*transport_, setHandshakeFinishedCallback(nullptr)).Times(2);
  EXPECT_CALL(*transport_, close(_)).WillRepeatedly(Invoke([this](auto) {
    hasShutdown_ = true;
  }));
  std::thread t([&] { eventbase_.loopForever(); });
  eventbase_.runInEventBaseThreadAndWait([&] { worker_.reset(); });
  eventbase_.terminateLoopSoon();
  t.join();
}

TEST_F(QuicServerWorkerTest, AssignBufAccessor) {
  EXPECT_CALL(*socketPtr_, address()).WillRepeatedly(ReturnRef(fakeAddress_));
  auto connId = getTestConnectionId(hostId_);
  TransportSettings transportSettings;
  transportSettings.dataPathType = DataPathType::ContinuousMemory;
  transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_GSO;
  worker_->setTransportSettings(transportSettings);
  EXPECT_CALL(*transport_, setBufAccessor(_))
      .Times(1)
      .WillOnce(Invoke(
          [](BufAccessor* accessor) { EXPECT_TRUE(accessor != nullptr); }));
  createQuicConnection(kClientAddr, connId);

  // From shutdownAllConnections:
  EXPECT_CALL(*transport_, setRoutingCallback(nullptr)).Times(1);
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr)).Times(1);
}

class MockAcceptObserver : public AcceptObserver {
 public:
  MOCK_METHOD(void, accept, (QuicTransportBase* const), (noexcept));
  MOCK_METHOD(void, acceptorDestroy, (QuicServerWorker*), (noexcept));
  MOCK_METHOD(void, observerAttach, (QuicServerWorker*), (noexcept));
  MOCK_METHOD(void, observerDetach, (QuicServerWorker*), (noexcept));
};

TEST_F(QuicServerWorkerTest, AcceptObserver) {
  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb.get());

  auto initTestSocketAndTransport = [this]() {
    NiceMock<MockConnectionSetupCallback> connSetupCb;
    NiceMock<MockConnectionCallback> connCb;
    auto mockSock = std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(
        &eventbase_);
    EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(fakeAddress_));
    MockQuicTransport::Ptr mockTransport = std::make_shared<MockQuicTransport>(
        worker_->getEventBase(),
        std::move(mockSock),
        &connSetupCb,
        &connCb,
        nullptr);
    EXPECT_CALL(*mockTransport, setRoutingCallback(nullptr));
    EXPECT_CALL(*mockTransport, setTransportStatsCallback(nullptr));
    EXPECT_CALL(*mockTransport, getEventBase())
        .WillRepeatedly(Return(&eventbase_));
    EXPECT_CALL(*mockTransport, getOriginalPeerAddress())
        .WillRepeatedly(ReturnRef(kClientAddr));
    return std::make_pair(std::move(mockSock), std::move(mockTransport));
  };

  // add first connection, expect events
  const auto [sock1, transport1] = initTestSocketAndTransport();
  EXPECT_CALL(*cb, accept(transport1.get()));
  createQuicConnection(kClientAddr, getTestConnectionId(hostId_), transport1);
  Mock::VerifyAndClearExpectations(cb.get());

  // add second connection, expect events
  const auto [sock2, transport2] = initTestSocketAndTransport();
  EXPECT_CALL(*cb, accept(transport2.get()));
  createQuicConnection(kClientAddr2, getTestConnectionId(hostId_), transport2);
  Mock::VerifyAndClearExpectations(cb.get());

  // remove AcceptObserver
  EXPECT_CALL(*cb, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());

  // add third connection, no events
  const auto [sock3, transport3] = initTestSocketAndTransport();
  createQuicConnection(kClientAddr3, getTestConnectionId(hostId_), transport3);
}

TEST_F(QuicServerWorkerTest, AcceptObserverRemove) {
  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb.get());
  Mock::VerifyAndClearExpectations(cb.get());

  EXPECT_CALL(*cb, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_F(QuicServerWorkerTest, AcceptObserverRemoveMissing) {
  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_FALSE(worker_->removeAcceptObserver(cb.get()));
}

TEST_F(QuicServerWorkerTest, AcceptObserverDestroyWorker) {
  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb.get());
  Mock::VerifyAndClearExpectations(cb.get());

  // destroy the acceptor while the AcceptObserver is installed
  EXPECT_CALL(*cb, acceptorDestroy(worker_.get()));
  worker_ = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_F(QuicServerWorkerTest, AcceptObserverMultipleRemove) {
  auto cb1 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb1, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb1.get());
  Mock::VerifyAndClearExpectations(cb1.get());

  auto cb2 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb2, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb2.get());
  Mock::VerifyAndClearExpectations(cb2.get());

  EXPECT_CALL(*cb1, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb1.get()));
  Mock::VerifyAndClearExpectations(cb1.get());

  EXPECT_CALL(*cb2, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb2.get()));
  Mock::VerifyAndClearExpectations(cb2.get());
}

TEST_F(QuicServerWorkerTest, AcceptObserverMultipleRemoveReverse) {
  auto cb1 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb1, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb1.get());
  Mock::VerifyAndClearExpectations(cb1.get());

  auto cb2 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb2, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb2.get());
  Mock::VerifyAndClearExpectations(cb2.get());

  EXPECT_CALL(*cb2, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb2.get()));
  Mock::VerifyAndClearExpectations(cb2.get());

  EXPECT_CALL(*cb1, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb1.get()));
  Mock::VerifyAndClearExpectations(cb1.get());
}

TEST_F(QuicServerWorkerTest, AcceptObserverMultipleAcceptorDestroyed) {
  auto cb1 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb1, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb1.get());
  Mock::VerifyAndClearExpectations(cb1.get());

  auto cb2 = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb2, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb2.get());
  Mock::VerifyAndClearExpectations(cb2.get());

  // destroy the acceptor while the AcceptObserver is installed
  EXPECT_CALL(*cb1, acceptorDestroy(worker_.get()));
  EXPECT_CALL(*cb2, acceptorDestroy(worker_.get()));
  worker_ = nullptr;
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
}

TEST_F(QuicServerWorkerTest, AcceptObserverRemoveCallbackThenDestroyWorker) {
  auto cb = std::make_unique<StrictMock<MockAcceptObserver>>();
  EXPECT_CALL(*cb, observerAttach(worker_.get()));
  worker_->addAcceptObserver(cb.get());
  Mock::VerifyAndClearExpectations(cb.get());

  EXPECT_CALL(*cb, observerDetach(worker_.get()));
  EXPECT_TRUE(worker_->removeAcceptObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());

  worker_ = nullptr;
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
      std::string("this is a retry token :)"));
  RegularQuicPacketBuilder builder(
      kDefaultUDPSendPacketLen,
      pktHeaderType == LongHeader::Types::Retry ? std::move(headerRetry)
                                                : std::move(header),
      0 /* largestAcked */);
  builder.encodePacketHeader();
  auto streamData = data.clone();
  auto dataLen = writeStreamFrameHeader(
      builder,
      streamId,
      0,
      streamData->computeChainDataLength(),
      streamData->computeChainDataLength(),
      true,
      folly::none /* skipLenHint */);
  EXPECT_TRUE(dataLen);
  writeStreamFrameData(builder, std::move(streamData), *dataLen);
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
  auto buf = pktHeaderType == LongHeader::Types::Initial
      ? createData(kMinInitialPacketSize)
      : folly::IOBuf::copyBuffer("hello, world!");
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
  return *connIdAlgo->encodeConnectionId(params);
}

class QuicServerWorkerRetryTest : public QuicServerWorkerTest {
 public:
  // Helper method to send a client initial that may contain the retry token to
  // the server in response to the retry packet
  void testSendInitial(
      ConnectionId& clientSrcConnId,
      ConnectionId& dstConnId,
      const folly::SocketAddress& clientAddr,
      const std::string& retryToken = "") {
    QuicVersion version = QuicVersion::MVFST;
    PacketNum num = 1;
    LongHeader initialHeader(
        LongHeader::Types::Initial,
        clientSrcConnId,
        dstConnId,
        num,
        version,
        retryToken);

    RegularQuicPacketBuilder initialBuilder(
        kDefaultUDPSendPacketLen, std::move(initialHeader), 0);
    initialBuilder.encodePacketHeader();
    while (initialBuilder.remainingSpaceInPkt() > 0) {
      writeFrame(PaddingFrame(), initialBuilder);
    }
    auto initialPacket = packetToBuf(std::move(initialBuilder).buildPacket());
    RoutingData routingData(
        HeaderForm::Long, true, false, dstConnId, clientSrcConnId);
    worker_->dispatchPacketData(
        clientAddr,
        std::move(routingData),
        NetworkData(initialPacket->clone(), Clock::now()),
        version);
    eventbase_.loopIgnoreKeepAlive();
  }

  /**
   * Helper method that expects a socketPtr_->write() contains a retry packet,
   * and retrieves the token value from its header. Sets the retry token value
   * to the encryptedRetryToken parameter.
   */
  void expectServerRetryPacketWrite(std::string& encryptedRetryToken) {
    EXPECT_CALL(*quicStats_, onConnectionRateLimited()).Times(1);
    EXPECT_CALL(*quicStats_, onWrite(_)).Times(1);
    EXPECT_CALL(*quicStats_, onPacketSent()).Times(1);

    EXPECT_CALL(*socketPtr_, write(_, _))
        .WillOnce(Invoke([&](const folly::SocketAddress& clientAddr,
                             const std::unique_ptr<folly::IOBuf>& buf) {
          // Validate that the retry packet has been created
          QuicReadCodec codec(QuicNodeType::Client);
          auto packetQueue = bufToQueue(buf->clone());
          AckStates ackStates;

          auto parsedPacket = codec.parsePacket(packetQueue, ackStates);
          auto* retryPacket = parsedPacket.retryPacket();
          CHECK(retryPacket);

          const ConnectionId& serverChosenRetrySrcConnId =
              retryPacket->header.getSourceConnId();

          // Validate the generated retry token
          EXPECT_TRUE(retryPacket->header.hasToken());
          encryptedRetryToken = retryPacket->header.getToken();
          auto tokenBuf = folly::IOBuf::copyBuffer(encryptedRetryToken);

          TokenGenerator generator(tokenSecret_);
          RetryToken token(
              serverChosenRetrySrcConnId, clientAddr.getIPAddress(), 0);

          auto maybeDecryptedTokenMs = generator.decryptToken(
              std::move(tokenBuf), token.genAeadAssocData());

          CHECK(maybeDecryptedTokenMs > 0);

          return buf->computeChainDataLength();
        }));
  }

  void enableRateLimiterForRetry() {
    // Retry packet will only be sent if rate-limiting is configured
    worker_->setRateLimiter(
        std::make_unique<SlidingWindowRateLimiter>([]() { return 0; }, 60s));
  }

  void enableUnfinishedHandshakeLimitForRetry() {
    worker_->setUnfinishedHandshakeLimit([]() { return 0; });
  }
};

// Validate that when the worker receives a valid NewToken, it invokes
// transportInfo->onNewTokenReceived().
TEST_F(QuicServerWorkerRetryTest, TestNewTokenStatsCallback) {
  EXPECT_CALL(*quicStats_, onNewTokenReceived());

  NewToken newToken(kClientAddr.getIPAddress());
  // Create the encrypted retry token
  TokenGenerator generator(tokenSecret_);
  auto encryptedToken = generator.encryptToken(newToken);

  CHECK(encryptedToken.has_value());
  std::string encryptedTokenStr =
      encryptedToken.value()->moveToFbString().toStdString();

  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  testSendInitial(srcConnId, dstConnId, kClientAddr, encryptedTokenStr);
}

TEST_F(QuicServerWorkerRetryTest, TestRetryValidInitial) {
  // The second client initial packet with the retry token is valid
  // as the client IP is the same as the one stored in the retry token
  enableRateLimiterForRetry();
  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);
  expectConnectionCreation(kClientAddr, transport_);
  EXPECT_CALL(*transport_, setRoutingCallback(nullptr));
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr));

  // send initial to extract the retry token sent by the server
  std::string retryToken{""};
  expectServerRetryPacketWrite(retryToken);
  testSendInitial(srcConnId, dstConnId, kClientAddr);

  // test that the retry token extracted is accepted by the server
  testSendInitial(srcConnId, dstConnId, kClientAddr, retryToken);
}

TEST_F(QuicServerWorkerRetryTest, TestRetryUnfinishedValidInitial) {
  // The second client initial packet with the retry token is valid
  // as the client IP is the same as the one stored in the retry token
  enableUnfinishedHandshakeLimitForRetry();
  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);
  expectConnectionCreation(kClientAddr, transport_);
  EXPECT_CALL(*transport_, setRoutingCallback(nullptr));
  EXPECT_CALL(*transport_, setTransportStatsCallback(nullptr));

  // send initial to extract the retry token sent by the server
  std::string retryToken{""};
  expectServerRetryPacketWrite(retryToken);
  testSendInitial(srcConnId, dstConnId, kClientAddr);

  // test that the retry token extracted is accepted by the server
  testSendInitial(srcConnId, dstConnId, kClientAddr, retryToken);
}

TEST_F(QuicServerWorkerRetryTest, TestRetryInvalidInitialClientIp) {
  // The second client initial packet with the retry token is invalid
  // as the client IP is different from the one stored in the retry token
  enableRateLimiterForRetry();
  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  // send initial to extract the retry token sent by the server
  std::string retryToken{""};
  expectServerRetryPacketWrite(retryToken);
  testSendInitial(srcConnId, dstConnId, kClientAddr);

  // send another client initial with the retry token rx'd above but with a
  // different client addr to verify it's invalid (i.e. will send another retry
  // packet)
  EXPECT_CALL(*quicStats_, onTokenDecryptFailure()).Times(1);
  expectServerRetryPacketWrite(retryToken);
  testSendInitial(srcConnId, dstConnId, kClientAddr2, retryToken);
}

TEST_F(QuicServerWorkerRetryTest, TestRetryUnfinishedInvalidInitialClientIp) {
  // The second client initial packet with the retry token is invalid
  // as the client IP is different from the one stored in the retry token
  enableUnfinishedHandshakeLimitForRetry();

  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  // send initial to extract the retry token sent by the server
  std::string retryToken{""};
  expectServerRetryPacketWrite(retryToken);
  testSendInitial(srcConnId, dstConnId, kClientAddr);

  // send another client initial with the retry token rx'd above but with a
  // different client addr to verify it's invalid
  EXPECT_CALL(*quicStats_, onTokenDecryptFailure()).Times(1);
  expectServerRetryPacketWrite(retryToken);
  testSendInitial(srcConnId, dstConnId, kClientAddr2, retryToken);
}

TEST_F(QuicServerWorkerRetryTest, TestRetryInvalidInitialDstConnId) {
  enableRateLimiterForRetry();
  auto dstConnId = getTestConnectionId(hostId_);
  auto srcConnId = getTestConnectionId(0);

  // send initial to extract the retry token sent by the server
  std::string retryToken{""};
  expectServerRetryPacketWrite(retryToken);
  testSendInitial(srcConnId, dstConnId, kClientAddr);

  // send another client initial with the retry token rx'd above but with a
  // different dst conn id to verify it's invalid (i.e. will send another retry
  // packet)
  auto invalidDstConnId = getTestConnectionId(1);
  EXPECT_CALL(*quicStats_, onTokenDecryptFailure()).Times(1);
  expectServerRetryPacketWrite(retryToken);
  testSendInitial(srcConnId, invalidDstConnId, kClientAddr, retryToken);
}

class QuicServerWorkerTakeoverTest : public Test {
 public:
  void SetUp() override {
    auto sock =
        std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb_);
    DCHECK(sock->getEventBase());
    EXPECT_CALL(*sock, getNetworkSocket())
        .WillRepeatedly(Return(folly::NetworkSocket()));
    EXPECT_CALL(*sock, pauseRead());
    takeoverWorkerCb_ = std::make_shared<NiceMock<MockWorkerCallback>>();
    takeoverWorker_ = std::make_unique<QuicServerWorker>(takeoverWorkerCb_);
    takeoverWorker_->setSupportedVersions(supportedVersions);
    takeoverWorker_->setSocket(std::move(sock));
    takeoverSocketFactory_ = std::make_unique<MockQuicUDPSocketFactory>();
    takeoverWorker_->setNewConnectionSocketFactory(
        takeoverSocketFactory_.get());
    factory_ = std::make_unique<MockQuicServerTransportFactory>();
    takeoverWorker_->setTransportFactory(factory_.get());
    auto quicStats = std::make_unique<NiceMock<MockQuicStats>>();
    takeoverWorker_->setConnectionIdAlgo(
        std::make_unique<DefaultConnectionIdAlgo>());
    takeoverWorker_->setTransportStatsCallback(std::move(quicStats));
    quicStats_ = (MockQuicStats*)takeoverWorker_->getTransportStatsCallback();

    auto takeoverSock =
        std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb_);
    takeoverSocket_ = takeoverSock.get();
    folly::SocketAddress takeoverAddr;
    EXPECT_CALL(*takeoverSocket_, bind(_, _));
    EXPECT_CALL(*takeoverSocket_, resumeRead(_));
    takeoverWorker_->allowBeingTakenOver(std::move(takeoverSock), takeoverAddr);
  }

  void testPacketForwarding(Buf data, size_t len, ConnectionId connId);

  void testNoPacketForwarding(Buf data, size_t len, ConnectionId connId);

 protected:
  std::shared_ptr<MockWorkerCallback> takeoverWorkerCb_;
  folly::test::MockAsyncUDPSocket* takeoverSocket_;
  folly::EventBase evb_;
  std::unique_ptr<QuicServerWorker> takeoverWorker_;
  folly::IOBufEqualTo eq;
  folly::SocketAddress clientAddr{kClientAddr};
  std::unique_ptr<MockQuicUDPSocketFactory> takeoverSocketFactory_;
  std::unique_ptr<MockQuicServerTransportFactory> factory_;
  MockQuicStats* quicStats_{nullptr};
  std::vector<QuicVersion> supportedVersions{QuicVersion::MVFST, MVFST1};
  uint16_t clientHostId_{25};
};

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverReInitHandler) {
  auto takeoverSock =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb_);
  folly::SocketAddress takeoverAddr;
  EXPECT_CALL(*takeoverSocket_, pauseRead());

  EXPECT_CALL(*takeoverSock, bind(_, _));
  EXPECT_CALL(*takeoverSock, resumeRead(_));
  EXPECT_CALL(*takeoverSock, address()).WillOnce(Invoke([&]() {
    return takeoverAddr;
  }));
  takeoverWorker_->overrideTakeoverHandlerAddress(
      std::move(takeoverSock), takeoverAddr);
  takeoverSocket_ = takeoverSock.get();
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverNoForwarding) {
  ConnectionId connId = createConnIdForServer(ProcessId::ONE),
               clientConnId = getTestConnectionId(clientHostId_);
  takeoverWorker_->setProcessId(ProcessId::ONE);
  size_t len{0};
  auto data = writeTestDataOnWorkersBuf(
      clientConnId, connId, len, takeoverWorker_.get());
  // enable packet forwarding
  takeoverWorker_->startPacketForwarding(kClientAddr);

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
                std::unique_ptr<NetworkData>& /* networkData */,
                folly::Optional<QuicVersion> /* quicVersion */,
                bool isForwardedData) {
    EXPECT_EQ(addr.getIPAddress(), clientAddr.getIPAddress());
    EXPECT_EQ(addr.getPort(), clientAddr.getPort());
    EXPECT_FALSE(isForwardedData);
  };
  EXPECT_CALL(*takeoverWorkerCb_, routeDataToWorkerLong(_, _, _, _, _))
      .WillOnce(Invoke(cb));
  EXPECT_CALL(*quicStats_, onPacketReceived());
  EXPECT_CALL(*quicStats_, onRead(len));
  EXPECT_CALL(*quicStats_, onPacketForwarded()).Times(0);
  takeoverWorker_->onDataAvailable(
      clientAddr, len, false, OnDataAvailableParams());
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverForwarding) {
  // now try for packets that belongs to different server
  ConnectionId connId = createConnIdForServer(ProcessId::ZERO),
               clientConnId = getTestConnectionId(clientHostId_);
  takeoverWorker_->setProcessId(ProcessId::ONE);
  size_t len{0};

  auto pkt = writeTestDataOnWorkersBuf(
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
  testNoPacketForwarding(std::move(pkt), len, connId);

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
  auto writeSock =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb_);
  EXPECT_CALL(*takeoverSocketFactory_, _make(_, _))
      .WillOnce(Return(writeSock.get()));
  EXPECT_CALL(*writeSock, bind(_, _));
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
        auto& header = parsedHeader->parsedHeader;
        LongHeader* longHeader = header->asLong();
        if (longHeader) {
          EXPECT_EQ(connId, longHeader->getDestinationConnId());
        } else {
          EXPECT_EQ(connId, header->asShort()->getConnectionId());
        }
        return data->computeChainDataLength();
      }));
  takeoverWorker_->startPacketForwarding(kClientAddr);

  auto cb = [&](const folly::SocketAddress& client,
                std::unique_ptr<RoutingData>& routingData,
                std::unique_ptr<NetworkData>& networkData,
                folly::Optional<QuicVersion> quicVersion,
                bool isForwardedData) {
    takeoverWorker_->dispatchPacketData(
        client,
        std::move(*routingData.get()),
        std::move(*networkData.get()),
        std::move(quicVersion),
        isForwardedData);
  };
  EXPECT_CALL(*takeoverWorkerCb_, routeDataToWorkerLong(_, _, _, _, _))
      .WillOnce(Invoke(cb));
  EXPECT_CALL(*quicStats_, onPacketReceived());
  EXPECT_CALL(*quicStats_, onRead(len));
  EXPECT_CALL(*quicStats_, onPacketForwarded()).Times(1);
  takeoverWorker_->onDataAvailable(
      clientAddr, len, false, OnDataAvailableParams());
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
  takeoverWorker_->startPacketForwarding(kClientAddr);

  // the packet will be forwarded
  auto writeSock =
      std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(&evb_);
  EXPECT_CALL(*takeoverSocketFactory_, _make(_, _))
      .WillOnce(Return(writeSock.get()));
  EXPECT_CALL(*writeSock, bind(_, _));
  EXPECT_CALL(*writeSock, write(_, _))
      .WillOnce(Invoke([&](const SocketAddress& client,
                           const std::unique_ptr<folly::IOBuf>& writtenData) {
        // the writtenData contains actual client address + time of ack + data
        EXPECT_FALSE(eq(*data, *writtenData));

        // flip the server id to 'own' the packet (else it'll keep forwarding)
        takeoverWorker_->setProcessId(ProcessId::ZERO);

        // now invoke the Takeover Handler callback
        QuicAsyncUDPSocketWrapper::ReadCallback* takeoverCb =
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
                      std::unique_ptr<NetworkData>& networkData,
                      folly::Optional<QuicVersion> /* quicVersion */,
                      bool isForwardedData) {
          // verify that it is the original client address
          EXPECT_EQ(addr.getIPAddress(), clientAddr.getIPAddress());
          EXPECT_EQ(addr.getPort(), clientAddr.getPort());
          // the original data should be extracted after processing takeover
          // protocol related information
          EXPECT_EQ(networkData->packets.size(), 1);
          EXPECT_TRUE(eq(*data, *(networkData->packets[0])));
          EXPECT_TRUE(isForwardedData);
        };
        EXPECT_CALL(*takeoverWorkerCb_, routeDataToWorkerLong(_, _, _, _, _))
            .WillOnce(Invoke(cb));

        takeoverCb->onDataAvailable(
            client, bufLen, false, OnDataAvailableParams());
        return bufLen;
      }));
  auto workerCb = [&](const folly::SocketAddress& client,
                      std::unique_ptr<RoutingData>& routingData,
                      std::unique_ptr<NetworkData>& networkData,
                      folly::Optional<QuicVersion> quicVersion,
                      bool isForwardedData) {
    takeoverWorker_->dispatchPacketData(
        client,
        std::move(*routingData.get()),
        std::move(*networkData.get()),
        std::move(quicVersion),
        isForwardedData);
  };
  EXPECT_CALL(*takeoverWorkerCb_, routeDataToWorkerLong(_, _, _, _, _))
      .WillOnce(Invoke(workerCb));
  EXPECT_CALL(*quicStats_, onPacketReceived());
  EXPECT_CALL(*quicStats_, onRead(len));
  EXPECT_CALL(*quicStats_, onPacketForwarded()).Times(1);
  EXPECT_CALL(*quicStats_, onForwardedPacketReceived()).Times(1);
  EXPECT_CALL(*quicStats_, onForwardedPacketProcessed()).Times(1);
  takeoverWorker_->onDataAvailable(
      clientAddr, len, false, OnDataAvailableParams());
  // release this resource since MockQuicUDPSocketFactory::_make() hands its
  // ownership to it's caller (i.e. QuicServerWorker)
  writeSock.release();
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverCbReadClose) {
  QuicAsyncUDPSocketWrapper::ReadCallback* takeoverCb =
      takeoverWorker_->getTakeoverHandlerCallback();
  takeoverCb->onReadClosed();
}

TEST_F(QuicServerWorkerTakeoverTest, QuicServerTakeoverCbReadError) {
  QuicAsyncUDPSocketWrapper::ReadCallback* takeoverCb =
      takeoverWorker_->getTakeoverHandlerCallback();
  EXPECT_CALL(*takeoverSocket_, pauseRead());
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::AsyncSocketExceptionType::UNKNOWN, "");
  takeoverCb->onReadError(ex);
  evb_.loopIgnoreKeepAlive();
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
    server_->setConnectionIdVersion(quic::ConnectionIdVersion::V2);
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
      EXPECT_CALL(*transportStatsFactory_, make())
          .WillRepeatedly(Invoke(
              [stats]() { return std::unique_ptr<MockQuicStats>(stats); }));
    } else {
      EXPECT_CALL(*transportStatsFactory_, make()).WillRepeatedly(Invoke([&]() {
        auto mockInfoCb = std::make_unique<NiceMock<MockQuicStats>>();
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
      QuicAsyncUDPSocketType& client,
      folly::SocketAddress serverAddr) {
    // create payload
    StreamId id = 1;
    auto clientConnId = getTestConnectionId(clientHostId_);
    auto serverConnId =
        getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
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
      NiceMock<MockConnectionSetupCallback> connSetupcb;
      NiceMock<MockConnectionCallback> connCb;
      std::unique_ptr<folly::test::MockAsyncUDPSocket> mockSock =
          std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(
              eventBase);
      EXPECT_CALL(*mockSock, address()).WillRepeatedly(ReturnRef(serverAddr));
      transport = std::make_shared<MockQuicTransport>(
          eventBase,
          std::move(mockSock),
          &connSetupcb,
          &connCb,
          quic::test::createServerCtx());
    });

    auto makeTransport =
        [&](folly::EventBase* evb,
            std::unique_ptr<QuicAsyncUDPSocketType>& /* socket */,
            const folly::SocketAddress&,
            std::shared_ptr<const fizz::server::FizzServerContext>) noexcept {
          // set proper expectations for the transport after its creation
          EXPECT_CALL(*transport, getEventBase()).WillRepeatedly(Return(evb));
          EXPECT_CALL(*transport, setTransportStatsCallback(_))
              .WillOnce(Invoke([&](QuicTransportStatsCallback* statsCallback) {
                CHECK(statsCallback);
              }));
          EXPECT_CALL(*transport, setTransportSettings(_))
              .WillRepeatedly(Invoke([&](auto transportSettings) {
                EXPECT_EQ(
                    transportSettings_
                        .advertisedInitialBidiLocalStreamWindowSize,
                    transportSettings
                        .advertisedInitialBidiLocalStreamWindowSize);
                EXPECT_EQ(
                    transportSettings_
                        .advertisedInitialBidiRemoteStreamWindowSize,
                    transportSettings
                        .advertisedInitialBidiRemoteStreamWindowSize);
                EXPECT_EQ(
                    transportSettings_.advertisedInitialUniStreamWindowSize,
                    transportSettings.advertisedInitialUniStreamWindowSize);
                EXPECT_EQ(
                    transportSettings_.advertisedInitialConnectionWindowSize,
                    transportSettings.advertisedInitialConnectionWindowSize);
              }));
          ON_CALL(*transport, onNetworkData(_, _))
              .WillByDefault(Invoke(
                  [&, expected = std::shared_ptr<folly::IOBuf>(data->clone())](
                      auto, const auto& networkData) mutable {
                    EXPECT_GT(networkData.packets.size(), 0);
                    EXPECT_TRUE(folly::IOBufEqualTo()(
                        *networkData.packets[0], *expected));
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

  std::unique_ptr<QuicAsyncUDPSocketType> makeUdpClient() {
    folly::SocketAddress addr2("::1", 0);
    std::unique_ptr<QuicAsyncUDPSocketType> client;
    evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
      client =
          std::make_unique<QuicAsyncUDPSocketType>(evbThread_.getEventBase());
      client->bind(addr2);
    });
    return client;
  }

  void closeUdpClient(std::unique_ptr<QuicAsyncUDPSocketType> client) {
    evbThread_.getEventBase()->runInEventBaseThreadAndWait(
        [&] { client->close(); });
  }

  void runTest(std::vector<folly::EventBase*> evbs) {
    auto serverAddr = initializeServer(evbs);
    auto client = makeUdpClient();
    folly::EventBase* evb = server_->getWorkerEvbs().back();
    auto transport = createNewTransport(evb, *client, serverAddr);
    EXPECT_CALL(*transport, setTransportStatsCallback(nullptr));
    EXPECT_CALL(*transport, setRoutingCallback(nullptr));
    EXPECT_CALL(*transport, closeNow(_));
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
  uint32_t clientHostId_{0}, serverHostId_{0xAABBCC};
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
  EXPECT_CALL(*transport, setTransportStatsCallback(nullptr));

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

    EXPECT_CALL(
        *stats,
        onPacketDropped(PacketDropReason(PacketDropReason::SERVER_SHUTDOWN)));
    NetworkData networkData(folly::IOBuf::copyBuffer("wat"), Clock::now());
    RoutingData routingData(
        HeaderForm::Long,
        true,
        false,
        header.getDestinationConnId(),
        header.getSourceConnId());
    server_->routeDataToWorker(
        kClientAddr, std::move(routingData), std::move(networkData), version);
  }));
  std::thread t([&] { server_->shutdown(); });
  t.join();
  closeUdpClient(std::move(client));
  // cleanup transport
  transport->getEventBase()->runInEventBaseThreadAndWait(
      [&] { transport.reset(); });
}

TEST_F(QuicServerTest, RouteDataFromDifferentThread) {
  folly::ScopedEventBaseThread evbThread;
  std::vector<folly::EventBase*> evbs;
  evbs.emplace_back(evbThread.getEventBase());
  MockQuicStats* stats = new MockQuicStats();
  auto serverAddr = initializeServer(evbs, stats);
  auto client = makeUdpClient();
  auto transport =
      createNewTransport(evbThread.getEventBase(), *client, serverAddr);
  EXPECT_CALL(*transport, setTransportStatsCallback(nullptr));
  EXPECT_CALL(
      *stats,
      onPacketDropped(PacketDropReason(PacketDropReason::SERVER_SHUTDOWN)))
      .Times(0);
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  PacketNum packetNum = 1;
  QuicVersion version = QuicVersion::MVFST;
  LongHeader header(
      LongHeader::Types::Initial,
      clientConnId,
      serverConnId,
      packetNum,
      version);
  auto initialData = std::shared_ptr<folly::IOBuf>(
      folly::IOBuf::create(kMinInitialPacketSize));
  initialData->append(kMinInitialPacketSize);
  memset(initialData->writableData(), 'd', kMinInitialPacketSize);
  NetworkData networkData(initialData->clone(), Clock::now());
  RoutingData routingData(
      HeaderForm::Long,
      true,
      false,
      header.getDestinationConnId(),
      header.getSourceConnId());

  EXPECT_CALL(*transport, onNetworkData(_, _))
      .WillOnce(Invoke([&](auto, const auto& networkData) {
        EXPECT_GT(networkData.packets.size(), 0);
        EXPECT_TRUE(
            folly::IOBufEqualTo()(*networkData.packets[0], *initialData));
      }));

  server_->routeDataToWorker(
      client->address(),
      std::move(routingData),
      std::move(networkData),
      version);

  // cleanup transport
  transport->getEventBase()->runInEventBaseThreadAndWait(
      [&] { transport.reset(); });
  closeUdpClient(std::move(client));
  std::thread t([&] { server_->shutdown(); });
  t.join();
}

TEST_F(QuicServerTest, OverrideTakeoverAddressTest) {
  folly::ScopedEventBaseThread evbThread;
  std::vector<folly::EventBase*> evbs;
  evbs.emplace_back(evbThread.getEventBase());
  auto serverAddr = initializeServer(evbs);
  folly::SocketAddress takeoverAddr("::1", 0);
  server_->allowBeingTakenOver(takeoverAddr);
  uint8_t bindAttempt = 0;
  folly::SocketAddress boundAddr;
  while (bindAttempt < 5) {
    boundAddr = server_->overrideTakeoverHandlerAddress(takeoverAddr);
    bindAttempt++;
  }
  EXPECT_TRUE(boundAddr.isInitialized());
  std::thread t([&] { server_->shutdown(); });
  t.join();
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
    NiceMock<MockConnectionSetupCallback> connSetupCb;
    NiceMock<MockConnectionCallback> connCb;
    auto makeTransport =
        [&](folly::EventBase* eventBase,
            std::unique_ptr<QuicAsyncUDPSocketType>& socket,
            const folly::SocketAddress&,
            std::shared_ptr<const fizz::server::FizzServerContext>
                ctx) noexcept {
          transport = std::make_shared<MockQuicTransport>(
              eventBase, std::move(socket), &connSetupCb, &connCb, ctx);
          transport->setClientConnectionId(clientConnId);
          // setup expectations
          EXPECT_CALL(*transport, getEventBase())
              .WillRepeatedly(Return(eventBase));
          EXPECT_CALL(*transport, setTransportSettings(_));
          EXPECT_CALL(*transport, accept());
          EXPECT_CALL(*transport, setSupportedVersions(_));
          EXPECT_CALL(*transport, setRoutingCallback(_));
          EXPECT_CALL(*transport, setOriginalPeerAddress(_));
          EXPECT_CALL(*transport, setTransportStatsCallback(_));
          EXPECT_CALL(*transport, setServerConnectionIdParams(_))
              .WillOnce(Invoke([&](ServerConnectionIdParams params) {
                EXPECT_EQ(params.processId, 0);
                EXPECT_EQ(params.workerId, 0);
              }));
          EXPECT_CALL(*transport, onNetworkData(_, _))
              .WillOnce(Invoke(
                  [&, expected = data.get()](auto, const auto& networkData) {
                    EXPECT_GT(networkData.packets.size(), 0);
                    EXPECT_TRUE(folly::IOBufEqualTo()(
                        *networkData.packets[0], *expected));
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
    auto makeCbForOldServer = [&]() {
      oldTransInfoCb_ = new NiceMock<MockQuicStats>();
      std::unique_ptr<MockQuicStats> quicStats;
      quicStats.reset(oldTransInfoCb_);
      return quicStats;
    };
    EXPECT_CALL(*transportStatsFactory, make())
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
    std::unique_ptr<QuicAsyncUDPSocketType> client;
    evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
      client =
          std::make_unique<QuicAsyncUDPSocketType>(evbThread_.getEventBase());
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
    auto makeCbForNewServer = [&]() {
      newTransInfoCb_ = new NiceMock<MockQuicStats>();
      std::unique_ptr<MockQuicStats> quicStats;
      quicStats.reset(newTransInfoCb_);
      return quicStats;
    };
    EXPECT_CALL(*transportStatsFactory, make())
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
    CHECK(newServerAddr != destAddr);

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
        .WillOnce(
            Invoke([&, expected = data.get()](auto, const auto& networkData) {
              EXPECT_GT(networkData.packets.size(), 0);
              EXPECT_TRUE(
                  folly::IOBufEqualTo()(*networkData.packets[0], *expected));
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

    EXPECT_CALL(*transportCbForOldServer, setTransportStatsCallback(nullptr));
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

struct UDPReader : public QuicAsyncUDPSocketWrapper::ReadCallback {
  UDPReader() {
    bufPromise_ =
        std::make_unique<folly::Promise<std::unique_ptr<folly::IOBuf>>>();
  }

  ~UDPReader() override = default;

  void start(EventBase* evb, SocketAddress addr) {
    evb_ = evb;
    evb_->runInEventBaseThreadAndWait([&] {
      client = std::make_unique<QuicAsyncUDPSocketType>(evb_);
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
      bool truncated,
      OnDataAvailableParams /*params*/) noexcept override {
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
  std::unique_ptr<QuicAsyncUDPSocketType> client;
  EventBase* evb_;
};

TEST_F(QuicServerTest, NetworkTestVersionNegotiation) {
  folly::SocketAddress addr("::1", 0);
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

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = createData(kMinInitialPacketSize + 10);
  auto packet =
      createInitialStream(clientConnId, serverConnId, id, *buf, MVFST1);
  auto data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());

  auto serverData = reader->readOne().get(200ms);

  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);
  auto packetQueue = bufToQueue(std::move(serverData));
  auto versionPacket = codec->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(versionPacket.has_value());

  EXPECT_EQ(versionPacket->destinationConnectionId, clientConnId);
}

TEST_F(QuicServerTest, NetworkTestVersionNegotiationMinLength) {
  folly::SocketAddress addr("::1", 0);
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

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = createData(kMinInitialPacketSize - 100);
  auto packet =
      createInitialStream(clientConnId, serverConnId, id, *buf, MVFST1);
  auto data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());
  EXPECT_THROW(reader->readOne().get(200ms), folly::FutureTimeout);
}

TEST_F(QuicServerTest, NetworkTestNoVersionNegotiation) {
  folly::SocketAddress addr("::1", 0);
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

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = folly::IOBuf::copyBuffer("hello");
  auto packet = createInitialStream(
      clientConnId, serverConnId, id, *buf, QuicVersion::VERSION_NEGOTIATION);
  auto data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());
  EXPECT_THROW(reader->readOne().get(200ms), folly::FutureTimeout);
}

TEST_F(QuicServerTest, TestRejectNewConnections) {
  // test that Version Negotiation fails if the server is rejecting all
  // new connections
  folly::SocketAddress addr("::1", 0);
  server_->start(addr, 2);
  server_->rejectNewConnections([]() { return true; });
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

  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = createData(kMinInitialPacketSize);
  auto packet =
      createInitialStream(clientConnId, serverConnId, id, *buf, MVFST1);
  auto data = std::move(packet);
  reader->getSocket().write(serverAddr, data->clone());

  auto serverData = reader->readOne().get(200ms);

  auto codec = std::make_unique<QuicReadCodec>(QuicNodeType::Server);

  auto packetQueue = bufToQueue(std::move(serverData));
  auto versionPacket = codec->tryParsingVersionNegotiation(packetQueue);
  ASSERT_TRUE(versionPacket.has_value());

  EXPECT_EQ(versionPacket->destinationConnectionId, clientConnId);
  EXPECT_EQ(versionPacket->sourceConnectionId, serverConnId);
  EXPECT_EQ(versionPacket->versions.size(), 1);
  EXPECT_EQ(versionPacket->versions.at(0), QuicVersion::MVFST_INVALID);
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
  EXPECT_THROW(reader->readOne().get(200ms), folly::FutureTimeout);
}

void QuicServerTest::testReset(Buf packet) {
  folly::SocketAddress addr("::1", 0);
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
  auto packetBuf = serverData->clone();
  overridePacketWithToken(*packetBuf, token);
  auto packetQueue = bufToQueue(std::move(packetBuf));
  auto res = codec.parsePacket(packetQueue, ackStates);
  EXPECT_NE(res.statelessReset(), nullptr);
}

TEST_F(QuicServerTest, NetworkTestReset) {
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
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
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
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
  ASSERT_LE(packet->computeChainDataLength(), kDefaultUDPSendPacketLen);
  testReset(std::move(packet));
}

TEST_F(QuicServerTest, NetworkTestResetLongHeader) {
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
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

  setUpTransportFactoryForWorkers(evbs);
  std::shared_ptr<MockQuicTransport> transport;
  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  folly::Baton<> b;
  // create payload
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto buf = createData(kMinInitialPacketSize + 10);
  auto packet = createInitialStream(
      clientConnId, serverConnId, id, *buf, QuicVersion::MVFST);
  auto data = std::move(packet);

  auto makeTransport =
      [&](folly::EventBase* eventBase,
          std::unique_ptr<QuicAsyncUDPSocketType>& socket,
          const folly::SocketAddress&,
          std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept {
        transport = std::make_shared<MockQuicTransport>(
            eventBase, std::move(socket), &connSetupCb, &connCb, ctx);
        EXPECT_CALL(*transport, getEventBase())
            .WillRepeatedly(Return(eventBase));
        EXPECT_CALL(*transport, setSupportedVersions(_));
        EXPECT_CALL(*transport, setOriginalPeerAddress(_));
        EXPECT_CALL(*transport, setTransportSettings(_));
        EXPECT_CALL(*transport, setServerConnectionIdParams(_));
        EXPECT_CALL(*transport, accept());
        // post baton upon receiving the data
        EXPECT_CALL(*transport, onNetworkData(_, _))
            .WillOnce(Invoke(
                [&, expected = data.get()](auto, const auto& networkData) {
                  EXPECT_GT(networkData.packets.size(), 0);
                  EXPECT_TRUE(folly::IOBufEqualTo()(
                      *networkData.packets[0], *expected));
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
  auto verifyZeroRtt = [&](const folly::SocketAddress& peer,
                           const NetworkData& networkData) noexcept {
    EXPECT_GT(networkData.packets.size(), 0);
    EXPECT_EQ(peer, reader->getSocket().address());
    EXPECT_TRUE(folly::IOBufEqualTo()(*data, *networkData.packets[0]));
    b1.post();
  };
  EXPECT_CALL(*transport, onNetworkData(_, _)).WillOnce(Invoke(verifyZeroRtt));
  reader->getSocket().write(serverAddr, data->clone());
  b1.wait();
}

TEST_F(QuicServerTest, ZeroRttBeforeInitial) {
  folly::ScopedEventBaseThread evbThread;
  auto evb = evbThread.getEventBase();
  std::vector<folly::EventBase*> evbs{evb};

  folly::SocketAddress addr("::1", 0);
  server_->start(addr, 1);
  server_->waitUntilInitialized();

  setUpTransportFactoryForWorkers(evbs);
  std::shared_ptr<MockQuicTransport> transport;
  NiceMock<MockConnectionSetupCallback> connSetupCb;
  NiceMock<MockConnectionCallback> connCb;
  folly::Baton<> b;
  // create payload
  StreamId id = 1;
  auto clientConnId = getTestConnectionId(clientHostId_);
  auto serverConnId =
      getTestConnectionId(serverHostId_, quic::ConnectionIdVersion::V2);
  auto initialBuf = createData(kMinInitialPacketSize + 10);
  auto initialPacket = createInitialStream(
      clientConnId, serverConnId, id, *initialBuf, QuicVersion::MVFST);
  auto initialData = std::move(initialPacket);

  std::vector<Buf> receivedData;
  auto makeTransport =
      [&](folly::EventBase* eventBase,
          std::unique_ptr<QuicAsyncUDPSocketType>& socket,
          const folly::SocketAddress&,
          std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept {
        transport = std::make_shared<MockQuicTransport>(
            eventBase, std::move(socket), &connSetupCb, &connCb, ctx);
        EXPECT_CALL(*transport, getEventBase())
            .WillRepeatedly(Return(eventBase));
        EXPECT_CALL(*transport, setSupportedVersions(_));
        EXPECT_CALL(*transport, setOriginalPeerAddress(_));
        EXPECT_CALL(*transport, setTransportSettings(_));
        EXPECT_CALL(*transport, setServerConnectionIdParams(_));
        EXPECT_CALL(*transport, accept());
        // post baton upon receiving the data
        EXPECT_CALL(*transport, onNetworkData(_, _))
            .Times(2)
            .WillRepeatedly(Invoke([&](auto, auto& networkData) {
              for (auto& buf : networkData.packets) {
                receivedData.emplace_back(buf->clone());
              }
              if (receivedData.size() == 2) {
                b.post();
              }
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

  // send 0-rtt packet, it should be buffered
  PacketNum packetNum = 20;
  auto zeroRttBuf = folly::IOBuf::copyBuffer("blah blah blah blah");
  auto zeroRttPacket = packetToBuf(createStreamPacket(
      clientConnId,
      serverConnId,
      packetNum,
      id,
      *zeroRttBuf,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      std::make_pair(LongHeader::Types::ZeroRtt, QuicVersion::MVFST)));
  auto zeroRttData = std::move(zeroRttPacket);
  reader->getSocket().write(serverAddr, zeroRttData->clone());

  // send an initial packet - that should create a new 'connection'
  reader->getSocket().write(serverAddr, initialData->clone());
  b.wait();
  ASSERT_EQ(receivedData.size(), 2);
  ASSERT_EQ(
      initialData->computeChainDataLength(),
      receivedData[0]->computeChainDataLength());
  ASSERT_EQ(
      zeroRttData->computeChainDataLength(),
      receivedData[1]->computeChainDataLength());
  EXPECT_TRUE(folly::IOBufEqualTo()(*initialData, *receivedData[0]));
  EXPECT_TRUE(folly::IOBufEqualTo()(*zeroRttData, *receivedData[1]));
}

TEST_F(QuicServerTest, OneEVB) {
  folly::EventBase evb;

  folly::SocketAddress addr("::1", 0);
  server_->initialize(addr, {&evb}, true);
  server_->start();
  server_->waitUntilInitialized();
  evb.runAfterDelay([this] { server_->shutdown(); }, 100);
  evb.loop();
}

} // namespace test
} // namespace quic
