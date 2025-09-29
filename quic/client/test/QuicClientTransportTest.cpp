/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/client/test/Mocks.h>
#include <quic/common/events/test/QuicEventBaseMock.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/test/QuicAsyncUDPSocketMock.h>

using namespace ::testing;

namespace quic::test {

class QuicClientTransportMock : public QuicClientTransport {
 public:
  QuicClientTransportMock(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory)
      : QuicTransportBaseLite(evb, std::move(socket)),
        QuicClientTransport(
            evb,
            nullptr /* Initialized through the QuicTransportBaseLite constructor
                     */
            ,
            handshakeFactory) {
    initializePathManagerState(*clientConn_);
  }

  void readWithRecvmsg(
      QuicAsyncUDPSocket& sock,
      uint64_t readBufferSize,
      uint16_t numPackets) {
    CHECK(
        !QuicClientTransport::readWithRecvmsg(sock, readBufferSize, numPackets)
             .hasError());
  }

  void readWithRecvmsgSinglePacketLoop(
      QuicAsyncUDPSocket& sock,
      uint64_t readBufferSize) {
    CHECK(!QuicClientTransport::readWithRecvmsgSinglePacketLoop(
               sock, readBufferSize)
               .hasError());
  }

  quic::Expected<void, QuicError> processPackets(
      const Optional<folly::SocketAddress>& /*localAddress*/,
      NetworkData&& networkData,
      const Optional<folly::SocketAddress>& server) override {
    networkDataVec_.push_back(std::move(networkData));
    server_ = server;
    return {};
  }

  QuicClientConnectionState* getClientConn() {
    return clientConn_;
  }

  std::vector<NetworkData> networkDataVec_;
  Optional<folly::SocketAddress> server_;
};

class QuicClientTransportTest : public Test {
 public:
  void SetUp() override {
    evb_ = std::make_shared<QuicEventBaseMock>();
    auto sock = std::make_unique<QuicAsyncUDPSocketMock>();
    sockPtr_ = sock.get();
    ON_CALL(*sock, setReuseAddr(_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setAdditionalCmsgsFunc(_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setDFAndTurnOffPMTU())
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setErrMessageCallback(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setTosOrTrafficClass(_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, init(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, applyOptions(testing::_, testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, bind(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, connect(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, close())
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setGRO(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, getGRO()).WillByDefault(testing::Return(0));
    ON_CALL(*sock, getGSO()).WillByDefault(testing::Return(0));
    ON_CALL(*sock, setRecvTos(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, getRecvTos()).WillByDefault(testing::Return(false));
    ON_CALL(*sock, setCmsgs(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, appendCmsgs(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, getTimestamping()).WillByDefault(testing::Return(0));
    ON_CALL(*sock, setReusePort(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setRcvBuf(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setSndBuf(testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*sock, setFD(testing::_, testing::_))
        .WillByDefault(testing::Return(quic::Expected<void, QuicError>{}));

    mockFactory_ = std::make_shared<MockClientHandshakeFactory>();
    EXPECT_CALL(*mockFactory_, makeClientHandshakeImpl(_))
        .WillRepeatedly(Invoke(
            [&](QuicClientConnectionState* conn)
                -> std::unique_ptr<quic::ClientHandshake> {
              auto handshake = std::make_unique<MockClientHandshake>(conn);
              mockHandshake_ = handshake.get();
              return handshake;
            }));

    EXPECT_CALL(*sockPtr_, getLocalAddressFamily()).WillRepeatedly(Invoke([]() {
      return AF_INET6;
    }));

    quicClient_ = std::make_shared<QuicClientTransportMock>(
        evb_, std::move(sock), mockFactory_);
  }

  void TearDown() override {
    quicClient_->closeNow(std::nullopt);
  }

  std::shared_ptr<QuicEventBaseMock> evb_;
  std::shared_ptr<MockClientHandshakeFactory> mockFactory_;
  MockClientHandshake* mockHandshake_{nullptr};
  std::shared_ptr<QuicClientTransportMock> quicClient_;
  QuicAsyncUDPSocketMock* sockPtr_{nullptr};
};

TEST_F(QuicClientTransportTest, TestReadWithRecvmsg) {
  int numRecvmsgCalls = 0;
  EXPECT_CALL(*sockPtr_, recvmsg(_, _))
      .WillRepeatedly(Invoke([&](struct msghdr* /* msg */, int /* flags */) {
        ++numRecvmsgCalls;
        return numRecvmsgCalls > 1 ? 0 : 10;
      }));
  quicClient_->readWithRecvmsg(
      *sockPtr_, 1024 /* readBufferSize */, 128 /* numPackets */);
  EXPECT_EQ(quicClient_->networkDataVec_.size(), 1);
  EXPECT_EQ(quicClient_->networkDataVec_[0].getPackets().size(), 1);
}

TEST_F(QuicClientTransportTest, TestReadWithRecvmsgSinglePacketLoop) {
  int numRecvmsgCalls = 0;
  const int numCallsExpected =
      quicClient_->getTransportSettings().maxRecvBatchSize;
  auto transportSettings = quicClient_->getTransportSettings();
  transportSettings.networkDataPerSocketRead = true;
  quicClient_->setTransportSettings(std::move(transportSettings));

  quicClient_->getClientConn()->oneRttWriteCipher = test::createNoOpAead();
  ASSERT_FALSE(quicClient_->getClientConn()
                   ->streamManager->setMaxLocalBidirectionalStreams(128)
                   .hasError());
  StreamId streamId = quicClient_->createBidirectionalStream().value();
  ASSERT_FALSE(
      quicClient_->writeChain(streamId, folly::IOBuf::copyBuffer("test"), false)
          .hasError());

  EXPECT_CALL(*sockPtr_, recvmsg(_, _))
      .WillRepeatedly(Invoke([&](struct msghdr* /* msg */, int /* flags */) {
        ++numRecvmsgCalls;
        return numRecvmsgCalls > numCallsExpected ? 0 : 42;
      }));
  // update WriteLooper() will call runInLoop() only once.
  EXPECT_CALL(*evb_, runInLoopWithCbPtr(_, _)).WillOnce(Return());
  quicClient_->readWithRecvmsgSinglePacketLoop(
      *sockPtr_, 1024 /* readBufferSize */);
  EXPECT_EQ(quicClient_->networkDataVec_.size(), numCallsExpected);
  for (const auto& networkData : quicClient_->networkDataVec_) {
    EXPECT_EQ(networkData.getPackets().size(), 1);
  }
}

} // namespace quic::test
