/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/client/test/Mocks.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/events/test/QuicEventBaseMock.h>
#include <quic/common/test/TestUtils.h>
#include <quic/common/udpsocket/test/QuicAsyncUDPSocketMock.h>

using namespace ::testing;

namespace quic::test {

class QuicClientTransportLiteMock : public QuicClientTransportLite {
 public:
  QuicClientTransportLiteMock(
      std::shared_ptr<quic::FollyQuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocketMock> socket,
      std::shared_ptr<MockClientHandshakeFactory> handshakeFactory)
      : QuicTransportBaseLite(evb, std::move(socket)),
        QuicClientTransportLite(evb, nullptr, handshakeFactory) {}

  QuicClientConnectionState* getConn() {
    return clientConn_;
  }
};

class QuicClientTransportLiteTest : public Test {
 public:
  void SetUp() override {
    qEvb_ = std::make_shared<FollyQuicEventBase>(&evb_);
    auto socket = std::make_unique<QuicAsyncUDPSocketMock>();
    sockPtr_ = socket.get();
    ON_CALL(*socket, setAdditionalCmsgsFunc(_))
        .WillByDefault(Return(folly::unit));
    ON_CALL(*socket, close()).WillByDefault(Return(folly::unit));
    ON_CALL(*socket, bind(_)).WillByDefault(Return(folly::unit));
    ON_CALL(*socket, connect(_)).WillByDefault(Return(folly::unit));
    ON_CALL(*socket, setReuseAddr(_)).WillByDefault(Return(folly::unit));
    ON_CALL(*socket, setReusePort(_)).WillByDefault(Return(folly::unit));
    ON_CALL(*socket, setRecvTos(_)).WillByDefault(Return(folly::unit));
    ON_CALL(*socket, getRecvTos()).WillByDefault(Return(false));
    ON_CALL(*socket, getGSO()).WillByDefault(Return(0));
    ON_CALL(*socket, setCmsgs(_)).WillByDefault(Return(folly::unit));
    ON_CALL(*socket, appendCmsgs(_)).WillByDefault(Return(folly::unit));
    auto mockFactory = std::make_shared<MockClientHandshakeFactory>();
    EXPECT_CALL(*mockFactory, _makeClientHandshake(_))
        .WillRepeatedly(Invoke(
            [&](QuicClientConnectionState* conn)
                -> std::unique_ptr<quic::ClientHandshake> {
              return std::make_unique<MockClientHandshake>(conn);
            }));
    quicClient_ = std::make_shared<QuicClientTransportLiteMock>(
        qEvb_, std::move(socket), mockFactory);
    quicClient_->getConn()->oneRttWriteCipher = test::createNoOpAead();
    quicClient_->getConn()->oneRttWriteHeaderCipher =
        test::createNoOpHeaderCipher();
    ASSERT_FALSE(quicClient_->getState()
                     ->streamManager->setMaxLocalBidirectionalStreams(128)
                     .hasError());
  }

  void TearDown() override {
    EXPECT_CALL(*sockPtr_, close()).WillRepeatedly(Return(folly::unit));
    quicClient_->closeNow(std::nullopt);
  }

  folly::EventBase evb_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  std::shared_ptr<QuicClientTransportLiteMock> quicClient_;
  MockConnectionSetupCallback mockConnectionSetupCallback_;
  QuicAsyncUDPSocketMock* sockPtr_{nullptr};
};

TEST_F(QuicClientTransportLiteTest, TestPriming) {
  auto transportSettings = quicClient_->getTransportSettings();
  transportSettings.isPriming = true;
  quicClient_->setTransportSettings(std::move(transportSettings));
  quicClient_->setConnectionSetupCallback(&mockConnectionSetupCallback_);
  quicClient_->getConn()->zeroRttWriteCipher = test::createNoOpAead();

  StreamId streamId = quicClient_->createBidirectionalStream().value();
  quicClient_->writeChain(streamId, folly::IOBuf::copyBuffer("test"), false);
  EXPECT_CALL(mockConnectionSetupCallback_, onPrimingDataAvailable(_));
  evb_.loopOnce(EVLOOP_NONBLOCK);
}

} // namespace quic::test
