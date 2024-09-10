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
#include <quic/common/udpsocket/test/QuicAsyncUDPSocketMock.h>

using namespace ::testing;

namespace quic::test {

class QuicClientTransportMock : public QuicClientTransport {
 public:
  QuicClientTransportMock(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory)
      : QuicClientTransport(evb, std::move(socket), handshakeFactory) {}

  void readWithRecvmsg(
      QuicAsyncUDPSocket& sock,
      uint64_t readBufferSize,
      uint16_t numPackets) {
    QuicClientTransport::readWithRecvmsg(sock, readBufferSize, numPackets);
  }
  void processPackets(
      NetworkData&& networkData,
      const Optional<folly::SocketAddress>& server) override {
    networkData_ = std::move(networkData);
    server_ = server;
  }

  NetworkData networkData_;
  Optional<folly::SocketAddress> server_;
};

class QuicClientTransportTest : public Test {
 public:
  void SetUp() override {
    evb_ = std::make_shared<QuicEventBaseMock>();
    auto sock = std::make_unique<QuicAsyncUDPSocketMock>();
    sockPtr_ = sock.get();

    mockFactory_ = std::make_shared<MockClientHandshakeFactory>();
    EXPECT_CALL(*mockFactory_, _makeClientHandshake(_))
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
    quicClient_->closeNow(folly::none);
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
  EXPECT_EQ(quicClient_->networkData_.getPackets().size(), 1);
}

} // namespace quic::test
