/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/futures/Future.h>
#include <folly/io/async/test/MockAsyncTransport.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <folly/io/async/AsyncTransport.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/QuicClientAsyncTransport.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientHandshake.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/async_tran/QuicAsyncTransportServer.h>
#include <quic/server/async_tran/QuicServerAsyncTransport.h>
#include <quic/server/test/Mocks.h>

using namespace testing;

namespace quic::test {

class MockConnection : public wangle::ManagedConnection {
 public:
  explicit MockConnection(folly::AsyncTransport::UniquePtr sock)
      : sock_(std::move(sock)) {}
  void timeoutExpired() noexcept final {}
  void describe(std::ostream&) const final {}
  bool isBusy() const final {
    return true;
  }
  void notifyPendingShutdown() final {}
  void closeWhenIdle() final {}
  void dropConnection(const std::string& /*errorMsg*/ = "") final {
    destroy();
  }
  void dumpConnectionState(uint8_t) final {}

 private:
  folly::AsyncTransport::UniquePtr sock_;
};

class QuicAsyncTransportServerTest : public Test {
 public:
  void SetUp() override {
    folly::ssl::init();
    createServer();
    createClient();
  }

  void createServer() {
    EXPECT_CALL(serverReadCB_, isBufferMovable_())
        .WillRepeatedly(Return(false));
    EXPECT_CALL(serverReadCB_, getReadBuffer(_, _))
        .WillRepeatedly(Invoke([&](void** buf, size_t* len) {
          *buf = serverBuf_.data();
          *len = serverBuf_.size();
        }));
    EXPECT_CALL(serverReadCB_, readDataAvailable_(_))
        .WillOnce(Invoke([&](auto len) {
          auto echoData = folly::IOBuf::wrapBuffer(serverBuf_.data(), len);
          echoData->appendChain(folly::IOBuf::copyBuffer(" ding dong"));
          serverAsyncWrapper_->writeChain(&serverWriteCB_, std::move(echoData));
          serverAsyncWrapper_->shutdownWrite();
        }));
    EXPECT_CALL(serverReadCB_, readEOF_()).WillOnce(Return());
    EXPECT_CALL(serverWriteCB_, writeSuccess_()).WillOnce(Return());

    server_ = std::make_shared<QuicAsyncTransportServer>([this](auto sock) {
      sock->setReadCB(&serverReadCB_);
      serverAsyncWrapper_ = std::move(sock);
      return new MockConnection(nullptr);
    });
    server_->setFizzContext(test::createServerCtx());
    folly::SocketAddress addr("::1", 0);
    server_->start(addr, 1);
    serverAddr_ = server_->quicServer().getAddress();
  }

  void createClient() {
    clientEvbThread_ = std::thread([&]() { clientEvb_.loopForever(); });

    EXPECT_CALL(clientReadCB_, isBufferMovable_())
        .WillRepeatedly(Return(false));
    EXPECT_CALL(clientReadCB_, getReadBuffer(_, _))
        .WillRepeatedly(Invoke([&](void** buf, size_t* len) {
          *buf = clientBuf_.data();
          *len = clientBuf_.size();
        }));
    EXPECT_CALL(clientReadCB_, readDataAvailable_(_))
        .WillOnce(Invoke([&](auto len) {
          clientReadPromise_.setValue(
              std::string(reinterpret_cast<char*>(clientBuf_.data()), len));
        }));
    EXPECT_CALL(clientReadCB_, readEOF_()).WillOnce(Return());
    EXPECT_CALL(clientWriteCB_, writeSuccess_()).WillOnce(Return());

    clientEvb_.runInEventBaseThreadAndWait([&]() {
      auto sock = std::make_unique<folly::AsyncUDPSocket>(&clientEvb_);
      auto fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(test::createTestCertificateVerifier())
              .build();
      client_ = std::make_shared<QuicClientTransport>(
          &clientEvb_, std::move(sock), std::move(fizzClientContext));
      client_->setHostname("echo.com");
      client_->addNewPeerAddress(serverAddr_);
      clientAsyncWrapper_.reset(new QuicClientAsyncTransport(client_));
      clientAsyncWrapper_->setReadCB(&clientReadCB_);
    });
  }

  void TearDown() override {
    server_->shutdown();
    server_ = nullptr;
    clientEvb_.runInEventBaseThreadAndWait([&] {
      clientAsyncWrapper_ = nullptr;
      client_ = nullptr;
    });
    clientEvb_.terminateLoopSoon();
    clientEvbThread_.join();
  }

 protected:
  std::shared_ptr<QuicAsyncTransportServer> server_;
  folly::SocketAddress serverAddr_;
  folly::AsyncTransport::UniquePtr serverAsyncWrapper_;
  folly::test::MockWriteCallback serverWriteCB_;
  folly::test::MockReadCallback serverReadCB_;
  std::array<uint8_t, 1024> serverBuf_;

  std::shared_ptr<QuicClientTransport> client_;
  folly::EventBase clientEvb_;
  std::thread clientEvbThread_;
  QuicClientAsyncTransport::UniquePtr clientAsyncWrapper_;
  folly::test::MockWriteCallback clientWriteCB_;
  folly::test::MockReadCallback clientReadCB_;
  std::array<uint8_t, 1024> clientBuf_;
  folly::Promise<std::string> clientReadPromise_;
};

TEST_F(QuicAsyncTransportServerTest, ReadWrite) {
  auto [promise, future] = folly::makePromiseContract<std::string>();
  clientReadPromise_ = std::move(promise);

  std::string msg = "jaja";
  clientEvb_.runInEventBaseThreadAndWait([&] {
    clientAsyncWrapper_->write(&clientWriteCB_, msg.data(), msg.size());
    clientAsyncWrapper_->shutdownWrite();
  });

  std::string clientReadString = std::move(future).get(1s);
  EXPECT_EQ(clientReadString, "jaja ding dong");
}

} // namespace quic::test
