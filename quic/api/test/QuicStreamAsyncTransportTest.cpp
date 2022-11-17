/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/MoveWrapper.h>
#include <folly/container/F14Map.h>
#include <folly/futures/Future.h>
#include <folly/io/async/test/MockAsyncTransport.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <quic/api/QuicStreamAsyncTransport.h>
#include <quic/api/test/Mocks.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientHandshake.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/test/Mocks.h>

using namespace testing;

namespace quic::test {

class QuicStreamAsyncTransportTest : public Test {
 protected:
  struct Stream {
    Stream() = default;
    Stream(const Stream&) = delete;
    Stream& operator=(const Stream&) = delete;
    Stream(Stream&&) = delete;
    Stream& operator=(Stream&&) = delete;
    folly::test::MockWriteCallback writeCb;
    folly::test::MockReadCallback readCb;
    QuicStreamAsyncTransport::UniquePtr transport;
    std::array<uint8_t, 1024> buf;
    uint8_t serverDone{2}; // need to finish reads & writes
  };

 public:
  void SetUp() override {
    folly::ssl::init();
    createServer();
    connect();
  }

  void createServer() {
    auto serverTransportFactory =
        std::make_unique<MockQuicServerTransportFactory>();
    EXPECT_CALL(*serverTransportFactory, _make(_, _, _, _))
        .WillOnce(Invoke(
            [&](folly::EventBase* evb,
                std::unique_ptr<folly::AsyncUDPSocket>& socket,
                const folly::SocketAddress& /*addr*/,
                std::shared_ptr<const fizz::server::FizzServerContext> ctx) {
              auto transport = quic::QuicServerTransport::make(
                  evb,
                  std::move(socket),
                  &serverConnectionSetupCB_,
                  &serverConnectionCB_,
                  std::move(ctx));
              CHECK(serverSocket_.get() == nullptr);
              serverSocket_ = transport;
              return transport;
            }));

    server_ = QuicServer::createQuicServer();
    auto serverCtx = test::createServerCtx();
    server_->setFizzContext(serverCtx);

    server_->setQuicServerTransportFactory(std::move(serverTransportFactory));

    folly::SocketAddress addr("::1", 0);
    server_->start(addr, 1);
    server_->waitUntilInitialized();
    serverAddr_ = server_->getAddress();
  }

  void expectNewServerStream() {
    EXPECT_CALL(serverConnectionCB_, onNewBidirectionalStream(_))
        .WillOnce(Invoke([&](StreamId id) {
          auto res = streams_.emplace(
              std::piecewise_construct,
              std::forward_as_tuple(id),
              std::forward_as_tuple(std::make_unique<Stream>()));
          auto& newStream = *res.first->second;
          newStream.transport =
              QuicStreamAsyncTransport::createWithExistingStream(
                  serverSocket_, id);
          EXPECT_CALL(newStream.readCb, readEOF_()).WillOnce(Invoke([this, id] {
            auto& stream = *streams_[id];
            if (--stream.serverDone == 0) {
              stream.transport->close();
            }
          }));
          EXPECT_CALL(newStream.readCb, isBufferMovable_())
              .WillRepeatedly(Return(false));
          EXPECT_CALL(newStream.readCb, getReadBuffer(_, _))
              .WillRepeatedly(Invoke([this, id](void** buf, size_t* len) {
                auto& stream = *streams_[id];
                *buf = stream.buf.data();
                *len = stream.buf.size();
              }));
          EXPECT_CALL(newStream.readCb, readDataAvailable_(_))
              .WillRepeatedly(Invoke([this, id](auto len) {
                auto& stream = *streams_[id];
                auto echoData = folly::IOBuf::copyBuffer("echo ");
                echoData->appendChain(
                    folly::IOBuf::wrapBuffer(stream.buf.data(), len));
                EXPECT_CALL(stream.writeCb, writeSuccess_())
                    .WillOnce(Return())
                    .RetiresOnSaturation();
                if (stream.transport->good()) {
                  // Echo the first readDataAvailable_ only
                  stream.transport->writeChain(
                      &stream.writeCb, std::move(echoData));
                  stream.transport->shutdownWrite();
                  if (--stream.serverDone == 0) {
                    stream.transport->close();
                  }
                }
              }));
          newStream.transport->setReadCB(&newStream.readCb);
        }))
        .RetiresOnSaturation();
  }

  std::unique_ptr<Stream> createClient(bool setReadCB = true) {
    auto clientStream = std::make_unique<Stream>();
    clientStream->transport =
        QuicStreamAsyncTransport::createWithNewStream(client_);
    CHECK(clientStream->transport);

    EXPECT_CALL(clientStream->readCb, isBufferMovable_())
        .WillRepeatedly(Return(false));
    EXPECT_CALL(clientStream->readCb, getReadBuffer(_, _))
        .WillRepeatedly(Invoke(
            [clientStream = clientStream.get()](void** buf, size_t* len) {
              *buf = clientStream->buf.data();
              *len = clientStream->buf.size();
            }));

    if (setReadCB) {
      clientStream->transport->setReadCB(&clientStream->readCb);
    }
    return clientStream;
  }

  void connect() {
    auto [promiseX, future] = folly::makePromiseContract<folly::Unit>();
    auto promise = std::move(promiseX);
    EXPECT_CALL(clientConnectionSetupCB_, onTransportReady())
        .WillOnce(Invoke([&promise]() mutable { promise.setValue(); }));

    clientEvb_.runInLoop([&]() {
      auto sock = std::make_unique<folly::AsyncUDPSocket>(&clientEvb_);
      auto fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(test::createTestCertificateVerifier())
              .build();
      client_ = std::make_shared<QuicClientTransport>(
          &clientEvb_, std::move(sock), std::move(fizzClientContext));
      client_->setHostname("echo.com");
      client_->addNewPeerAddress(serverAddr_);
      client_->start(&clientConnectionSetupCB_, &clientConnectionCB_);
    });

    std::move(future).via(&clientEvb_).waitVia(&clientEvb_);
  }

  void TearDown() override {
    if (client_) {
      client_->close(folly::none);
    }
    clientEvb_.loop();
    server_->shutdown();
    server_ = nullptr;
    client_ = nullptr;
  }

 protected:
  std::shared_ptr<QuicServer> server_;
  folly::SocketAddress serverAddr_;
  NiceMock<MockConnectionSetupCallback> serverConnectionSetupCB_;
  NiceMock<MockConnectionCallback> serverConnectionCB_;
  std::shared_ptr<quic::QuicSocket> serverSocket_;
  folly::F14FastMap<quic::StreamId, std::unique_ptr<Stream>> streams_;

  std::shared_ptr<QuicClientTransport> client_;
  folly::EventBase clientEvb_;
  NiceMock<MockConnectionSetupCallback> clientConnectionSetupCB_;
  NiceMock<MockConnectionCallback> clientConnectionCB_;
};

TEST_F(QuicStreamAsyncTransportTest, ReadWrite) {
  expectNewServerStream();
  auto clientStream = createClient();
  EXPECT_CALL(clientStream->readCb, readEOF_()).WillOnce(Return());
  auto [promiseX, future] = folly::makePromiseContract<std::string>();
  auto promise = std::move(promiseX);
  EXPECT_CALL(clientStream->readCb, readDataAvailable_(_))
      .WillOnce(Invoke([&clientStream, &promise](auto len) mutable {
        promise.setValue(std::string(
            reinterpret_cast<char*>(clientStream->buf.data()), len));
      }));

  std::string msg = "yo yo!";
  EXPECT_CALL(clientStream->writeCb, writeSuccess_()).WillOnce(Return());
  clientStream->transport->write(
      &clientStream->writeCb, msg.data(), msg.size());
  clientStream->transport->shutdownWrite();

  EXPECT_EQ(
      std::move(future).via(&clientEvb_).getVia(&clientEvb_), "echo yo yo!");
}

TEST_F(QuicStreamAsyncTransportTest, TwoClients) {
  std::list<std::unique_ptr<Stream>> clientStreams;
  std::list<folly::SemiFuture<std::string>> futures;
  std::string msg = "yo yo!";
  for (auto i = 0; i < 2; i++) {
    expectNewServerStream();
    clientStreams.emplace_back(createClient());
    auto& clientStream = clientStreams.back();
    EXPECT_CALL(clientStream->readCb, readEOF_()).WillOnce(Return());
    auto [promiseX, future] = folly::makePromiseContract<std::string>();
    auto promise = std::move(promiseX);
    futures.emplace_back(std::move(future));
    EXPECT_CALL(clientStream->readCb, readDataAvailable_(_))
        .WillOnce(Invoke(
            [clientStream = clientStream.get(),
             p = folly::MoveWrapper(std::move(promise))](auto len) mutable {
              p->setValue(std::string(
                  reinterpret_cast<char*>(clientStream->buf.data()), len));
            }));

    EXPECT_CALL(clientStream->writeCb, writeSuccess_()).WillOnce(Return());
    clientStream->transport->write(
        &clientStream->writeCb, msg.data(), msg.size());
    clientStream->transport->shutdownWrite();
  }
  for (auto& future : futures) {
    EXPECT_EQ(
        std::move(future).via(&clientEvb_).getVia(&clientEvb_), "echo yo yo!");
  }
}

TEST_F(QuicStreamAsyncTransportTest, DelayedSetReadCB) {
  expectNewServerStream();
  auto clientStream = createClient(/*setReadCB=*/false);
  auto [promiseX, future] = folly::makePromiseContract<std::string>();
  auto promise = std::move(promiseX);
  EXPECT_CALL(clientStream->readCb, readDataAvailable_(_))
      .WillOnce(Invoke([&clientStream, &promise](auto len) mutable {
        promise.setValue(std::string(
            reinterpret_cast<char*>(clientStream->buf.data()), len));
      }));

  std::string msg = "yo yo!";
  EXPECT_CALL(clientStream->writeCb, writeSuccess_()).WillOnce(Return());
  clientStream->transport->write(
      &clientStream->writeCb, msg.data(), msg.size());
  clientEvb_.runAfterDelay(
      [&clientStream] {
        EXPECT_CALL(clientStream->readCb, readEOF_()).WillOnce(Return());
        clientStream->transport->setReadCB(&clientStream->readCb);
        clientStream->transport->shutdownWrite();
      },
      750);
  EXPECT_EQ(
      std::move(future).via(&clientEvb_).getVia(&clientEvb_), "echo yo yo!");
}

TEST_F(QuicStreamAsyncTransportTest, close) {
  auto clientStream = createClient(/*setReadCB=*/false);
  EXPECT_TRUE(client_->good());
  clientStream->transport->close();
  clientStream->transport.reset();
  EXPECT_TRUE(client_->good());
  clientEvb_.loopOnce();
}

TEST_F(QuicStreamAsyncTransportTest, closeNow) {
  auto clientStream = createClient(/*setReadCB=*/false);
  EXPECT_TRUE(client_->good());
  clientStream->transport->closeNow();
  clientStream->transport.reset();
  // The quic socket is still good
  EXPECT_TRUE(client_->good());
  clientEvb_.loopOnce();
}

} // namespace quic::test
