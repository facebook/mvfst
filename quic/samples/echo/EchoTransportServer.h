/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Synchronized.h>
#include <glog/logging.h>

#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/server/QuicServerTransport.h>

#include <quic/samples/echo/EchoHandler.h>

#include <utility>

namespace quic::samples {

class UDPAcceptor : public folly::AsyncUDPSocket::ReadCallback {
 public:
  explicit UDPAcceptor(
      folly::EventBase* evb,
      std::shared_ptr<folly::AsyncUDPSocket> socket)
      : evb_(evb),
        qEvb_(std::make_shared<FollyQuicEventBase>(evb_)),
        socket_(std::move(socket)) {}

  void getReadBuffer(void** buf, size_t* len) noexcept override {
    readBuffer_ = folly::IOBuf::create(quic::kDefaultUDPReadBufferSize);
    *buf = readBuffer_->writableData();
    *len = quic::kDefaultUDPReadBufferSize;
  }

  void onDataAvailable(
      const folly::SocketAddress& client,
      size_t len,
      bool /*truncated*/,
      OnDataAvailableParams) noexcept override {
    readBuffer_->append(len);

    auto packetReceiveTime = quic::Clock::now();

    if (!transport_ || !transport_->good()) {
      quicHandler_ = std::make_shared<EchoHandler>(evb_);

      auto fizzServerCtx = quic::test::createServerCtx();
      fizzServerCtx->setClock(std::make_shared<fizz::SystemClock>());

      auto follySharedSocket = std::make_unique<FollyAsyncUDPSocketAlias>(evb_);

      auto sockFD = socket_->getNetworkSocket();
      if (sockFD.toFd() != -1) {
        follySharedSocket->setFD(
            sockFD, FollyAsyncUDPSocketAlias::FDOwnership::SHARED);
        follySharedSocket->setDFAndTurnOffPMTU();
      }

      transport_ = quic::QuicServerTransport::make(
          qEvb_->getBackingEventBase(),
          std::move(follySharedSocket),
          quicHandler_.get(),
          quicHandler_.get(),
          fizzServerCtx);

      quicHandler_->setQuicSocket(transport_);

      transport_->setConnectionIdAlgo(new quic::DefaultConnectionIdAlgo());

      transport_->setServerConnectionIdParams(
          quic::ServerConnectionIdParams(1, 1, 0));

      quic::TransportSettings transportSettings;
      std::array<uint8_t, quic::kStatelessResetTokenSecretLength> secret;
      folly::Random::secureRandom(secret.data(), secret.size());
      transportSettings.statelessResetTokenSecret = secret;

      transport_->setTransportSettings(transportSettings);

      transport_->setClientConnectionId(
          quic::ConnectionId(std::vector<uint8_t>{}));

      transport_->setOriginalPeerAddress(client);

      transport_->accept();
    }

    ReceivedUdpPacket packet(std::move(readBuffer_));
    packet.timings.receiveTimePoint = packetReceiveTime;
    quic::NetworkData networkData(std::move(packet));

    transport_->onNetworkData(client, std::move(networkData));
  }

  void onReadError(const folly::AsyncSocketException& ex) noexcept override {
    LOG(INFO) << "onReadError " << ex.what();
  }

  void onReadClosed() noexcept override {
    LOG(INFO) << "onReadClosed";
  }

 private:
  folly::EventBase* evb_;
  std::shared_ptr<FollyQuicEventBase> qEvb_;
  std::shared_ptr<folly::AsyncUDPSocket> socket_;
  std::shared_ptr<EchoHandler> quicHandler_;
  std::shared_ptr<quic::QuicServerTransport> transport_;
  std::unique_ptr<folly::IOBuf> readBuffer_;
};

class EchoTransportServer {
 public:
  explicit EchoTransportServer(std::string host = "::1", uint16_t port = 6666)
      : host_(std::move(host)), port_(port) {}

  void start() {
    auto socket = std::make_shared<folly::AsyncUDPSocket>(&eventbase_);
    UDPAcceptor udpAcceptor(&eventbase_, socket);
    socket->bind(folly::SocketAddress(host_, port_));
    socket->resumeRead(&udpAcceptor);

    LOG(INFO) << "Echo transport server started at: " << socket->address();
    eventbase_.loopForever();
  }

 private:
  std::string host_;
  uint16_t port_;
  folly::EventBase eventbase_;
};

} // namespace quic::samples
