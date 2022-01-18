/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <iostream>
#include <string>
#include <thread>

#include <glog/logging.h>

#include <folly/fibers/Baton.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <quic/api/QuicSocket.h>
#include <quic/client/QuicClientTransport.h>
#include <quic/common/BufUtil.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/samples/echo/LogQuicStats.h>

namespace quic {
namespace samples {
class EchoClient : public quic::QuicSocket::ConnectionCallback,
                   public quic::QuicSocket::ReadCallback,
                   public quic::QuicSocket::WriteCallback {
 public:
  EchoClient(const std::string& host, uint16_t port)
      : host_(host), port_(port) {}

  void readAvailable(quic::StreamId streamId) noexcept override {
    auto readData = quicClient_->read(streamId, 0);
    if (readData.hasError()) {
      LOG(ERROR) << "EchoClient failed read from stream=" << streamId
                 << ", error=" << (uint32_t)readData.error();
    }
    auto copy = readData->first->clone();
    if (recvOffsets_.find(streamId) == recvOffsets_.end()) {
      recvOffsets_[streamId] = copy->length();
    } else {
      recvOffsets_[streamId] += copy->length();
    }
    LOG(INFO) << "Client received data=" << copy->moveToFbString().toStdString()
              << " on stream=" << streamId;
  }

  void readError(
      quic::StreamId streamId,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
          error) noexcept override {
    LOG(ERROR) << "EchoClient failed read from stream=" << streamId
               << ", error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "EchoClient: new bidirectional stream=" << id;
    quicClient_->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "EchoClient: new unidirectional stream=" << id;
    quicClient_->setReadCallback(id, this);
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode /*error*/) noexcept override {
    VLOG(10) << "EchoClient got StopSending stream id=" << id;
  }

  void onConnectionEnd() noexcept override {
    LOG(INFO) << "EchoClient connection end";
  }

  void onConnectionSetupError(
      std::pair<quic::QuicErrorCode, std::string> error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(
      std::pair<quic::QuicErrorCode, std::string> error) noexcept override {
    LOG(ERROR) << "EchoClient error: " << toString(error.first)
               << "; errStr=" << error.second;
    startDone_.post();
  }

  void onTransportReady() noexcept override {
    startDone_.post();
  }

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    LOG(INFO) << "EchoClient socket is write ready with maxToSend="
              << maxToSend;
    sendMessage(id, pendingOutput_[id]);
  }

  void onStreamWriteError(
      quic::StreamId id,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
          error) noexcept override {
    LOG(ERROR) << "EchoClient write error with stream=" << id
               << " error=" << toString(error);
  }

  void start() {
    folly::ScopedEventBaseThread networkThread("EchoClientThread");
    auto evb = networkThread.getEventBase();
    folly::SocketAddress addr(host_.c_str(), port_);

    evb->runInEventBaseThreadAndWait([&] {
      auto sock = std::make_unique<folly::AsyncUDPSocket>(evb);
      auto fizzClientContext =
          FizzClientQuicHandshakeContext::Builder()
              .setCertificateVerifier(test::createTestCertificateVerifier())
              .build();
      quicClient_ = std::make_shared<quic::QuicClientTransport>(
          evb, std::move(sock), std::move(fizzClientContext));
      quicClient_->setHostname("echo.com");
      quicClient_->addNewPeerAddress(addr);

      TransportSettings settings;
      quicClient_->setTransportSettings(settings);

      quicClient_->setTransportStatsCallback(
          std::make_shared<LogQuicStats>("client"));

      LOG(INFO) << "EchoClient connecting to " << addr.describe();
      quicClient_->start(this);
    });

    startDone_.wait();

    std::string message;
    auto client = quicClient_;
    // loop until Ctrl+D
    while (std::getline(std::cin, message)) {
      if (message.empty()) {
        continue;
      }
      evb->runInEventBaseThreadAndWait([=] {
        // create new stream for each message
        auto streamId = client->createBidirectionalStream().value();
        client->setReadCallback(streamId, this);
        pendingOutput_[streamId].append(folly::IOBuf::copyBuffer(message));
        sendMessage(streamId, pendingOutput_[streamId]);
      });
    }
    LOG(INFO) << "EchoClient stopping client";
  }

  ~EchoClient() override = default;

 private:
  void sendMessage(quic::StreamId id, BufQueue& data) {
    auto message = data.move();
    auto res = quicClient_->writeChain(id, message->clone(), true);
    if (res.hasError()) {
      LOG(ERROR) << "EchoClient writeChain error=" << uint32_t(res.error());
    } else {
      auto str = message->moveToFbString().toStdString();
      LOG(INFO) << "EchoClient wrote \"" << str << "\""
                << ", len=" << str.size() << " on stream=" << id;
      // sent whole message
      pendingOutput_.erase(id);
    }
  }

  std::string host_;
  uint16_t port_;
  std::shared_ptr<quic::QuicClientTransport> quicClient_;
  std::map<quic::StreamId, BufQueue> pendingOutput_;
  std::map<quic::StreamId, uint64_t> recvOffsets_;
  folly::fibers::Baton startDone_;
};
} // namespace samples
} // namespace quic
