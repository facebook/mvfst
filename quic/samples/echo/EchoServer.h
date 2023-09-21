/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Synchronized.h>
#include <glog/logging.h>

#include <quic/common/test/TestUtils.h>
#include <quic/samples/echo/EchoHandler.h>
#include <quic/samples/echo/LogQuicStats.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>

namespace quic {
namespace samples {

class EchoServerTransportFactory : public quic::QuicServerTransportFactory {
 public:
  ~EchoServerTransportFactory() override {
    draining_ = true;
    echoHandlers_.withWLock([](auto& echoHandlers) {
      while (!echoHandlers.empty()) {
        auto& handler = echoHandlers.back();
        handler->getEventBase()->runImmediatelyOrRunInEventBaseThreadAndWait(
            [&] {
              // The evb should be performing a sequential consistency atomic
              // operation already, so we can bank on that to make sure the
              // writes propagate to all threads.
              echoHandlers.pop_back();
            });
      }
    });
  }

  explicit EchoServerTransportFactory(
      bool useDatagrams = false,
      bool disableRtx = false)
      : useDatagrams_(useDatagrams), disableRtx_(disableRtx) {}

  quic::QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> sock,
      const folly::SocketAddress&,
      QuicVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
      override {
    CHECK_EQ(evb, sock->getEventBase());
    if (draining_) {
      return nullptr;
    }
    auto echoHandler =
        std::make_unique<EchoHandler>(evb, useDatagrams_, disableRtx_);
    auto transport = quic::QuicServerTransport::make(
        evb, std::move(sock), echoHandler.get(), echoHandler.get(), ctx);
    echoHandler->setQuicSocket(transport);
    echoHandlers_.withWLock([&](auto& echoHandlers) {
      echoHandlers.push_back(std::move(echoHandler));
    });
    return transport;
  }

 private:
  bool useDatagrams_;
  folly::Synchronized<std::vector<std::unique_ptr<EchoHandler>>> echoHandlers_;
  bool draining_{false};
  bool disableRtx_{false};
};

class EchoServer {
 public:
  explicit EchoServer(
      const std::string& host = "::1",
      uint16_t port = 6666,
      bool useDatagrams = false,
      uint64_t activeConnIdLimit = 10,
      bool enableMigration = true,
      bool enableStreamGroups = false,
      bool disableRtx = false)
      : host_(host), port_(port), server_(QuicServer::createQuicServer()) {
    server_->setQuicServerTransportFactory(
        std::make_unique<EchoServerTransportFactory>(useDatagrams, disableRtx));
    server_->setTransportStatsCallbackFactory(
        std::make_unique<LogQuicStatsFactory>());
    auto serverCtx = quic::test::createServerCtx();
    serverCtx->setClock(std::make_shared<fizz::SystemClock>());
    server_->setFizzContext(serverCtx);

    auto settingsCopy = server_->getTransportSettings();
    settingsCopy.datagramConfig.enabled = useDatagrams;
    settingsCopy.selfActiveConnectionIdLimit = activeConnIdLimit;
    settingsCopy.disableMigration = !enableMigration;
    if (enableStreamGroups) {
      settingsCopy.notifyOnNewStreamsExplicitly = true;
      settingsCopy.advertisedMaxStreamGroups = 1024;
    }
    if (disableRtx) {
      if (!enableStreamGroups) {
        LOG(FATAL) << "disable_rtx requires use_stream_groups to be enabled";
      }
    }
    server_->setTransportSettings(std::move(settingsCopy));
  }

  ~EchoServer() {
    server_->shutdown();
  }

  void start() {
    // Create a SocketAddress and the default or passed in host.
    folly::SocketAddress addr1(host_.c_str(), port_);
    addr1.setFromHostPort(host_, port_);
    server_->start(addr1, 0);
    LOG(INFO) << "Echo server started at: " << addr1.describe();
    eventbase_.loopForever();
  }

 private:
  std::string host_;
  uint16_t port_;
  folly::EventBase eventbase_;
  std::shared_ptr<quic::QuicServer> server_;
};
} // namespace samples
} // namespace quic
