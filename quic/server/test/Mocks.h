/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicServerWorker.h>

namespace quic {

class MockQuicServerTransportFactory : public QuicServerTransportFactory {
 public:
  ~MockQuicServerTransportFactory() override {}

  // wrapper for mocked make since gmock doesn't support methods with rvalue ref
  QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      const folly::SocketAddress& addr,
      std::shared_ptr<const fizz::server::FizzServerContext>
          ctx) noexcept override {
    return _make(evb, socket, addr, ctx);
  }

  GMOCK_METHOD4_(
      ,
      noexcept,
      ,
      _make,
      QuicServerTransport::Ptr(
          folly::EventBase* evb,
          std::unique_ptr<folly::AsyncUDPSocket>& sock,
          const folly::SocketAddress&,
          std::shared_ptr<const fizz::server::FizzServerContext>));
};

class MockWorkerCallback : public QuicServerWorker::WorkerCallback {
 public:
  ~MockWorkerCallback() = default;
  MOCK_METHOD1(handleWorkerError, void(LocalErrorCode));

  MOCK_METHOD3(
      routeDataToWorkerLong,
      void(
          const folly::SocketAddress&,
          std::unique_ptr<RoutingData>&,
          std::unique_ptr<NetworkData>&));

  MOCK_METHOD3(
      routeDataToWorkerShort,
      void(
          const folly::SocketAddress&,
          std::unique_ptr<RoutingData>&,
          std::unique_ptr<NetworkData>&));

  void routeDataToWorker(
      const folly::SocketAddress& client,
      RoutingData&& routingDataIn,
      NetworkData&& networkDataIn) {
    auto routingData = std::make_unique<RoutingData>(std::move(routingDataIn));
    auto networkData = std::make_unique<NetworkData>(std::move(networkDataIn));
    if (routingData->headerForm == HeaderForm::Long) {
      routeDataToWorkerLong(client, routingData, networkData);
    } else {
      routeDataToWorkerShort(client, routingData, networkData);
    }
  }
};

class MockQuicUDPSocketFactory : public QuicUDPSocketFactory {
 public:
  ~MockQuicUDPSocketFactory() = default;
  std::unique_ptr<folly::AsyncUDPSocket> make(folly::EventBase* evb, int fd) {
    return std::unique_ptr<folly::AsyncUDPSocket>(_make(evb, fd));
  }
  MOCK_METHOD2(_make, folly::AsyncUDPSocket*(folly::EventBase*, int));
};

class MockRoutingCallback : public QuicServerTransport::RoutingCallback {
 public:
  ~MockRoutingCallback() override = default;

  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      onConnectionIdAvailable,
      void(QuicServerTransport::Ptr, ConnectionId));
  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      onConnectionIdBound,
      void(QuicServerTransport::Ptr));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      onConnectionUnbound,
      void(
          const QuicServerTransport::SourceIdentity&,
          folly::Optional<ConnectionId>));
};
} // namespace quic
