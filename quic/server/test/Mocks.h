/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>

#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicServerWorker.h>
#include <quic/server/state/ServerConnectionIdRejector.h>

namespace quic {

class MockServerConnectionIdRejector : public ServerConnectionIdRejector {
 public:
#if defined(MOCK_METHOD)
  MOCK_METHOD(
      (bool),
      rejectConnectionIdNonConst,
      (const ConnectionId),
      (noexcept));
#else
  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      rejectConnectionIdNonConst,
      bool(const ConnectionId));
#endif

  bool rejectConnectionId(const ConnectionId& id) const noexcept override {
    return const_cast<MockServerConnectionIdRejector&>(*this)
        .rejectConnectionIdNonConst(id);
  }
};

class MockQuicServerTransportFactory : public QuicServerTransportFactory {
 public:
  ~MockQuicServerTransportFactory() override {}

  // wrapper for mocked make since gmock doesn't support methods with rvalue ref
  QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      const folly::SocketAddress& addr,
      QuicVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
      override {
    return _make(evb, socket, addr, ctx);
  }

#if defined(MOCK_METHOD)
  MOCK_METHOD(
      (QuicServerTransport::Ptr),
      _make,
      (folly::EventBase*,
       std::unique_ptr<folly::AsyncUDPSocket>&,
       const folly::SocketAddress&,
       std::shared_ptr<const fizz::server::FizzServerContext>),
      (noexcept));
#else
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
#endif
};

class MockWorkerCallback : public QuicServerWorker::WorkerCallback {
 public:
  ~MockWorkerCallback() = default;
  MOCK_METHOD1(handleWorkerError, void(LocalErrorCode));

  MOCK_METHOD5(
      routeDataToWorkerLong,
      void(
          const folly::SocketAddress&,
          std::unique_ptr<RoutingData>&,
          std::unique_ptr<NetworkData>&,
          folly::Optional<QuicVersion>,
          bool isForwardedData));

  MOCK_METHOD5(
      routeDataToWorkerShort,
      void(
          const folly::SocketAddress&,
          std::unique_ptr<RoutingData>&,
          std::unique_ptr<NetworkData>&,
          folly::Optional<QuicVersion>,
          bool isForwardedData));

  void routeDataToWorker(
      const folly::SocketAddress& client,
      RoutingData&& routingDataIn,
      NetworkData&& networkDataIn,
      folly::Optional<QuicVersion> quicVersion,
      bool isForwardedData = false) {
    auto routingData = std::make_unique<RoutingData>(std::move(routingDataIn));
    auto networkData = std::make_unique<NetworkData>(std::move(networkDataIn));
    if (routingData->headerForm == HeaderForm::Long) {
      routeDataToWorkerLong(
          client, routingData, networkData, quicVersion, isForwardedData);
    } else {
      routeDataToWorkerShort(
          client, routingData, networkData, quicVersion, isForwardedData);
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

#if defined(MOCK_METHOD)
  MOCK_METHOD(
      (void),
      onConnectionIdAvailable,
      (QuicServerTransport::Ptr, ConnectionId),
      (noexcept));
  MOCK_METHOD(
      (void),
      onConnectionIdBound,
      (QuicServerTransport::Ptr),
      (noexcept));
  MOCK_METHOD(
      (void),
      onConnectionUnbound,
      (QuicServerTransport*,
       const QuicServerTransport::SourceIdentity&,
       const std::vector<ConnectionIdData>&),
      (noexcept));
#else
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
  GMOCK_METHOD3_(
      ,
      noexcept,
      ,
      onConnectionUnbound,
      void(
          QuicServerTransport*,
          const QuicServerTransport::SourceIdentity&,
          const std::vector<ConnectionIdData>& connIdData));
#endif
};

class MockHandshakeFinishedCallback
    : public QuicServerTransport::HandshakeFinishedCallback {
 public:
  ~MockHandshakeFinishedCallback() override = default;

#if defined(MOCK_METHOD)
  MOCK_METHOD((void), onHandshakeFinished, (), (noexcept));
  MOCK_METHOD((void), onHandshakeUnfinished, (), (noexcept));
#else
  GMOCK_METHOD0_(, noexcept, , onHandshakeFinished, void());
  GMOCK_METHOD0_(, noexcept, , onHandshakeUnfinished, void());
#endif
};

} // namespace quic
