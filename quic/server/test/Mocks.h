/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>

#include <quic/common/QuicAsyncUDPSocketWrapper.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicServerWorker.h>
#include <quic/server/state/ServerConnectionIdRejector.h>

namespace quic {

class MockServerConnectionIdRejector : public ServerConnectionIdRejector {
 public:
  MOCK_METHOD(
      (bool),
      rejectConnectionIdNonConst,
      (const ConnectionId),
      (noexcept));

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
      std::unique_ptr<QuicAsyncUDPSocketWrapper> socket,
      const folly::SocketAddress& addr,
      QuicVersion,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept
      override {
    return _make(evb, socket, addr, ctx);
  }

  MOCK_METHOD(
      (QuicServerTransport::Ptr),
      _make,
      (folly::EventBase*,
       std::unique_ptr<QuicAsyncUDPSocketWrapper>&,
       const folly::SocketAddress&,
       std::shared_ptr<const fizz::server::FizzServerContext>),
      (noexcept));
};

class MockWorkerCallback : public QuicServerWorker::WorkerCallback {
 public:
  ~MockWorkerCallback() = default;
  MOCK_METHOD(void, handleWorkerError, (LocalErrorCode));

  MOCK_METHOD(
      void,
      routeDataToWorkerLong,
      (const folly::SocketAddress&,
       std::unique_ptr<RoutingData>&,
       std::unique_ptr<NetworkData>&,
       folly::Optional<QuicVersion>,
       bool isForwardedData));

  MOCK_METHOD(
      void,
      routeDataToWorkerShort,
      (const folly::SocketAddress&,
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
  std::unique_ptr<QuicAsyncUDPSocketWrapper> make(folly::EventBase* evb, int fd)
      override {
    return std::unique_ptr<QuicAsyncUDPSocketWrapper>(_make(evb, fd));
  }
  MOCK_METHOD(QuicAsyncUDPSocketWrapper*, _make, (folly::EventBase*, int));
};

class MockRoutingCallback : public QuicServerTransport::RoutingCallback {
 public:
  ~MockRoutingCallback() override = default;

  MOCK_METHOD(
      (void),
      onConnectionIdAvailable,
      (QuicServerTransport::Ptr, ConnectionId),
      (noexcept));
  MOCK_METHOD(
      (void),
      onConnectionIdRetired,
      (QuicServerTransport::Ref, ConnectionId),
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
};

class MockHandshakeFinishedCallback
    : public QuicServerTransport::HandshakeFinishedCallback {
 public:
  ~MockHandshakeFinishedCallback() override = default;

  MOCK_METHOD((void), onHandshakeFinished, (), (noexcept));
  MOCK_METHOD((void), onHandshakeUnfinished, (), (noexcept));
};

class MockQuicServerTransport : public QuicServerTransport {
 public:
  MockQuicServerTransport(
      folly::EventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> socket)
      : QuicServerTransport(evb, std::move(socket), nullptr, nullptr, nullptr) {
  }
  MOCK_CONST_METHOD0(getOneRttCipherInfo, CipherInfo());
  MOCK_CONST_METHOD0(getServerConnectionId, folly::Optional<ConnectionId>());
  MOCK_CONST_METHOD0(getClientConnectionId, folly::Optional<ConnectionId>());
  MOCK_CONST_METHOD0(getPeerAddress, folly::SocketAddress&());
};

} // namespace quic
