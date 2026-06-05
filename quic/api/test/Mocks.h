/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/test/ApiMocks.h>

#include <folly/portability/GMock.h>

#include <quic/common/NetworkData.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/events/QuicTimer.h>
#include <quic/server/QuicServerTransport.h>

namespace quic {

class MockQuicTransport : public QuicServerTransport {
 public:
  using Ptr = std::shared_ptr<MockQuicTransport>;

  class RoutingCallback : public QuicServerTransport::RoutingCallback {
   public:
    ~RoutingCallback() override = default;

    // Called when a connection id is available
    void onConnectionIdAvailable(
        QuicServerTransport::Ptr transport,
        ConnectionId id) noexcept override = 0;

    // Called when a connection id is bound and ip address should not
    // be used any more for routing.
    void onConnectionIdBound(
        QuicServerTransport::Ptr transport) noexcept override = 0;

    // Called when the connection is finished and needs to be Unbound.
    void onConnectionUnbound(
        QuicServerTransport*,
        const QuicServerTransport::SourceIdentity& address,
        const std::vector<ConnectionIdData>& connectionIdData) noexcept
        override = 0;
  };

  MockQuicTransport(
      std::shared_ptr<FollyQuicEventBase> evb,
      std::unique_ptr<FollyQuicAsyncUDPSocket> sock,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx)
      : QuicTransportBaseLite(evb, std::move(sock)),
        QuicServerTransport(
            std::move(evb),
            nullptr /* Initialized through the QuicTransportBaseLite constructor
                     */
            ,
            connSetupCb,
            connCb,
            ctx) {}

  ~MockQuicTransport() override {
    customDestructor();
  }

  MOCK_METHOD(void, customDestructor, ());
  MOCK_METHOD(const quic::SocketAddress&, getPeerAddress, (), (const));
  MOCK_METHOD(const quic::SocketAddress&, getOriginalPeerAddress, (), (const));

  MOCK_METHOD((std::shared_ptr<QuicEventBase>), getEventBase, (), (const));
  MOCK_METHOD((void), accept, (folly::Optional<QuicVersion>), ());
  MOCK_METHOD((void), setTransportSettings, (TransportSettings), ());
  MOCK_METHOD((void), setOriginalPeerAddress, (const quic::SocketAddress&));
  MOCK_METHOD((void), setPacingTimer, (QuicTimer::SharedPtr), (noexcept));
  MOCK_METHOD(
      (void),
      onNetworkData,
      (const quic::SocketAddress&, const NetworkData&),
      (noexcept));
  MOCK_METHOD(
      (void),
      setRoutingCallback,
      (QuicServerTransport::RoutingCallback*),
      (noexcept));
  MOCK_METHOD(
      (void),
      setHandshakeFinishedCallback,
      (QuicServerTransport::HandshakeFinishedCallback*),
      (noexcept));
  MOCK_METHOD(
      (void),
      setSupportedVersions,
      (const std::vector<QuicVersion>&),
      (noexcept));
  MOCK_METHOD(
      (void),
      setServerConnectionIdParams,
      (ServerConnectionIdParams),
      (noexcept));
  MOCK_METHOD((void), close, (Optional<QuicError>), (noexcept));
  MOCK_METHOD((void), closeNow, (Optional<QuicError>), (noexcept));
  MOCK_METHOD((bool), hasShutdown, (), (const));
  MOCK_METHOD((Optional<ConnectionId>), getClientConnectionId, (), (const));
  MOCK_METHOD(
      (Optional<ConnectionId>),
      getClientChosenDestConnectionId,
      (),
      (const));
  MOCK_METHOD(
      (void),
      setTransportStatsCallback,
      (QuicTransportStatsCallback*),
      (noexcept));
  MOCK_METHOD((void), setConnectionIdAlgo, (ConnectionIdAlgo*), (noexcept));

  void onNetworkData(
      const quic::SocketAddress& localAddress,
      NetworkData&& networkData) noexcept override {
    onNetworkData(localAddress, networkData);
  }

  MOCK_METHOD(void, setBufAccessor, (BufAccessor*));

  MOCK_METHOD(void, addPacketProcessor, (std::shared_ptr<PacketProcessor>));
};

inline std::ostream& operator<<(std::ostream& os, const MockQuicTransport&) {
  return os;
}

} // namespace quic
