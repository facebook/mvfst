/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicTransportBase.h>
#include <quic/client/QuicClientTransportLite.h>

namespace quic {

class QuicClientTransport : public QuicTransportBase,
                            public QuicClientTransportLite {
 public:
  QuicClientTransport(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = 0,
      bool useConnectionEndWithErrorCallback = false)
      : QuicTransportBaseLite(
            evb,
            std::move(socket),
            useConnectionEndWithErrorCallback),
        QuicTransportBase(evb, nullptr, useConnectionEndWithErrorCallback),
        QuicClientTransportLite(
            evb,
            nullptr,
            std::move(handshakeFactory),
            connectionIdSize,
            useConnectionEndWithErrorCallback),
        wrappedObserverContainer_(this) {
    conn_->observerContainer = wrappedObserverContainer_.getWeakPtr();
  }

  // Testing only API:
  QuicClientTransport(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize,
      PacketNum startingPacketNum,
      bool useConnectionEndWithErrorCallback = false)
      : QuicTransportBaseLite(
            evb,
            std::move(socket),
            useConnectionEndWithErrorCallback),
        QuicTransportBase(
            evb,
            std::move(socket),
            useConnectionEndWithErrorCallback),
        QuicClientTransportLite(
            evb,
            std::move(socket),
            std::move(handshakeFactory),
            connectionIdSize,
            startingPacketNum,
            useConnectionEndWithErrorCallback),
        wrappedObserverContainer_(this) {
    conn_->observerContainer = wrappedObserverContainer_.getWeakPtr();
  }

  virtual ~QuicClientTransport() override;

  /**
   * Returns an un-connected QuicClientTransportLite which is self-owning.
   * The transport is cleaned up when the app calls close() or closeNow() on the
   * transport, or on receiving a terminal ConnectionCallback supplied on
   * start().
   * The transport is self owning in this case is to be able to
   * deal with cases where the app wants to dispose of the transport, however
   * the peer is still sending us packets. If we do not keep the transport alive
   * for this period, the kernel will generate unwanted ICMP echo messages.
   */
  template <class TransportType = QuicClientTransport>
  static std::shared_ptr<TransportType> newClient(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> sock,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = 0,
      bool useConnectionEndWithErrorCallback = false) {
    auto client = std::make_shared<TransportType>(
        evb,
        std::move(sock),
        std::move(handshakeFactory),
        connectionIdSize,
        useConnectionEndWithErrorCallback);
    client->setSelfOwning();
    return client;
  }

 protected:
  // From QuicSocket
  [[nodiscard]] virtual SocketObserverContainer* getSocketObserverContainer()
      const override {
    return wrappedObserverContainer_.getPtr();
  }

 private:
  // Container of observers for the socket / transport.
  //
  // This member MUST be last in the list of members to ensure it is destroyed
  // first, before any other members are destroyed. This ensures that observers
  // can inspect any socket / transport state available through public methods
  // when destruction of the transport begins.
  const WrappedSocketObserverContainer wrappedObserverContainer_;
};

} // namespace quic
