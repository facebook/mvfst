/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicTransportBase.h>
#include <quic/client/QuicClientTransportLite.h>
#include <quic/common/Expected.h>

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
        happyEyeballsConnAttemptDelayTimeout_(this),
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
        happyEyeballsConnAttemptDelayTimeout_(this),
        wrappedObserverContainer_(this) {
    conn_->observerContainer = wrappedObserverContainer_.getWeakPtr();
  }

  ~QuicClientTransport() override;

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

  void onNotifyDataAvailable(QuicAsyncUDPSocket& sock) noexcept override;

  /**
   * Happy Eyeballs support: Add a new socket for connection attempts.
   */
  void addNewSocket(std::unique_ptr<QuicAsyncUDPSocket> socket);

  /**
   * Happy Eyeballs support: Enable/disable Happy Eyeballs behavior.
   */
  void setHappyEyeballsEnabled(bool happyEyeballsEnabled);

  /**
   * Happy Eyeballs support: Set cached address family preference.
   */
  virtual void setHappyEyeballsCachedFamily(sa_family_t cachedFamily);

  class HappyEyeballsConnAttemptDelayTimeout : public QuicTimerCallback {
   public:
    explicit HappyEyeballsConnAttemptDelayTimeout(
        QuicClientTransport* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->happyEyeballsConnAttemptDelayTimeoutExpired();
    }

    void callbackCanceled() noexcept override {}

   private:
    QuicClientTransport* transport_;
  };

 protected:
  // From QuicSocket
  [[nodiscard]] SocketObserverContainer* getSocketObserverContainer()
      const override {
    return wrappedObserverContainer_.getPtr();
  }

  [[nodiscard]] quic::Expected<void, QuicError> readWithRecvmmsgWrapper(
      QuicAsyncUDPSocket& sock,
      uint64_t readBufferSize,
      uint16_t numPackets);

  [[nodiscard]] quic::Expected<void, QuicError> readWithRecvmmsg(
      QuicAsyncUDPSocket& sock,
      uint64_t readBufferSize,
      uint16_t numPackets);

  [[nodiscard]] quic::Expected<void, QuicError> readWithRecvmsg(
      QuicAsyncUDPSocket& sock,
      uint64_t readBufferSize,
      uint16_t numPackets);

  [[nodiscard]] quic::Expected<void, QuicError> recvMmsg(
      QuicAsyncUDPSocket& sock,
      uint64_t readBufferSize,
      uint16_t numPackets,
      NetworkData& networkData,
      Optional<folly::SocketAddress>& server,
      size_t& totalData);

  // Happy Eyeballs virtual method overrides
  void happyEyeballsConnAttemptDelayTimeoutExpired() noexcept override;

  void cleanupHappyEyeballsState() override;

  void startHappyEyeballsIfEnabled() override;

  void happyEyeballsOnDataReceivedIfEnabled(
      const folly::SocketAddress& peerAddress) override;

  void cancelHappyEyeballsConnAttemptDelayTimeout() override;

  [[nodiscard]] bool happyEyeballsAddPeerAddressIfEnabled(
      const folly::SocketAddress& peerAddress) override;

 protected:
  // Happy Eyeballs state
  HappyEyeballsConnAttemptDelayTimeout happyEyeballsConnAttemptDelayTimeout_;
  bool happyEyeballsEnabled_{false};
  sa_family_t happyEyeballsCachedFamily_{AF_UNSPEC};

  // TODO(bschlinker): Deprecate in favor of Wrapper::recvmmsg
  struct RecvmmsgStorage {
    struct impl_ {
      struct sockaddr_storage addr;
      struct iovec iovec;
      // Buffers we pass to recvmmsg.
      BufPtr readBuffer;
    };

    // Storage for the recvmmsg system call.
    std::vector<struct mmsghdr> msgs;
    std::vector<struct impl_> impl_;
    void resize(size_t numPackets);
  };

  // TODO(bschlinker): Deprecate in favor of Wrapper::recvmmsg
  RecvmmsgStorage recvmmsgStorage_;

  // Container of observers for the socket / transport.
  //
  // This member MUST be last in the list of members to ensure it is destroyed
  // first, before any other members are destroyed. This ensures that observers
  // can inspect any socket / transport state available through public methods
  // when destruction of the transport begins.
  const WrappedSocketObserverContainer wrappedObserverContainer_;
};

} // namespace quic
