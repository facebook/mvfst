/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Random.h>
#include <folly/SocketAddress.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/net/NetOps.h>
#include <quic/api/QuicTransportBase.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/BufUtil.h>
#include <quic/common/QuicAsyncUDPSocketWrapper.h>
#include <quic/state/QuicConnectionStats.h>

namespace quic {

class ClientHandshakeFactory;

class QuicClientTransport
    : public QuicTransportBase,
      public QuicAsyncUDPSocketWrapper::ReadCallback,
      public QuicAsyncUDPSocketWrapper::ErrMessageCallback,
      public std::enable_shared_from_this<QuicClientTransport> {
 public:
  QuicClientTransport(
      QuicBackingEventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = 0,
      bool useConnectionEndWithErrorCallback = false);

  // Testing only API:
  QuicClientTransport(
      QuicBackingEventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize,
      PacketNum startingPacketNum,
      bool useConnectionEndWithErrorCallback = false);

  ~QuicClientTransport() override;

  /**
   * Returns an un-connected QuicClientTransport which is self-owning.
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
      folly::EventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> sock,
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

  /**
   * Supply the hostname to use to validate the server. Must be set before
   * start().
   */
  void setHostname(const std::string& hostname);

  /**
   * Supplies a new peer address to use for the connection. This must be called
   * at least once before start().
   */
  void addNewPeerAddress(folly::SocketAddress peerAddress);
  /**
   * Supplies the local address to use for the connection. Calling this is
   * optional. If not called, INADDR_ANY will be used.
   */
  void setLocalAddress(folly::SocketAddress localAddress);
  void addNewSocket(std::unique_ptr<QuicAsyncUDPSocketWrapper> socket);
  void setHappyEyeballsEnabled(bool happyEyeballsEnabled);
  virtual void setHappyEyeballsCachedFamily(sa_family_t cachedFamily);

  /**
   * Starts the connection.
   */
  virtual void start(
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connCb);

  /**
   * Returns whether or not TLS is resumed.
   */
  bool isTLSResumed() const;

  enum class ZeroRttAttemptState : uint8_t {
    NotAttempted = 0,
    Accepted,
    Rejected
  };
  /**
   * Returns the state of the 0RTT attempt if there was one.
   */
  ZeroRttAttemptState getZeroRttState() {
    if (!clientConn_->zeroRttRejected.has_value()) {
      return ZeroRttAttemptState::NotAttempted;
    }
    return *clientConn_->zeroRttRejected ? ZeroRttAttemptState::Rejected
                                         : ZeroRttAttemptState::Accepted;
  }

  // From QuicTransportBase
  void onReadData(
      const folly::SocketAddress& peer,
      NetworkDataSingle&& networkData) override;
  void writeData() override;
  void closeTransport() override;
  void unbindConnection() override;
  bool hasWriteCipher() const override;
  std::shared_ptr<QuicTransportBase> sharedGuard() override;

  // QuicAsyncUDPSocketWrapper::ReadCallback
  void onReadClosed() noexcept override {}
  void onReadError(const folly::AsyncSocketException&) noexcept override;

  // QuicAsyncUDPSocketWrapper::ErrMessageCallback
  void errMessage(const cmsghdr& cmsg) noexcept override;
  void errMessageError(const folly::AsyncSocketException&) noexcept override {}

  void setSupportedVersions(const std::vector<QuicVersion>& versions) override;

  /**
   * Set socket options for the underlying socket.
   * Options are being set before and after bind, and not at the time of
   * invoking this function.
   */
  void setSocketOptions(const folly::SocketOptionMap& options) noexcept {
    socketOptions_ = options;
  }

  /**
   * Make QuicClient transport self owning.
   */
  void setSelfOwning();

  void onNetworkSwitch(
      std::unique_ptr<QuicAsyncUDPSocketWrapper> newSock) override;

  /**
   * Set callback for various transport stats (such as packet received, dropped
   * etc). Since the callback is invoked very frequently, it is
   * important that the implementation is efficient.
   */
  void setTransportStatsCallback(
      std::shared_ptr<QuicTransportStatsCallback> statsCallback) noexcept;

  /**
   * Set a callback function to be invoked and passed
   * the new token upon receiving a NEW_TOKEN (0x07) frame.
   */
  void setNewTokenCallback(
      std::function<void(std::string)> newTokenCallback) noexcept {
    newTokenCallback_ = std::move(newTokenCallback);
  }

  /**
   * Set a new token to be included in the initial packet. Must be set before
   * attempting to connect.
   */
  void setNewToken(std::string token) noexcept {
    clientConn_->newToken = std::move(token);
  }

  void createBufAccessor(size_t capacity) override {
    bufAccessor_ = std::make_unique<SimpleBufAccessor>(capacity);
    conn_->bufAccessor = bufAccessor_.get();
  }

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
  SocketObserverContainer* getSocketObserverContainer() const override {
    return wrappedObserverContainer_.getPtr();
  }

  // From QuicAsyncUDPSocketWrapper::ReadCallback
  void getReadBuffer(void** buf, size_t* len) noexcept override;
  void onDataAvailable(
      const folly::SocketAddress& server,
      size_t len,
      bool truncated,
      OnDataAvailableParams params) noexcept override;
  bool shouldOnlyNotify() override;
  void onNotifyDataAvailable(QuicAsyncUDPSocketWrapper& sock) noexcept override;

  void recvMsg(
      QuicAsyncUDPSocketType& sock,
      uint64_t readBufferSize,
      int numPackets,
      NetworkData& networkData,
      folly::Optional<folly::SocketAddress>& server,
      size_t& totalData);
  void recvMmsg(
      QuicAsyncUDPSocketType& sock,
      uint64_t readBufferSize,
      uint16_t numPackets,
      NetworkData& networkData,
      folly::Optional<folly::SocketAddress>& server,
      size_t& totalData);

  void processUDPData(
      const folly::SocketAddress& peer,
      NetworkDataSingle&& networkData);

  void processPacketData(
      const folly::SocketAddress& peer,
      TimePoint receiveTimePoint,
      BufQueue& packetQueue);

  void startCryptoHandshake();

  void happyEyeballsConnAttemptDelayTimeoutExpired() noexcept;

  void handleAckFrame(
      const OutstandingPacketWrapper& outstandingPacket,
      const QuicWriteFrame& packetFrame,
      const ReadAckFrame&);

  folly::Optional<std::string> hostname_;
  HappyEyeballsConnAttemptDelayTimeout happyEyeballsConnAttemptDelayTimeout_;

 private:
  // TODO(bschlinker): Deprecate in favor of Wrapper::recvmmsg
  struct RecvmmsgStorage {
    struct impl_ {
      struct sockaddr_storage addr;
      struct iovec iovec;
      // Buffers we pass to recvmmsg.
      Buf readBuffer;
    };

    // Storage for the recvmmsg system call.
    std::vector<struct mmsghdr> msgs;
    std::vector<struct impl_> impl_;
    void resize(size_t numPackets);
  };

  void setSupportedExtensionTransportParameters();
  void adjustGROBuffers();
  void trackDatagramReceived(size_t len);

  /**
   * Send quic transport knobs defined by transportSettings.knobs to peer. This
   * calls setKnobs() internally.
   */
  void maybeSendTransportKnobs();

  void maybeEnableStreamGroups();

  bool replaySafeNotified_{false};
  // Set it QuicClientTransport is in a self owning mode. This will be cleaned
  // up when the caller invokes a terminal call to the transport.
  std::shared_ptr<QuicClientTransport> selfOwning_;
  bool happyEyeballsEnabled_{false};
  sa_family_t happyEyeballsCachedFamily_{AF_UNSPEC};
  QuicClientConnectionState* clientConn_;
  std::vector<TransportParameter> customTransportParameters_;
  folly::SocketOptionMap socketOptions_;
  std::shared_ptr<QuicTransportStatsCallback> statsCallback_;
  // Same value as conn_->transportSettings.numGROBuffers_ if the kernel
  // supports GRO. otherwise kDefaultNumGROBuffers
  uint32_t numGROBuffers_{kDefaultNumGROBuffers};
  // TODO(bschlinker): Deprecate in favor of Wrapper::recvmmsg
  RecvmmsgStorage recvmmsgStorage_;
  // We will only send transport knobs once, this flag keeps track of it
  bool transportKnobsSent_{false};
  // Callback function to invoke when the client receives a new token
  std::function<void(std::string)> newTokenCallback_;

  // Container of observers for the socket / transport.
  //
  // This member MUST be last in the list of members to ensure it is destroyed
  // first, before any other members are destroyed. This ensures that observers
  // can inspect any socket / transport state available through public methods
  // when destruction of the transport begins.
  const WrappedSocketObserverContainer wrappedObserverContainer_;
  // Output buf/accessor to be used for continuous memory writes.
  std::unique_ptr<BufAccessor> bufAccessor_;
};
} // namespace quic
