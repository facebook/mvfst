/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Random.h>
#include <folly/SocketAddress.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/net/NetOps.h>
#include <quic/api/QuicTransportBase.h>
#include <quic/client/handshake/QuicPskCache.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/BufUtil.h>

namespace quic {

class ClientHandshakeFactory;

class QuicClientTransport
    : public QuicTransportBase,
      public folly::AsyncUDPSocket::ReadCallback,
      public folly::AsyncUDPSocket::ErrMessageCallback,
      public std::enable_shared_from_this<QuicClientTransport>,
      private ClientHandshake::HandshakeCallback {
 public:
  QuicClientTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = kDefaultConnectionIdSize);

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
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = 0) {
    auto client = std::make_shared<TransportType>(
        evb, std::move(sock), std::move(handshakeFactory), connectionIdSize);
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
  void addNewSocket(std::unique_ptr<folly::AsyncUDPSocket> socket);
  void setHappyEyeballsEnabled(bool happyEyeballsEnabled);
  virtual void setHappyEyeballsCachedFamily(sa_family_t cachedFamily);

  /**
   * Set the cache that remembers psk and server transport parameters from
   * last connection. This is useful for session resumption and 0-rtt.
   */
  void setPskCache(std::shared_ptr<QuicPskCache> pskCache);

  /**
   * Starts the connection.
   */
  virtual void start(ConnectionCallback* cb);

  /**
   * Returns whether or not TLS is resumed.
   */
  bool isTLSResumed() const;

  // From QuicTransportBase
  void onReadData(
      const folly::SocketAddress& peer,
      NetworkDataSingle&& networkData) override;
  void writeData() override;
  void closeTransport() override;
  void unbindConnection() override;
  bool hasWriteCipher() const override;
  std::shared_ptr<QuicTransportBase> sharedGuard() override;

  // folly::AsyncUDPSocket::ReadCallback
  void onReadClosed() noexcept override {}
  void onReadError(const folly::AsyncSocketException&) noexcept override {}

  // folly::AsyncUDPSocket::ErrMessageCallback
  void errMessage(const cmsghdr& cmsg) noexcept override;
  void errMessageError(const folly::AsyncSocketException&) noexcept override {}

  void setSupportedVersions(const std::vector<QuicVersion>& versions) override;

  /**
   * Make QuicClient transport self owning.
   */
  void setSelfOwning();

  /**
   * Used to set private transport parameters that are not in the
   * TransportParameterId enum.
   * See kCustomTransportParameterThreshold in QuicConstants.h
   */
  bool setCustomTransportParameter(
      std::unique_ptr<CustomTransportParameter> customParam);

  void setQLogger(std::shared_ptr<QLogger> qLogger) override;

  void onNetworkSwitch(std::unique_ptr<folly::AsyncUDPSocket> newSock) override;

  class HappyEyeballsConnAttemptDelayTimeout
      : public folly::HHWheelTimer::Callback {
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
  // From AsyncUDPSocket::ReadCallback
  void getReadBuffer(void** buf, size_t* len) noexcept override;
  void onDataAvailable(
      const folly::SocketAddress& server,
      size_t len,
      bool truncated) noexcept override;
  bool shouldOnlyNotify() override;
  void onNotifyDataAvailable(folly::AsyncUDPSocket& sock) noexcept override;
  void recvMsg(
      folly::AsyncUDPSocket& sock,
      uint64_t readBufferSize,
      int numPackets,
      NetworkData& networkData,
      folly::Optional<folly::SocketAddress>& server,
      size_t& totalData);
  void recvMmsg(
      folly::AsyncUDPSocket& sock,
      uint64_t readBufferSize,
      int numPackets,
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
      const OutstandingPacket& outstandingPacket,
      const QuicWriteFrame& packetFrame,
      const ReadAckFrame&);

  // From ClientHandshake::HandshakeCallback
  void onNewCachedPsk(
      fizz::client::NewCachedPsk& newCachedPsk) noexcept override;

  Buf readBuffer_;
  folly::Optional<std::string> hostname_;
  HappyEyeballsConnAttemptDelayTimeout happyEyeballsConnAttemptDelayTimeout_;
  bool serverInitialParamsSet_{false};
  uint64_t peerAdvertisedInitialMaxData_{0};
  uint64_t peerAdvertisedInitialMaxStreamDataBidiLocal_{0};
  uint64_t peerAdvertisedInitialMaxStreamDataBidiRemote_{0};
  uint64_t peerAdvertisedInitialMaxStreamDataUni_{0};

 private:
  void cacheServerInitialParams(
      uint64_t peerAdvertisedInitialMaxData,
      uint64_t peerAdvertisedInitialMaxStreamDataBidiLocal,
      uint64_t peerAdvertisedInitialMaxStreamDataBidiRemote,
      uint64_t peerAdvertisedInitialMaxStreamDataUni,
      uint64_t peerAdvertisedInitialMaxStreamsBidi,
      uint64_t peerAdvertisedInitialMaxStreamUni);
  folly::Optional<QuicCachedPsk> getPsk();
  void removePsk();
  void setPartialReliabilityTransportParameter();

 private:
  bool replaySafeNotified_{false};
  // Set it QuicClientTransport is in a self owning mode. This will be cleaned
  // up when the caller invokes a terminal call to the transport.
  std::shared_ptr<QuicClientTransport> selfOwning_;
  bool happyEyeballsEnabled_{false};
  sa_family_t happyEyeballsCachedFamily_{AF_UNSPEC};
  std::shared_ptr<QuicPskCache> pskCache_;
  QuicClientConnectionState* clientConn_;
  std::vector<TransportParameter> customTransportParameters_;
};
} // namespace quic
