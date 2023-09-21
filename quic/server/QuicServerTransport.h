/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicTransportBase.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/common/TransportKnobs.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/server/handshake/ServerTransportParametersExtension.h>
#include <quic/server/state/ServerConnectionIdRejector.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicTransportStatsCallback.h>

#include <folly/io/async/AsyncTransportCertificate.h>

#include <fizz/record/Types.h>

namespace quic {

struct CipherInfo {
  TrafficKey trafficKey;
  fizz::CipherSuite cipherSuite;
  Buf packetProtectionKey;
};

class QuicServerTransport
    : public QuicTransportBase,
      public ServerHandshake::HandshakeCallback,
      public std::enable_shared_from_this<QuicServerTransport> {
 public:
  using Ptr = std::shared_ptr<QuicServerTransport>;
  using Ref = const QuicServerTransport&;
  using SourceIdentity = std::pair<folly::SocketAddress, ConnectionId>;

  class RoutingCallback {
   public:
    virtual ~RoutingCallback() = default;

    // Called when a connection id is available
    virtual void onConnectionIdAvailable(
        Ptr transport,
        ConnectionId id) noexcept = 0;

    virtual void onConnectionIdRetired(
        Ref transport,
        ConnectionId id) noexcept = 0;

    // Called when a connection id is bound and ip address should not
    // be used any more for routing.
    virtual void onConnectionIdBound(Ptr transport) noexcept = 0;

    // Called when the connection is finished and needs to be Unbound.
    virtual void onConnectionUnbound(
        QuicServerTransport* transport,
        const SourceIdentity& address,
        const std::vector<ConnectionIdData>& connectionIdData) noexcept = 0;
  };

  class HandshakeFinishedCallback {
   public:
    virtual ~HandshakeFinishedCallback() = default;

    virtual void onHandshakeFinished() noexcept = 0;

    virtual void onHandshakeUnfinished() noexcept = 0;
  };

  static QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> sock,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connStreamsCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx,
      bool useConnectionEndWithErrorCallback = false);

  QuicServerTransport(
      folly::EventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> sock,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connStreamsCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx,
      std::unique_ptr<CryptoFactory> cryptoFactory = nullptr,
      bool useConnectionEndWithErrorCallback = false);

  // Testing only API:
  QuicServerTransport(
      folly::EventBase* evb,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> sock,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connStreamsCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx,
      std::unique_ptr<CryptoFactory> cryptoFactory,
      PacketNum startingPacketNum);

  ~QuicServerTransport() override;

  virtual void setRoutingCallback(RoutingCallback* callback) noexcept;

  virtual void setHandshakeFinishedCallback(
      HandshakeFinishedCallback* callback) noexcept;

  virtual void setOriginalPeerAddress(const folly::SocketAddress& addr);

  virtual void setServerConnectionIdParams(
      ServerConnectionIdParams params) noexcept;

  /**
   * Set callback for various transport stats (such as packet received, dropped
   * etc).
   */
  virtual void setTransportStatsCallback(
      QuicTransportStatsCallback* statsCallback) noexcept;

  /**
   * Set ConnectionIdAlgo implementation to encode and decode ConnectionId with
   * various info, such as routing related info.
   */
  virtual void setConnectionIdAlgo(ConnectionIdAlgo* connIdAlgo) noexcept;

  void setServerConnectionIdRejector(
      ServerConnectionIdRejector* connIdRejector) noexcept;

  virtual void setClientConnectionId(const ConnectionId& clientConnectionId);

  void setClientChosenDestConnectionId(const ConnectionId& serverCid);

  void verifiedClientAddress();

  // From QuicTransportBase
  void onReadData(
      const folly::SocketAddress& peer,
      NetworkDataSingle&& networkData) override;
  void writeData() override;
  void closeTransport() override;
  void unbindConnection() override;
  bool hasWriteCipher() const override;
  std::shared_ptr<QuicTransportBase> sharedGuard() override;
  QuicConnectionStats getConnectionsStats() const override;

  const fizz::server::FizzServerContext& getCtx() {
    return *ctx_;
  }

  virtual void accept();

  virtual void setBufAccessor(BufAccessor* bufAccessor);

  const std::shared_ptr<const folly::AsyncTransportCertificate>
  getPeerCertificate() const override;

  virtual CipherInfo getOneRttCipherInfo() const;

  /* Log a collection of statistics that are meant to be sampled consistently
   * over time, rather than driven by transport events.
   */
  void logTimeBasedStats() const;

 protected:
  // From QuicSocket
  SocketObserverContainer* getSocketObserverContainer() const override {
    return wrappedObserverContainer_.getPtr();
  }

  // From ServerHandshake::HandshakeCallback
  virtual void onCryptoEventAvailable() noexcept override;

  void onTransportKnobs(Buf knobBlob) override;

  void handleTransportKnobParams(const TransportKnobParams& params);

  // Made it protected for testing purpose
  void registerTransportKnobParamHandler(
      uint64_t paramId,
      std::function<void(QuicServerTransport*, TransportKnobParam::Val)>&&
          handler);

 private:
  void processPendingData(bool async);
  void maybeNotifyTransportReady();
  void maybeNotifyConnectionIdRetired();
  void maybeNotifyConnectionIdBound();
  void maybeWriteNewSessionTicket();
  void maybeIssueConnectionIds();
  void maybeNotifyHandshakeFinished();
  bool hasReadCipher() const;
  void registerAllTransportKnobParamHandlers();

 private:
  RoutingCallback* routingCb_{nullptr};
  HandshakeFinishedCallback* handshakeFinishedCb_{nullptr};
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  bool notifiedRouting_{false};
  bool notifiedConnIdBound_{false};
  bool newSessionTicketWritten_{false};
  QuicServerConnectionState* serverConn_;
  std::unordered_map<
      uint64_t,
      std::function<void(QuicServerTransport*, TransportKnobParam::Val)>>
      transportKnobParamHandlers_;

  // Container of observers for the socket / transport.
  //
  // This member MUST be last in the list of members to ensure it is destroyed
  // first, before any other members are destroyed. This ensures that observers
  // can inspect any socket / transport state available through public methods
  // when destruction of the transport begins.
  const WrappedSocketObserverContainer wrappedObserverContainer_;
};
} // namespace quic
