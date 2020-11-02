/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
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

namespace quic {

class QuicServerTransport
    : public QuicTransportBase,
      public ServerHandshake::HandshakeCallback,
      public std::enable_shared_from_this<QuicServerTransport> {
 public:
  using Ptr = std::shared_ptr<QuicServerTransport>;
  using SourceIdentity = std::pair<folly::SocketAddress, ConnectionId>;

  class RoutingCallback {
   public:
    virtual ~RoutingCallback() = default;

    // Called when a connection id is available
    virtual void onConnectionIdAvailable(
        Ptr transport,
        ConnectionId id) noexcept = 0;

    // Called when a connecton id is bound and ip address should not
    // be used any more for routing.
    virtual void onConnectionIdBound(Ptr transport) noexcept = 0;

    // Called when the connection is finished and needs to be Unbound.
    virtual void onConnectionUnbound(
        QuicServerTransport* transport,
        const SourceIdentity& address,
        const std::vector<ConnectionIdData>& connectionIdData) noexcept = 0;
  };

  static QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      ConnectionCallback& cb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  QuicServerTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      ConnectionCallback& cb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  ~QuicServerTransport() override;

  virtual void setRoutingCallback(RoutingCallback* callback) noexcept;

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

  /**
   * Set factory to create specific congestion controller instances
   * for a given connection
   * This must be set before the server is started.
   */
  void setCongestionControllerFactory(
      std::shared_ptr<CongestionControllerFactory> factory) override;

  virtual void setClientConnectionId(const ConnectionId& clientConnectionId);

  void setClientChosenDestConnectionId(const ConnectionId& serverCid);

  // From QuicTransportBase
  void onReadData(
      const folly::SocketAddress& peer,
      NetworkDataSingle&& networkData) override;
  void writeData() override;
  void closeTransport() override;
  void unbindConnection() override;
  bool hasWriteCipher() const override;
  std::shared_ptr<QuicTransportBase> sharedGuard() override;

  const fizz::server::FizzServerContext& getCtx() {
    return *ctx_;
  }

  virtual void accept();

  virtual void setBufAccessor(BufAccessor* bufAccessor);

#ifdef CCP_ENABLED
  /*
   * This function must be called with an initialized ccp_datapath (via
   * libccp:ccp_init) before starting any connections using the CCP congestion
   * control algorithm. See further notes on this struct in the header file.
   */
  void setCcpDatapath(struct ccp_datapath* datapath);
#endif

  const std::shared_ptr<const folly::AsyncTransportCertificate>
  getPeerCertificate() const override;

 protected:
  // From ServerHandshake::HandshakeCallback
  virtual void onCryptoEventAvailable() noexcept override;

  void onTransportKnobs(Buf knobBlob) override;

  void handleTransportKnobParams(const TransportKnobParams& params);

  // Made it protected for testing purpose
  void registerTransportKnobParamHandler(
      uint64_t paramId,
      std::function<void(QuicServerConnectionState*, uint64_t)>&& handler);

 private:
  void processPendingData(bool async);
  void maybeNotifyTransportReady();
  void maybeNotifyConnectionIdBound();
  void maybeWriteNewSessionTicket();
  void maybeIssueConnectionIds();
  bool hasReadCipher() const;
  void maybeStartD6DProbing();
  void registerAllTransportKnobParamHandlers();

 private:
  RoutingCallback* routingCb_{nullptr};
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  bool notifiedRouting_{false};
  bool notifiedConnIdBound_{false};
  bool newSessionTicketWritten_{false};
  bool connectionIdsIssued_{false};
  QuicServerConnectionState* serverConn_;
  std::unordered_map<
      uint64_t,
      std::function<void(QuicServerConnectionState*, uint64_t)>>
      transportKnobParamHandlers_;
};
} // namespace quic
