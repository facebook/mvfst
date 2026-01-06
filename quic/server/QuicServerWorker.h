/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Random.h>
#include <folly/container/EvictingCacheMap.h>
#include <folly/container/F14Map.h>
#include <folly/container/F14Set.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <cstdint>
#include <type_traits>

#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/events/HighResQuicTimer.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/server/QuicServerPacketRouter.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <quic/server/QuicUDPSocketFactory.h>
#include <quic/server/RateLimiter.h>
#include <quic/server/state/ServerConnectionIdRejector.h>
#include <quic/state/QuicConnectionStats.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

class AcceptObserver;

class QuicServerWorker : public FollyAsyncUDPSocketAlias::ReadCallback,
                         public QuicServerTransport::RoutingCallback,
                         public QuicServerTransport::HandshakeFinishedCallback,
                         public ServerConnectionIdRejector,
                         public folly::HHWheelTimer::Callback {
 public:
  static int getUnfinishedHandshakeCount();

  using TransportSettingsOverrideFn =
      std::function<void(quic::TransportSettings&)>;

  using ShouldRegisterKnobParamHandlerFn =
      std::function<bool(TransportKnobParamId)>;

  class WorkerCallback {
   public:
    virtual ~WorkerCallback() = default;
    // Callback for when the worker has errored
    virtual void handleWorkerError(LocalErrorCode error) = 0;

    virtual void routeDataToWorker(
        const folly::SocketAddress& client,
        RoutingData&& routingData,
        NetworkData&& networkData,
        Optional<QuicVersion> quicVersion,
        folly::EventBase* workerEvb,
        bool isForwardedData) = 0;
  };

  explicit QuicServerWorker(
      std::shared_ptr<WorkerCallback> callback,
      TransportSettings transportSettings = TransportSettings());

  ~QuicServerWorker() override;

  [[nodiscard]] folly::EventBase* getEventBase() const;

  void setPacingTimer(QuicTimer::SharedPtr pacingTimer) noexcept;

  /*
   * Take in a function to supply overrides for transport parameters, given
   * the client address as input. This can be useful if we are running
   * experiments.
   */
  void setTransportSettingsOverrideFn(TransportSettingsOverrideFn fn);

  /*
   * Set a callback to validate whether a specific transport knob parameter
   * is allowed to be registered.
   */
  void setShouldRegisterKnobParamHandlerFn(ShouldRegisterKnobParamHandlerFn fn);

  /**
   * Sets the listening socket
   */
  void setSocket(std::unique_ptr<FollyAsyncUDPSocketAlias> socket);

  /**
   * Sets the socket options
   */
  void setSocketOptions(folly::SocketOptionMap* options) {
    socketOptions_ = options;
  }

  /**
   * Binds to the given address
   */
  void bind(
      const folly::SocketAddress& address,
      FollyAsyncUDPSocketAlias::BindOptions bindOptions =
          FollyAsyncUDPSocketAlias::BindOptions());

  /**
   * start reading data from the socket
   */
  void start();

  /*
   * Pause reading from the listening socket this worker is bound to
   */
  void pauseRead();

  /**
   * Returns listening address of this server
   */
  [[nodiscard]] const folly::SocketAddress& getAddress() const;

  /*
   * Returns the File Descriptor of the listening socket
   */
  int getFD();

  /*
   * Apply all the socket options (pre/post bind).
   * Called after takeover.
   */
  void applyAllSocketOptions();

  /**
   * Initialize and bind given listening socket to the given takeover address
   * so that this server can accept and process misrouted packets forwarded
   * by other server
   */
  void allowBeingTakenOver(
      std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
      const folly::SocketAddress& address);

  /**
   * Override listening address for takeover packets
   * Returns const ref to SocketAddress representing the address it is bound to.
   */
  const folly::SocketAddress& overrideTakeoverHandlerAddress(
      std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
      const folly::SocketAddress& address);

  /**
   * Setup address that the taken over quic server is listening to forward
   * misrouted packets belonging to the old server.
   */
  void startPacketForwarding(const folly::SocketAddress& destAddr);

  /**
   * Stop forwarding of packets and clean up any allocated resources
   */
  void stopPacketForwarding();

  /*
   * Returns the File Descriptor of the listening socket that handles the
   * packets routed from another quic server.
   */
  int getTakeoverHandlerSocketFD();

  [[nodiscard]] TakeoverProtocolVersion getTakeoverProtocolVersion()
      const noexcept;

  /*
   * Sets the id of the server, that is later used in the routing of the packets
   * The id will be used to set a bit in the ConnectionId for routing.
   */
  void setProcessId(enum ProcessId id) noexcept;

  /*
   * Get the id of the server.
   * The id will be used to set a bit in the ConnectionId for routing (which is
   * later used in the routing of the packets)
   */
  [[nodiscard]] ProcessId getProcessId() const noexcept;

  /**
   * Set the id for this worker thread. Server can make routing decision by
   * setting this id in the ConnectionId
   */
  void setWorkerId(uint8_t id) noexcept;

  /**
   * Returns the id for this worker thread.
   */
  [[nodiscard]] uint8_t getWorkerId() const noexcept;

  /**
   * Set the id for the host where this server is running.
   * It is used to make routing decision by setting this id in the ConnectionId
   */
  void setHostId(uint32_t hostId) noexcept;

  /**
   * Set version of connection ID used by quic server.
   */
  void setConnectionIdVersion(ConnectionIdVersion cidVersion) noexcept;

  void setNewConnectionSocketFactory(QuicUDPSocketFactory* factory);

  void setTransportFactory(QuicServerTransportFactory* factory);

  void setSupportedVersions(const std::vector<QuicVersion>& supportedVersions);

  void setFizzContext(
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  /**
   * If true, start to reject any new connection during handshake
   */
  void rejectNewConnections(std::function<bool()> rejectNewConnections);

  /**
   * Set callback to determine if MVFST_PRIMING protocol version is enabled
   */
  void setPrimingEnabledCallback(std::function<bool()> isPrimingEnabled);

  /**
   * If true, begin rejecting connections with block listed source ports
   */
  void setIsBlockListedSrcPort(
      std::function<bool(uint16_t)> isBlockListedSrcPort_);

  /**
   * Set a health-check token that can be used to ping if the server is alive
   */
  void setHealthCheckToken(const std::string& healthCheckToken);

  /**
   * Set callback for various transport stats (such as packet received, dropped
   * etc). Since the callback is invoked very frequently and per thread, it is
   * important that the implementation is efficient.
   * NOTE: Quic does not synchronize across threads before calling it.
   */
  void setTransportStatsCallback(
      std::unique_ptr<QuicTransportStatsCallback> statsCallback) noexcept;

  /**
   * Return callback for recording various transport stats info.
   */
  [[nodiscard]] QuicTransportStatsCallback* getTransportStatsCallback()
      const noexcept;

  /**
   * Set ConnectionIdAlgo implementation to encode and decode ConnectionId with
   * various info, such as routing related info.
   */
  void setConnectionIdAlgo(
      std::unique_ptr<ConnectionIdAlgo> connIdAlgo) noexcept;

  /**
   * Set factory to create specific congestion controller instances
   * for a given connection
   * This must be set before the server starts (and accepts connections)
   */
  void setCongestionControllerFactory(
      std::shared_ptr<CongestionControllerFactory> factory);

  /**
   * Set the rate limiter which will be used to rate limit new connections.
   */
  void setRateLimiter(std::unique_ptr<RateLimiter> rateLimiter);

  void setUnfinishedHandshakeLimit(std::function<int()> limitFn);

  // Read callback
  void getReadBuffer(void** buf, size_t* len) noexcept override;

  void onDataAvailable(
      const folly::SocketAddress& client,
      size_t len,
      bool truncated,
      OnDataAvailableParams params) noexcept override;

  // Routing callback
  /**
   * Called when a connection id is available for a new connection (i.e flow)
   * The connection-id here is chosen by this server
   */
  void onConnectionIdAvailable(
      QuicServerTransport::Ptr transport,
      ConnectionId id) noexcept override;

  /**
   * Called when a connection id has been retired by the peer thru a
   * RETIRE_CONNECTION_ID frame.
   */
  void onConnectionIdRetired(
      QuicServerTransport::Ref transport,
      ConnectionId id) noexcept override;

  /**
   * Called when a connection id is bound and ip address should not
   * be used any more for routing.
   */
  void onConnectionIdBound(
      QuicServerTransport::Ptr transport) noexcept override;

  /**
   * source: Source address and source CID
   * connectionId: destination CID (i.e. server chosen connection-id)
   */
  void onConnectionUnbound(
      QuicServerTransport* transport,
      const QuicServerTransport::SourceIdentity& source,
      const std::vector<ConnectionIdData>& connectionIdData) noexcept override;

  void onHandshakeFinished() noexcept override;

  void onHandshakeUnfinished() noexcept override;

  // From ServerConnectionIdRejector:
  [[nodiscard]] bool rejectConnectionId(
      const ConnectionId& candidate) const noexcept override;

  void onReadError(const folly::AsyncSocketException& ex) noexcept override;

  void onReadClosed() noexcept override;

  void dispatchPacketData(
      const folly::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData,
      Optional<QuicVersion> quicVersion,
      bool isForwardedData = false) noexcept;

  using ConnIdToTransportMap = folly::
      F14FastMap<ConnectionId, QuicServerTransport::Ptr, ConnectionIdHash>;

  struct SourceIdentityHash {
    size_t operator()(const QuicServerTransport::SourceIdentity& sid) const;
  };

  using SrcToTransportMap = folly::F14FastMap<
      QuicServerTransport::SourceIdentity,
      QuicServerTransport::Ptr,
      SourceIdentityHash>;

  [[nodiscard]] const ConnIdToTransportMap& getConnectionIdMap() const;

  [[nodiscard]] const SrcToTransportMap& getSrcToTransportMap() const;

  void shutdownAllConnections(LocalErrorCode error);

  // for unit test
  FollyAsyncUDPSocketAlias::ReadCallback* getTakeoverHandlerCallback() {
    return takeoverCB_.get();
  }

  // Handle the network data for a udp packet
  // public so that it can be called by tests as well.
  void handleNetworkData(
      const folly::SocketAddress& client,
      ReceivedUdpPacket& packet,
      bool isForwardedData = false) noexcept;

  /**
   * Try handling the data as a health check.
   */
  bool tryHandlingAsHealthCheck(
      const folly::SocketAddress& client,
      const Buf& data);

  /**
   * Return Infocallback ptr for various transport stats (such as packet
   * received, dropped etc). Since the callback is invoked very frequently and
   * per thread, it is important that the implementation is efficient.
   * NOTE: QuicServer does not synchronize across threads before calling it
   */
  QuicTransportStatsCallback* getStatsCallback() {
    return statsCallback_.get();
  }

  /**
   * Adds observer for accept events.
   *
   * Can be used to install socket observers and instrumentation without
   * changing / interfering with application-specific acceptor logic.
   *
   * @param observer     Observer to add (implements AcceptObserver).
   */
  virtual void addAcceptObserver(AcceptObserver* observer) {
    observerList_.add(observer);
  }

  /**
   * Remove observer for accept events.
   *
   * @param observer     Observer to remove.
   * @return             Whether observer found and removed from list.
   */
  virtual bool removeAcceptObserver(AcceptObserver* observer) {
    return observerList_.remove(observer);
  }

  void getAllConnectionsStats(std::vector<QuicConnectionStats>& stats);

  void timeoutExpired() noexcept override;
  void logTimeBasedStats();

 private:
  /**
   * Creates accepting socket from this server's listening address.
   * This socket is powered by the same underlying eventbase
   * for this QuicServerWorker
   */
  std::unique_ptr<FollyAsyncUDPSocketAlias> makeSocket(
      folly::EventBase* evb) const;

  /**
   * Creates accepting socket from the listening address denoted by given fd.
   * This socket is powered by the same underlying eventbase
   * for this QuicServerWorker
   */
  std::unique_ptr<FollyAsyncUDPSocketAlias> makeSocket(
      folly::EventBase* evb,
      int fd) const;

  /**
   * Tries to get the encrypted retry token from a client initial packet
   */
  Optional<std::string> maybeGetEncryptedToken(ContiguousReadCursor& cursor);

  bool validRetryToken(
      std::string& encryptedToken,
      const ConnectionId& dstConnId,
      const folly::IPAddress& clientIp);

  bool validNewToken(
      std::string& encryptedToken,
      const folly::IPAddress& clientIp);

  void sendRetryPacket(
      const folly::SocketAddress& client,
      const ConnectionId& dstConnId,
      const ConnectionId& srcConnId);

  void sendResetPacket(
      const HeaderForm& headerForm,
      const folly::SocketAddress& client,
      const NetworkData& networkData,
      const ConnectionId& connId);

  bool maybeSendVersionNegotiationPacketOrDrop(
      const folly::SocketAddress& client,
      bool isInitial,
      LongHeaderInvariant& invariant,
      size_t datagramLen);

  void sendVersionNegotiationPacket(
      const folly::SocketAddress& client,
      LongHeaderInvariant& invariant);

  void recordRxDelay(
      const std::chrono::system_clock::time_point& currentTime,
      const timespec& socketRxTime);

  /**
   * Helper method to extract and log routing info from the given (dest) connId
   */
  [[nodiscard]] std::string logRoutingInfo(const ConnectionId& connId) const;

  bool hasTimestamping() {
    return (socket_ && (socket_->getTimestamping() > 0));
  }

  /**
   * Forward data to the right worker or to the takeover socket
   */
  void forwardNetworkData(
      const folly::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData,
      Optional<QuicVersion> quicVersion,
      bool isForwardedData = false);

  // Create transport and invoke appropriate setters
  QuicServerTransport::Ptr makeTransport(
      QuicVersion quicVersion,
      const folly::SocketAddress& client,
      const Optional<ConnectionId>& srcConnId,
      const ConnectionId& dstConnId,
      bool validNewToken);

  // Parses the dst conn id to determine if packet was incorrectly routed to
  // this host/process.
  PacketDropReason isDstConnIdMisrouted(
      const ConnectionId& dstConnId,
      const folly::SocketAddress& client);

  std::unique_ptr<FollyAsyncUDPSocketAlias> socket_;
  folly::SocketOptionMap* socketOptions_{nullptr};
  std::shared_ptr<WorkerCallback> callback_;
  folly::Executor::KeepAlive<folly::EventBase> evb_;

  // factories are owned by quic server
  QuicUDPSocketFactory* socketFactory_;
  QuicServerTransportFactory* transportFactory_;
  std::shared_ptr<CongestionControllerFactory> ccFactory_{nullptr};

  // A server transport's membership is exclusive to only one of these maps.
  ConnIdToTransportMap connectionIdMap_;
  SrcToTransportMap sourceAddressMap_;

  folly::EvictingCacheMap<
      ConnectionId,
      SmallVec<
          NetworkData,
          kDefaultMaxBufferedPackets,
          folly::small_vector_policy::policy_in_situ_only<true>>,
      ConnectionIdHash>
      pending0RttData_{20};

  // Contains every unique transport that is mapped in connectionIdMap_.
  folly::F14FastMap<QuicServerTransport*, std::weak_ptr<QuicServerTransport>>
      boundServerTransports_;

  BufPtr readBuffer_;
  bool shutdown_{false};
  std::vector<QuicVersion> supportedVersions_;
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  const TransportSettings transportSettings_;
  // Same value as transportSettings_.numGROBuffers_ if the kernel
  // supports GRO. otherwise 1
  uint32_t numGROBuffers_{kDefaultNumGROBuffers};
  Optional<BufPtr> healthCheckToken_;
  std::function<bool()> rejectNewConnections_{[]() { return false; }};
  std::function<bool()> isPrimingEnabled_{[]() { return false; }};
  std::function<bool(uint16_t)> isBlockListedSrcPort_{
      [](uint16_t) { return false; }};
  uint8_t workerId_{0};
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  uint32_t hostId_{0};
  uint32_t prevHostId_{0};
  ConnectionIdVersion cidVersion_{ConnectionIdVersion::V1};
  // QuicServerWorker maintains ownership of the info stats callback
  std::unique_ptr<QuicTransportStatsCallback> statsCallback_;
  std::chrono::seconds timeLoggingSamplingInterval_{1};

  // Handle takeover between processes
  std::unique_ptr<TakeoverHandlerCallback> takeoverCB_;

  enum ProcessId processId_ { ProcessId::ZERO };

  TakeoverPacketHandler takeoverPktHandler_;
  bool packetForwardingEnabled_{false};
  QuicTimer::SharedPtr pacingTimer_;

  // Used to override certain transport parameters, given the client address
  TransportSettingsOverrideFn transportSettingsOverrideFn_;

  // Used to validate whether a transport knob parameter is allowed to be
  // registered
  ShouldRegisterKnobParamHandlerFn shouldRegisterKnobParamHandlerFn_;

  // Output buffer to be used for continuous memory GSO write
  std::unique_ptr<BufAccessor> bufAccessor_;

  // Rate limits the creation of new connections for this worker.
  std::unique_ptr<RateLimiter> newConnRateLimiter_;

  Optional<std::function<int()>> unfinishedHandshakeLimitFn_;

  // Wrapper around list of AcceptObservers to handle cleanup on destruction
  class AcceptObserverList {
   public:
    explicit AcceptObserverList(QuicServerWorker* worker);

    /**
     * Destructor, triggers observerDetach for any attached observers.
     */
    ~AcceptObserverList();

    /**
     * Add observer and trigger observerAttach.
     */
    void add(AcceptObserver* observer);

    /**
     * Remove observer and trigger observerDetach.
     */
    bool remove(AcceptObserver* observer);

    /**
     * Get reference to vector containing observers.
     */
    [[nodiscard]] const std::vector<AcceptObserver*>& getAll() const {
      return observers_;
    }

   private:
    QuicServerWorker* worker_{nullptr};
    std::vector<AcceptObserver*> observers_;
  };

  // List of AcceptObservers
  AcceptObserverList observerList_;

  TimePoint largestPacketReceiveTime_{TimePoint::min()};
};

} // namespace quic
