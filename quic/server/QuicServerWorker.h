/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/container/EvictingCacheMap.h>
#include <folly/container/F14Map.h>
#include <folly/container/F14Set.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/small_vector.h>

#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/Timers.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/server/CCPReader.h>
#include <quic/server/QuicServerPacketRouter.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <quic/server/QuicUDPSocketFactory.h>
#include <quic/server/RateLimiter.h>
#include <quic/server/state/ServerConnectionIdRejector.h>
#include <quic/state/QuicConnectionStats.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

class AcceptObserver;

class QuicServerWorker : public folly::AsyncUDPSocket::ReadCallback,
                         public QuicServerTransport::RoutingCallback,
                         public QuicServerTransport::HandshakeFinishedCallback,
                         public ServerConnectionIdRejector,
                         public folly::EventRecvmsgCallback {
 private:
  struct MsgHdr : public folly::EventRecvmsgCallback::MsgHdr {
    static auto constexpr kBuffSize = 1024;

    MsgHdr() = delete;
    ~MsgHdr() override = default;
    explicit MsgHdr(QuicServerWorker* worker) {
      arg_ = worker;
      freeFunc_ = MsgHdr::free;
      cbFunc_ = MsgHdr::cb;
    }

    void reset() {
      len_ = getBuffSize();
      ioBuf_ = folly::IOBuf::create(len_);
      ::memset(&data_, 0, sizeof(data_));
      iov_.iov_base = ioBuf_->writableData();
      iov_.iov_len = len_;
      data_.msg_iov = &iov_;
      data_.msg_iovlen = 1;
      ::memset(&addrStorage_, 0, sizeof(addrStorage_));
      auto* rawAddr = reinterpret_cast<sockaddr*>(&addrStorage_);
      rawAddr->sa_family =
          reinterpret_cast<QuicServerWorker*>(arg_)->getAddress().getFamily();
      data_.msg_name = rawAddr;
      ;
      data_.msg_namelen = sizeof(addrStorage_);
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
      if (hasGRO() || hasTimestamping()) {
        ::memset(control_, 0, sizeof(control_));
        data_.msg_control = control_;
        data_.msg_controllen = sizeof(control_);
      }
#endif
    }

    static void free(folly::EventRecvmsgCallback::MsgHdr* msgHdr) {
      delete msgHdr;
    }

    static void cb(folly::EventRecvmsgCallback::MsgHdr* msgHdr, int res) {
      reinterpret_cast<QuicServerWorker*>(msgHdr->arg_)
          ->eventRecvmsgCallback(reinterpret_cast<MsgHdr*>(msgHdr), res);
    }

    size_t getBuffSize() {
      auto* worker = reinterpret_cast<QuicServerWorker*>(arg_);
      return worker->transportSettings_.maxRecvPacketSize *
          worker->numGROBuffers_;
    }

    bool hasGRO() {
      auto* worker = reinterpret_cast<QuicServerWorker*>(arg_);
      return worker->numGROBuffers_ > 1;
    }

    bool hasTimestamping() {
      auto* worker = reinterpret_cast<QuicServerWorker*>(arg_);
      return worker->hasTimestamping();
    }

    // data
    Buf ioBuf_;
    struct iovec iov_;
    size_t len_{0};
    // addr
    struct sockaddr_storage addrStorage_;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    char control_[folly::AsyncUDPSocket::ReadCallback::OnDataAvailableParams::
                      kCmsgSpace];
#endif
  };

 public:
  using TransportSettingsOverrideFn =
      std::function<folly::Optional<quic::TransportSettings>(
          const quic::TransportSettings&,
          const folly::IPAddress&)>;

  class WorkerCallback {
   public:
    virtual ~WorkerCallback() = default;
    // Callback for when the worker has errored
    virtual void handleWorkerError(LocalErrorCode error) = 0;

    virtual void routeDataToWorker(
        const folly::SocketAddress& client,
        RoutingData&& routingData,
        NetworkData&& networkData,
        folly::Optional<QuicVersion> quicVersion,
        bool isForwardedData) = 0;
  };

  explicit QuicServerWorker(
      std::shared_ptr<WorkerCallback> callback,
      bool setEventCallback = false);

  ~QuicServerWorker() override;

  folly::EventBase* getEventBase() const;

  void setPacingTimer(TimerHighRes::SharedPtr pacingTimer) noexcept;

  /*
   * Take in a function to supply overrides for transport parameters, given
   * the client address as input. This can be useful if we are running
   * experiments.
   */
  void setTransportSettingsOverrideFn(TransportSettingsOverrideFn fn);

  /**
   * Sets the listening socket
   */
  void setSocket(std::unique_ptr<folly::AsyncUDPSocket> socket);

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
      folly::AsyncUDPSocket::BindOptions bindOptions =
          folly::AsyncUDPSocket::BindOptions());

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
  const folly::SocketAddress& getAddress() const;

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
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      const folly::SocketAddress& address);

  /**
   * Override listening address for takeover packets
   * Returns const ref to SocketAddress representing the address it is bound to.
   */
  const folly::SocketAddress& overrideTakeoverHandlerAddress(
      std::unique_ptr<folly::AsyncUDPSocket> socket,
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

  TakeoverProtocolVersion getTakeoverProtocolVersion() const noexcept;

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
  ProcessId getProcessId() const noexcept;

  /**
   * Set the id for this worker thread. Server can make routing decision by
   * setting this id in the ConnectionId
   */
  void setWorkerId(uint8_t id) noexcept;

  /**
   * Returns the id for this worker thread.
   */
  uint8_t getWorkerId() const noexcept;

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

  void setTransportSettings(TransportSettings transportSettings);

  /**
   * If true, start to reject any new connection during handshake
   */
  void rejectNewConnections(std::function<bool()> rejectNewConnections);

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
  QuicTransportStatsCallback* getTransportStatsCallback() const noexcept;

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

  /*
   * Get a reference to this worker's corresponding CCPReader.
   * Each worker has a CCPReader that handles recieving messages from CCP
   * and dispatching them to the correct connection.
   */
  FOLLY_NODISCARD CCPReader* getCcpReader() const noexcept;

  // Read callback
  void getReadBuffer(void** buf, size_t* len) noexcept override;

  void onDataAvailable(
      const folly::SocketAddress& client,
      size_t len,
      bool truncated,
      OnDataAvailableParams params) noexcept override;

  // Routing callback
  /**
   * Called when a connecton id is available for a new connection (i.e flow)
   * The connection-id here is chosen by this server
   */
  void onConnectionIdAvailable(
      QuicServerTransport::Ptr transport,
      ConnectionId id) noexcept override;

  /**
   * Called when a connecton id is bound and ip address should not
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
  bool rejectConnectionId(
      const ConnectionId& candidate) const noexcept override;

  void onReadError(const folly::AsyncSocketException& ex) noexcept override;

  void onReadClosed() noexcept override;

  void dispatchPacketData(
      const folly::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData,
      folly::Optional<QuicVersion> quicVersion,
      bool isForwardedData = false) noexcept;

  using ConnIdToTransportMap = folly::
      F14FastMap<ConnectionId, QuicServerTransport::Ptr, ConnectionIdHash>;

  struct SourceIdentityHash {
    size_t operator()(const QuicServerTransport::SourceIdentity& sid) const {
      return folly::hash::hash_combine(
          folly::hash::fnv32_buf(sid.second.data(), sid.second.size()),
          sid.first.hash());
    }
  };
  using SrcToTransportMap = folly::F14FastMap<
      QuicServerTransport::SourceIdentity,
      QuicServerTransport::Ptr,
      SourceIdentityHash>;

  const ConnIdToTransportMap& getConnectionIdMap() const;

  const SrcToTransportMap& getSrcToTransportMap() const;

  void shutdownAllConnections(LocalErrorCode error);

  // for unit test
  folly::AsyncUDPSocket::ReadCallback* getTakeoverHandlerCallback() {
    return takeoverCB_.get();
  }

  // public so that it can be called by tests as well.
  void handleNetworkData(
      const folly::SocketAddress& client,
      Buf data,
      const TimePoint& receiveTime,
      bool isForwardedData = false) noexcept;

  /**
   * Try handling the data as a health check.
   */
  bool tryHandlingAsHealthCheck(
      const folly::SocketAddress& client,
      const folly::IOBuf& data);

  /**
   * Return Infocallback ptr for various transport stats (such as packet
   * received, dropped etc). Since the callback is invoked very frequently and
   * per thread, it is important that the implementation is efficient.
   * NOTE: QuicServer does not synchronize across threads before calling it
   */
  QuicTransportStatsCallback* getStatsCallback() {
    return statsCallback_.get();
  }

  // from EventRecvmsgCallback
  EventRecvmsgCallback::MsgHdr* allocateData() override {
    auto* ret = msgHdr_.release();
    if (!ret) {
      ret = new MsgHdr(this);
    }

    ret->reset();

    return ret;
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

 private:
  /**
   * Creates accepting socket from this server's listening address.
   * This socket is powered by the same underlying eventbase
   * for this QuicServerWorker
   */
  std::unique_ptr<folly::AsyncUDPSocket> makeSocket(
      folly::EventBase* evb) const;

  /**
   * Creates accepting socket from the listening address denoted by given fd.
   * This socket is powered by the same underlying eventbase
   * for this QuicServerWorker
   */
  std::unique_ptr<folly::AsyncUDPSocket> makeSocket(
      folly::EventBase* evb,
      int fd) const;

  /**
   * Tries to get the encrypted retry token from a client initial packet
   */
  folly::Optional<std::string> maybeGetEncryptedToken(
      folly::io::Cursor& cursor);

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

  /**
   * Helper method to extract and log routing info from the given (dest) connId
   */
  std::string logRoutingInfo(const ConnectionId& connId) const;

  void eventRecvmsgCallback(MsgHdr* msgHdr, int res);

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
      folly::Optional<QuicVersion> quicVersion,
      bool isForwardedData = false);

  std::unique_ptr<folly::AsyncUDPSocket> socket_;
  folly::SocketOptionMap* socketOptions_{nullptr};
  std::shared_ptr<WorkerCallback> callback_;
  bool setEventCallback_{false};
  folly::EventBase* evb_{nullptr};

  // factories are owned by quic server
  QuicUDPSocketFactory* socketFactory_;
  QuicServerTransportFactory* transportFactory_;
  std::shared_ptr<CongestionControllerFactory> ccFactory_{nullptr};

  // A server transport's membership is exclusive to only one of these maps.
  ConnIdToTransportMap connectionIdMap_;
  SrcToTransportMap sourceAddressMap_;

  folly::EvictingCacheMap<
      ConnectionId,
      folly::small_vector<
          NetworkData,
          kDefaultMaxBufferedPackets,
          folly::small_vector_policy::NoHeap>,
      ConnectionIdHash>
      pending0RttData_{20};

  // Contains every unique transport that is mapped in connectionIdMap_.
  folly::F14FastMap<QuicServerTransport*, std::weak_ptr<QuicServerTransport>>
      boundServerTransports_;

  Buf readBuffer_;
  bool shutdown_{false};
  std::vector<QuicVersion> supportedVersions_;
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  TransportSettings transportSettings_;
  // Same value as transportSettings_.numGROBuffers_ if the kernel
  // supports GRO. otherwise 1
  uint32_t numGROBuffers_{kDefaultNumGROBuffers};
  folly::Optional<Buf> healthCheckToken_;
  std::function<bool()> rejectNewConnections_{[]() { return false; }};
  std::function<bool(uint16_t)> isBlockListedSrcPort_{
      [](uint16_t) { return false; }};
  uint8_t workerId_{0};
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  uint32_t hostId_{0};
  ConnectionIdVersion cidVersion_{ConnectionIdVersion::V1};
  // QuicServerWorker maintains ownership of the info stats callback
  std::unique_ptr<QuicTransportStatsCallback> statsCallback_;

  // Handle takeover between processes
  std::unique_ptr<TakeoverHandlerCallback> takeoverCB_;
  enum ProcessId processId_ { ProcessId::ZERO };
  TakeoverPacketHandler takeoverPktHandler_;
  bool packetForwardingEnabled_{false};
  using PacketDropReason = QuicTransportStatsCallback::PacketDropReason;
  TimerHighRes::SharedPtr pacingTimer_;

  // Used to override certain transport parameters, given the client address
  TransportSettingsOverrideFn transportSettingsOverrideFn_;

  // Output buffer to be used for continuous memory GSO write
  std::unique_ptr<BufAccessor> bufAccessor_;

  // Rate limits the creation of new connections for this worker.
  std::unique_ptr<RateLimiter> newConnRateLimiter_;

  folly::Optional<std::function<int()>> unfinishedHandshakeLimitFn_;

  // EventRecvmsgCallback data
  std::unique_ptr<MsgHdr> msgHdr_;

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
    FOLLY_NODISCARD const std::vector<AcceptObserver*>& getAll() const {
      return observers_;
    }

   private:
    QuicServerWorker* worker_{nullptr};
    std::vector<AcceptObserver*> observers_;
  };

  // List of AcceptObservers
  AcceptObserverList observerList_;

  std::unique_ptr<CCPReader> ccpReader_;

  TimePoint largestPacketReceiveTime_{TimePoint::min()};
};

} // namespace quic
