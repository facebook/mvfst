/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <condition_variable>
#include <memory>
#include <vector>

#include <folly/ThreadLocal.h>
#include <folly/container/F14Map.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <quic/QuicConstants.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <quic/server/QuicServerWorker.h>
#include <quic/server/QuicUDPSocketFactory.h>
#include <quic/state/QuicConnectionStats.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

class QuicServer : public QuicServerWorker::WorkerCallback,
                   public std::enable_shared_from_this<QuicServer> {
 public:
  using TransportSettingsOverrideFn =
      std::function<folly::Optional<quic::TransportSettings>(
          const quic::TransportSettings&,
          const folly::IPAddress&)>;

  static std::shared_ptr<QuicServer> createQuicServer() {
    return std::shared_ptr<QuicServer>(new QuicServer());
  }

  virtual ~QuicServer();

  // Initialize and start the quic server where the quic server manages
  // the eventbases for workers
  void start(const folly::SocketAddress& address, size_t maxWorkers);

  // Initialize quic server worker per evb.
  void initialize(
      const folly::SocketAddress& address,
      const std::vector<folly::EventBase*>& evbs,
      bool useDefaultTransport = false);

  /**
   * start reading from sockets
   */
  void start();

  /*
   * Pause reading from the listening socket the server workers are bound to
   */
  void pauseRead();

  /*
   * Take in a function to supply overrides for transport parameters, given
   * the client address as input. This can be useful if we are running
   * experiments.
   */
  void setTransportSettingsOverrideFn(TransportSettingsOverrideFn fn);

  /*
   * Transport factory to create server-transport.
   * QuicServer calls 'make()' on the supplied transport factory for *each* new
   * connection.
   * This is useful to do proper set-up on the callers side for each new
   * established connection, such as transport settings and setup sessions.
   */
  void setQuicServerTransportFactory(
      std::unique_ptr<QuicServerTransportFactory> factory);

  /*
   * The socket factory used to create sockets for client connections.  These
   * will end up backing QuicServerTransports and managing per connection state.
   */
  void setQuicUDPSocketFactory(std::unique_ptr<QuicUDPSocketFactory> factory);

  /*
   * The socket factory used to create acceptor sockets.  The sockets created
   * from this factory will listen for udp packets and create new connections
   * via the factory specified in setQuicUDPSocketFactory.
   */
  void setListenerSocketFactory(std::unique_ptr<QuicUDPSocketFactory> factory);

  /**
   * Set factory to create specific congestion controller instances
   * for a given connection
   * This must be set before the server is started.
   */
  void setCongestionControllerFactory(
      std::shared_ptr<CongestionControllerFactory> ccFactory);

  void setRateLimit(
      std::function<uint64_t()> count,
      std::chrono::seconds window);

  void setUnfinishedHandshakeLimit(std::function<int()> limitFn);

  /**
   * Set list of supported QUICVersion for this server. These versions will be
   * used during the 'Version-Negotiation' phase with the client.
   */
  void setSupportedVersion(const std::vector<QuicVersion>& versions);

  /**
   * A token to use for health checking VIPs. When a UDP packet is sent to the
   * server with the exact contents of the health check token, the server will
   * respond with an "OK".
   */
  void setHealthCheckToken(const std::string& healthCheckToken);

  /**
   * Set server TLS context.
   */
  void setFizzContext(
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  /**
   * Set server TLS context for a worker associated with the given eventbase.
   */
  void setFizzContext(
      folly::EventBase* evb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  /**
   * Set socket options for the underlying socket.
   * Options are being set before and after bind, and not at the time of
   * invoking this function.
   */
  void setSocketOptions(const folly::SocketOptionMap& options) noexcept {
    socketOptions_ = options;
  }

  /**
   * Sets whether the underlying socket should set the IPV6_ONLY socket option
   * or not. If set to false, IPv4-mapped IPv6 addresses will be enabled on the
   * socket.
   */
  void setBindV6Only(bool bindV6Only) {
    bindOptions_.bindV6Only = bindV6Only;
  }

  /**
   * Set the server id of the quic server.
   * Note that this function must be called before initialize(..)
   */
  void setProcessId(ProcessId id) noexcept;

  ProcessId getProcessId() const noexcept;

  /**
   * Set the id of the host where this server is running.
   * It is used to make routing decision by setting this id in the ConnectionId
   */
  void setHostId(uint32_t hostId) noexcept;

  /**
   * Set version of connection ID used by quic server.
   * Note that this function must be called before initialize(..)
   */
  void setConnectionIdVersion(ConnectionIdVersion cidVersion) noexcept;

  /**
   * Get transport settings.
   */
  const TransportSettings& getTransportSettings() const noexcept;

  /**
   * Set initial flow control settings for the connection.
   */
  void setTransportSettings(TransportSettings transportSettings);

  /**
   * If the calling application wants to use CCP for CC, it's the
   * app's responsibility to start an instance of CCP -- this ID
   * refers to that unique instance of CCP so we (QuicServer) know
   * how to connect to it.
   */
  void setCcpId(uint64_t ccpId);

  /**
   * Tells the server to start rejecting any new connection. The parameter
   * function is stored and evaluated on each new connection before being
   * accepted.
   */
  void rejectNewConnections(std::function<bool()> rejectFn);

  /**
   * Tells the server to begin rejecting any new connections with block listed
   * source ports. Like rejectNewConnections above, the parameter function is
   * stored and evaluated on each new connection before being accepted.
   */
  void blockListedSrcPort(std::function<bool(uint16_t)> isBlockListedSrcPort);

  /**
   * Returns listening address of this server
   */
  const folly::SocketAddress& getAddress() const;

  /**
   * Returns true iff the server is fully initialized
   */
  bool isInitialized() const noexcept;

  /**
   * Shutdown the sever (and all the workers)
   */
  void shutdown(LocalErrorCode error = LocalErrorCode::SHUTTING_DOWN);

  /**
   * Returns true if the server has begun the termination process or if it has
   * not been initialized
   */
  bool hasShutdown() const noexcept;

  /**
   * Blocks the calling thread until isInitialized() is true
   */
  void waitUntilInitialized();

  void handleWorkerError(LocalErrorCode error) override;

  /**
   * Routes the given data for the given client to the correct worker that may
   * have the state for the connection associated with the given data and client
   */
  void routeDataToWorker(
      const folly::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData,
      folly::Optional<QuicVersion> quicVersion,
      bool isForwardedData = false) override;

  /**
   * Set the transport factory for the worker associated with the given
   * eventbase.
   * This is relevant if the QuicServer is initialized with the vector of
   * event-bases supplied by the caller.
   * Typically, this is useful when the server is already running fixed pool of
   * thread ('workers'), and want to run QuicServer within those workers.
   * In such scenario, the supplied factory's make() will be called (lock-free)
   * upon each new connection establishment within each worker.
   */
  void addTransportFactory(
      folly::EventBase*,
      QuicServerTransportFactory* acceptor);

  /**
   * Initialize necessary steps to enable being taken over of this server by
   * another server, such as binding to a local port so that once another
   * process starts to takeover the port this server is listening to, the other
   * server can forward packets belonging to this server
   * Note that this method cannot be called on a worker's thread.
   * Note that this should also be called after initialize(..),
   * calling this before initialize is undefined.
   */
  void allowBeingTakenOver(const folly::SocketAddress& addr);

  folly::SocketAddress overrideTakeoverHandlerAddress(
      const folly::SocketAddress& addr);

  /*
   * Setup and initialize the listening socket of the old server from the given
   * address to forward misrouted packets belonging to that server during
   * the takeover process
   */
  void startPacketForwarding(const folly::SocketAddress& destAddr);

  /*
   * Disable packet forwarding, even if the packet has no connection id
   * associated with it after the 'delayMS' milliseconds
   */
  void stopPacketForwarding(std::chrono::milliseconds delay);

  /**
   * Set takenover socket fds for the quic server from another process.
   * Quic server calls ::dup for each fd and will not bind to the address for
   * all the valid fds (i.e. not -1) in the given vector
   * NOTE: it must be called before calling 'start()'
   */
  void setListeningFDs(const std::vector<int>& fds);

  /*
   * Returns the File Descriptor of the listening socket for this server.
   */
  int getListeningSocketFD() const;

  /*
   * Returns all the File Descriptor of the listening sockets for each
   * worker for this server.
   */
  std::vector<int> getAllListeningSocketFDs() const noexcept;

  /*
   * Once this server is notified that another server has initiated the takeover
   * it opens a new communication channel so that new server can forward
   * misrouted packets to this server.
   * This method returns the File Descriptor of a local port that this server
   * is listening to.
   */
  int getTakeoverHandlerSocketFD() const;

  TakeoverProtocolVersion getTakeoverProtocolVersion() const noexcept;

  /**
   * Factory to create per worker callback for various transport stats (such as
   * packet received, dropped etc). QuicServer calls 'make' during the
   * initialization _for each worker_.
   * Also, 'make' is called from the worker's eventbase.
   *
   * NOTE: Since the callback is invoked very frequently and per thread,
   * it is important that the implementation of QuicTransportStatsCallback is
   * efficient.
   * NOTE: Quic does not synchronize across threads before calling
   * callbacks for various stats.
   */
  void setTransportStatsCallbackFactory(
      std::unique_ptr<QuicTransportStatsCallbackFactory> statsFactory);

  /**
   * Factory to create per worker ConnectionIdAlgo instance
   * NOTE: it must be set before calling 'start()' or 'initialize(..)'
   */
  void setConnectionIdAlgoFactory(
      std::unique_ptr<ConnectionIdAlgoFactory> connIdAlgoFactory);

  /**
   * Returns vector of running eventbases.
   * This is useful if QuicServer is initialized with a 'default' mode by just
   * specifying number of workers.
   */
  std::vector<folly::EventBase*> getWorkerEvbs() const noexcept;

  /**
   * Adds observer for accept events.
   *
   * Adds for the worker associated with the given EventBase. This is relevant
   * if the QuicServer is initialized with a vector of EventBase supplied by
   * the caller. With this approach, each worker thread can (but is not
   * required to) have its own observer, removing the need for the observer
   * implementation to be thread safe.
   *
   * Can be used to install socket observers and instrumentation without
   * changing / interfering with application-specific acceptor logic.
   *
   * See AcceptObserver class for details.
   *
   * @param evb           Worker EventBase for which we want to add observer.
   * @param observer      Observer to add (implements AcceptObserver).
   * @return              Whether worker found and observer added.
   */
  bool addAcceptObserver(folly::EventBase* evb, AcceptObserver* observer);

  /**
   * Remove observer for accept events.
   *
   * Removes for the worker associated with the given EventBase.
   *
   * @param evb           Worker EventBase for which we want to remove observer.
   * @param observer      Observer to remove.
   * @return              Whether worker + observer found and observer removed.
   */
  bool removeAcceptObserver(folly::EventBase* evb, AcceptObserver* observer);

  void getAllConnectionsStats(std::vector<QuicConnectionStats>& stats);

 private:
  QuicServer();

  static std::unique_ptr<folly::EventBaseBackendBase> getEventBaseBackend();

  // helper function to initialize workers
  void initializeWorkers(
      const std::vector<folly::EventBase*>& evbs,
      bool useDefaultTransport);

  std::unique_ptr<QuicServerWorker> newWorkerWithoutSocket();

  // helper method to run the given function in all worker asynchronously
  void runOnAllWorkers(const std::function<void(QuicServerWorker*)>& func);

  // helper method to run the given function in all worker synchronously
  void runOnAllWorkersSync(const std::function<void(QuicServerWorker*)>& func);

  void bindWorkersToSocket(
      const folly::SocketAddress& address,
      const std::vector<folly::EventBase*>& evbs);

  std::vector<QuicVersion> supportedVersions_{
      {QuicVersion::MVFST,
       QuicVersion::MVFST_EXPERIMENTAL,
       QuicVersion::MVFST_ALIAS,
       QuicVersion::QUIC_V1,
       QuicVersion::QUIC_DRAFT}};

  bool isUsingCCP();

  std::atomic<bool> shutdown_{true};
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  TransportSettings transportSettings_;
  std::mutex startMutex_;
  std::atomic<bool> initialized_{false};
  std::atomic<bool> workersInitialized_{false};
  std::condition_variable startCv_;
  std::atomic<bool> takeoverHandlerInitialized_{false};
  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> workerEvbs_;

  std::vector<std::unique_ptr<QuicServerWorker>> workers_;
  // Thread local pointer to QuicServerWorker. This is useful to avoid
  // looking up the worker to route to.
  // NOTE: QuicServer still maintains ownership of all the workers and manages
  // their destruction
  folly::ThreadLocalPtr<QuicServerWorker> workerPtr_;
  folly::F14FastMap<folly::EventBase*, QuicServerWorker*> evbToWorkers_;
  std::unique_ptr<QuicServerTransportFactory> transportFactory_;
  folly::F14FastMap<folly::EventBase*, QuicServerTransportFactory*>
      evbToAcceptors_;
  // factory used for workers to create their listening / bound sockets
  std::unique_ptr<QuicUDPSocketFactory> listenerSocketFactory_;
  // factory used by workers to create sockets for connection transports
  std::unique_ptr<QuicUDPSocketFactory> socketFactory_;
  // factory used to create specific instance of Congestion control algorithm
  std::shared_ptr<CongestionControllerFactory> ccFactory_;

  std::shared_ptr<folly::EventBaseObserver> evbObserver_;
  folly::Optional<std::string> healthCheckToken_;
  // vector of all the listening fds on each quic server worker
  std::vector<int> listeningFDs_;
  ProcessId processId_{ProcessId::ZERO};
  uint32_t hostId_{0};
  ConnectionIdVersion cidVersion_{ConnectionIdVersion::V1};
  std::function<bool()> rejectNewConnections_{[]() { return false; }};
  std::function<bool(uint16_t)> isBlockListedSrcPort_{
      [](uint16_t) { return false; }};
  // factory to create per worker QuicTransportStatsCallback
  std::unique_ptr<QuicTransportStatsCallbackFactory> transportStatsFactory_;
  // factory to create per worker ConnectionIdAlgo
  std::unique_ptr<ConnectionIdAlgoFactory> connIdAlgoFactory_;
  // Impl of ConnectionIdAlgo to make routing decisions from ConnectionId
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  // Used to override certain transport parameters, given the client address
  TransportSettingsOverrideFn transportSettingsOverrideFn_;
  // address that the server is bound to
  folly::SocketAddress boundAddress_;
  folly::SocketOptionMap socketOptions_;
  // Rate limits
  struct RateLimit {
    RateLimit(std::function<uint64_t()> c, std::chrono::seconds w)
        : count(std::move(c)), window(w) {}
    std::function<uint64_t()> count;
    std::chrono::seconds window;
  };
  folly::Optional<RateLimit> rateLimit_;

  std::function<int()> unfinishedHandshakeLimitFn_{[]() { return 1048576; }};

  // Options to AsyncUDPSocket::bind, only controls IPV6_ONLY currently.
  folly::AsyncUDPSocket::BindOptions bindOptions_;

#ifdef CCP_ENABLED
  std::unique_ptr<folly::ScopedEventBaseThread> ccpEvb_;
#endif
  // Random number to uniquely identify this instance of quic to ccp
  // in case there are multiple concurrent instances (e.g. when proxygen is
  // migrating connections and there are two concurrent instances of proxygen)
  uint64_t ccpId_{0};
};

} // namespace quic
