/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <condition_variable>
#include <memory>
#include <vector>

#include <folly/ThreadLocal.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <quic/QuicConstants.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <quic/server/QuicServerWorker.h>
#include <quic/server/QuicUDPSocketFactory.h>
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
   * Set the server id of the quic server.
   * Note that this function must be called before initialize(..)
   */
  void setProcessId(ProcessId id) noexcept;

  ProcessId getProcessId() const noexcept;

  /**
   * Set the id of the host where this server is running.
   * It is used to make routing decision by setting this id in the ConnectionId
   */
  void setHostId(uint16_t hostId) noexcept;

  /**
   * Set initial flow control settings for the connection.
   */
  void setTransportSettings(TransportSettings transportSettings);

  /**
   * Tells the server to start rejecting any new connection
   */
  void rejectNewConnections(bool reject);

  /**
   * Tells the server to disable partial reliability in transport settings.
   * Any new connections negotiated after will have partial reliability enabled
   * or disabled accordingly.
   */
  void enablePartialReliability(bool enabled);

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

  void handleWorkerError(LocalErrorCode error);

  /**
   * Routes the given data for the given client to the correct worker that may
   * have the state for the connection associated with the given data and client
   */
  void routeDataToWorker(
      const folly::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData);

  /**
   * Set an EventBaseObserver for server and all its workers. This only works
   * after server is already start()-ed, no-op otherwise.
   */
  void setEventBaseObserver(std::shared_ptr<folly::EventBaseObserver> observer);

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

 private:
  QuicServer();

  // helper function to initialize workers
  void initializeWorkers(
      const std::vector<folly::EventBase*>& evbs,
      bool useDefaultTransport);

  std::unique_ptr<QuicServerWorker> newWorkerWithoutSocket();

  void runOnAllWorkers(std::function<void(QuicServerWorker*)> func);

  void bindWorkersToSocket(
      const folly::SocketAddress& address,
      const std::vector<folly::EventBase*>& evbs);

  std::vector<QuicVersion> supportedVersions_{
      {QuicVersion::MVFST, QuicVersion::MVFST_OLD, QuicVersion::QUIC_DRAFT}};
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
  std::unordered_map<folly::EventBase*, QuicServerWorker*> evbToWorkers_;
  std::unique_ptr<QuicServerTransportFactory> transportFactory_;
  std::unordered_map<folly::EventBase*, QuicServerTransportFactory*>
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
  uint16_t hostId_{0};
  bool rejectNewConnections_{false};
  // factory to create per worker QuicTransportStatsCallback
  std::unique_ptr<QuicTransportStatsCallbackFactory> transportStatsFactory_;
  // factory to create per worker ConnectionIdAlgo
  std::unique_ptr<ConnectionIdAlgoFactory> connIdAlgoFactory_;
  // Impl of ConnectionIdAlgo to make routing decisions from ConnectionId
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  // Used to override certain transport parameters, given the client address
  TransportSettingsOverrideFn transportSettingsOverrideFn_;
};

} // namespace quic
