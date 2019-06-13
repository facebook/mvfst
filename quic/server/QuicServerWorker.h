/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once
#include <unordered_map>

#include <folly/io/async/AsyncUDPSocket.h>

#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/common/Timers.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/server/QuicServerPacketRouter.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <quic/server/QuicUDPSocketFactory.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

class QuicServerWorker : public folly::AsyncUDPSocket::ReadCallback,
                         public QuicServerTransport::RoutingCallback {
 public:
  class WorkerCallback {
   public:
    virtual ~WorkerCallback() = default;
    // Callback for when the worker has errored
    virtual void handleWorkerError(LocalErrorCode error) = 0;

    virtual void routeDataToWorker(
        const folly::SocketAddress& client,
        RoutingData&& routingData,
        NetworkData&& networkData) = 0;
  };

  explicit QuicServerWorker(std::shared_ptr<WorkerCallback> callback);

  ~QuicServerWorker() override;

  folly::EventBase* getEventBase() const;

  void setPacingTimer(TimerHighRes::SharedPtr pacingTimer) noexcept;

  /**
   * Sets the listening socket
   */
  void setSocket(std::unique_ptr<folly::AsyncUDPSocket> socket);

  /**
   * Binds to the given address
   */
  void bind(const folly::SocketAddress& address);

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

  /**
   * Initialize and bind given listening socket to the given takeover address
   * so that this server can accept and process misrouted packets forwarded
   * by other server
   */
  void allowBeingTakenOver(
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
  void setHostId(uint16_t hostId) noexcept;

  void setNewConnectionSocketFactory(QuicUDPSocketFactory* factory);

  void setTransportFactory(QuicServerTransportFactory* factory);

  void setSupportedVersions(const std::vector<QuicVersion>& supportedVersions);

  void setFizzContext(
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  void setTransportSettings(TransportSettings transportSettings);

  /**
   * If true, start to reject any new connection during handshake
   */
  void rejectNewConnections(bool rejectNewConnections);

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
  void setTransportInfoCallback(
      std::unique_ptr<QuicTransportStatsCallback> infoCallback) noexcept;

  /**
   * Return callback for recording various transport stats info.
   */
  QuicTransportStatsCallback* getTransportInfoCallback() const noexcept;

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

  // Read callback
  void getReadBuffer(void** buf, size_t* len) noexcept override;

  void onDataAvailable(
      const folly::SocketAddress& client,
      size_t len,
      bool truncated) noexcept override;

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
      const QuicServerTransport::SourceIdentity& source,
      folly::Optional<ConnectionId> connectionId) noexcept override;

  void onReadError(const folly::AsyncSocketException& ex) noexcept override;

  void onReadClosed() noexcept override;

  void dispatchPacketData(
      const folly::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData) noexcept;

  using ConnIdToTransportMap = std::
      unordered_map<ConnectionId, QuicServerTransport::Ptr, ConnectionIdHash>;

  struct SourceIdentityHash {
    size_t operator()(const QuicServerTransport::SourceIdentity& sid) const {
      return folly::hash::hash_combine(
          folly::hash::fnv32_buf(sid.second.data(), sid.second.size()),
          sid.first.hash());
    }
  };
  using SrcToTransportMap = std::unordered_map<
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
      const TimePoint& receiveTime) noexcept;

  /**
   * Try handling the data as a health check.
   */
  void tryHandlingAsHealthCheck(
      const folly::SocketAddress& client,
      const folly::IOBuf& data);

  /**
   * Forward data to the right worker or to the takeover socket
   */
  void forwardNetworkData(
      const folly::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData);

  /**
   * Return Infocallback ptr for various transport stats (such as packet
   * received, dropped etc). Since the callback is invoked very frequently and
   * per thread, it is important that the implementation is efficient.
   * NOTE: QuicServer does not synchronize across threads before calling it
   */
  QuicTransportStatsCallback* getInfoCallback() {
    return infoCallback_.get();
  }

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

  void sendResetPacket(
      const HeaderForm& headerForm,
      const folly::SocketAddress& client,
      const NetworkData& networkData,
      const ConnectionId& connId);

  std::unique_ptr<folly::AsyncUDPSocket> socket_;
  std::shared_ptr<WorkerCallback> callback_;
  folly::EventBase* evb_{nullptr};

  // factories are owned by quic server
  QuicUDPSocketFactory* socketFactory_;
  QuicServerTransportFactory* transportFactory_;
  std::shared_ptr<CongestionControllerFactory> ccFactory_{nullptr};

  ConnIdToTransportMap connectionIdMap_;
  SrcToTransportMap sourceAddressMap_;

  Buf readBuffer_;
  bool shutdown_{false};
  std::vector<QuicVersion> supportedVersions_;
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  TransportSettings transportSettings_;
  folly::Optional<Buf> healthCheckToken_;
  bool rejectNewConnections_{false};
  uint8_t workerId_{0};
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  uint16_t hostId_{0};
  // QuicServerWorker maintains ownership of the info stats callback
  std::unique_ptr<QuicTransportStatsCallback> infoCallback_;

  // Handle takeover between processes
  std::unique_ptr<TakeoverHandlerCallback> takeoverCB_;
  enum ProcessId processId_ { ProcessId::ZERO };
  TakeoverPacketHandler takeoverPktHandler_;
  bool packetForwardingEnabled_{false};
  using PacketDropReason = QuicTransportStatsCallback::PacketDropReason;
  TimerHighRes::SharedPtr pacingTimer_;
};

} // namespace quic
