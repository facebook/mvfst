/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/QuicAsyncUDPSocketWrapper.h>

#include <quic/QuicConstants.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <quic/server/QuicUDPSocketFactory.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {
class QuicServerWorker;

/**
 * ID for Quic Server, that gets toggled for each consecutive
 * running server.
 */
enum class ProcessId : uint8_t { ZERO = 0x0, ONE = 0x1 };

/*
 * Version of the 'takeover' protocol
 */
enum class TakeoverProtocolVersion : uint32_t {
  V0 = 0x00000001,
};

struct RoutingData {
  HeaderForm headerForm;
  bool isInitial;
  bool is0Rtt;
  // true if destinationConnId below was randomly chosen by the client (for 0rtt
  // or initial packets), or issued by server after processing 0rtt/initial
  const bool clientChosenDcid;

  // The destination connection id is the connection id picked by the
  // server for non initial packets and the sourceConnId is the one chosen
  // by the peer.
  ConnectionId destinationConnId;

  //
  // Source connection may not be present for short header packets.
  folly::Optional<ConnectionId> sourceConnId;

  RoutingData(
      HeaderForm headerFormIn,
      bool isInitialIn,
      bool is0RttIn,
      ConnectionId destinationConnIdIn,
      folly::Optional<ConnectionId> sourceConnIdIn)
      : headerForm(headerFormIn),
        isInitial(isInitialIn),
        is0Rtt(is0RttIn),
        clientChosenDcid(isInitial || is0Rtt),
        destinationConnId(std::move(destinationConnIdIn)),
        sourceConnId(std::move(sourceConnIdIn)) {}
};

/**
 * Handler that appropriately encodes and decodes packets during takeover of
 * listening sockets.
 * It's purpose is to forward the packets belonging to
 * another quic server (on the same host) and process the packets forwarded by
 * another quic server.
 */
class TakeoverPacketHandler {
 public:
  explicit TakeoverPacketHandler(QuicServerWorker* worker);
  virtual ~TakeoverPacketHandler();

  void setSocketFactory(QuicUDPSocketFactory* factory);

  void setDestination(const folly::SocketAddress& destAddr);

  void forwardPacketToAnotherServer(
      const folly::SocketAddress& peerAddress,
      Buf data,
      const TimePoint& packetReceiveTime);

  void processForwardedPacket(const folly::SocketAddress& client, Buf data);

  void stop();

  TakeoverProtocolVersion getTakeoverProtocolVersion() const noexcept {
    return TakeoverProtocolVersion::V0;
  }

  TakeoverProtocolVersion takeoverProtocol_{TakeoverProtocolVersion::V0};

 private:
  std::unique_ptr<QuicAsyncUDPSocketWrapper> makeSocket(folly::EventBase* evb);
  void forwardPacket(Buf packet);
  // prevent copying
  TakeoverPacketHandler(const TakeoverPacketHandler&);
  TakeoverPacketHandler& operator=(const TakeoverPacketHandler&);

  QuicServerWorker* worker_;
  folly::SocketAddress pktForwardDestAddr_;
  std::unique_ptr<QuicAsyncUDPSocketWrapper> pktForwardingSocket_;
  bool packetForwardingEnabled_{false};
  QuicUDPSocketFactory* socketFactory_{nullptr};
};

/**
 * Class for handling packets after the socket takeover has initiated
 */
class TakeoverHandlerCallback : public QuicAsyncUDPSocketWrapper::ReadCallback,
                                private folly::DelayedDestruction {
 public:
  explicit TakeoverHandlerCallback(
      QuicServerWorker* worker,
      TakeoverPacketHandler& takeoverPktHandler,
      const TransportSettings& transportSettings,
      std::unique_ptr<QuicAsyncUDPSocketWrapper> socket);

  // prevent copying
  TakeoverHandlerCallback(const TakeoverHandlerCallback&) = delete;
  TakeoverHandlerCallback& operator=(const TakeoverHandlerCallback&) = delete;

  virtual ~TakeoverHandlerCallback() override;

  void bind(const folly::SocketAddress& addr);

  /**
   * Rebinds the given socket to the given address
   * Frees existing socket if any
   */
  void rebind(
      std::unique_ptr<QuicAsyncUDPSocketWrapper> socket,
      const folly::SocketAddress& addr);

  void pause();

  int getSocketFD();

  const folly::SocketAddress& getAddress() const;

  // AsyncUDPSocket ReadCallback methods
  void getReadBuffer(void** buf, size_t* len) noexcept override;

  void onDataAvailable(
      const folly::SocketAddress& client,
      size_t len,
      bool truncated,
      OnDataAvailableParams params) noexcept override;

  void onReadError(const folly::AsyncSocketException& ex) noexcept override;

  void onReadClosed() noexcept override;

 private:
  QuicServerWorker* worker_;
  // QuicServerWorker owns Packethandler
  TakeoverPacketHandler& takeoverPktHandler_;
  // QuicServerWorker owns the transport settings
  const TransportSettings& transportSettings_;
  folly::SocketAddress address_;
  std::unique_ptr<QuicAsyncUDPSocketWrapper> socket_;
  Buf readBuffer_;
};
} // namespace quic
