/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/portability/GMock.h>

#include <folly/io/async/EventBase.h>
#include <quic/QuicException.h>
#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicSocket.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/common/Timers.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/state/StateData.h>

namespace quic {

class MockFrameScheduler : public FrameScheduler {
 public:
  ~MockFrameScheduler() override = default;

  MockFrameScheduler() : FrameScheduler("mock") {}

  // override methods accepting rvalue ref since gmock doesn't support it
  std::pair<
      folly::Optional<PacketEvent>,
      folly::Optional<RegularQuicPacketBuilder::Packet>>
  scheduleFramesForPacket(
      RegularQuicPacketBuilder&& builderIn,
      uint32_t writableBytes) override {
    auto builder =
        std::make_unique<RegularQuicPacketBuilder>(std::move(builderIn));
    return _scheduleFramesForPacket(builder, writableBytes);
  }

  GMOCK_METHOD0_(, const, , hasData, bool());
  MOCK_METHOD2(
      _scheduleFramesForPacket,
      std::pair<
          folly::Optional<PacketEvent>,
          folly::Optional<RegularQuicPacketBuilder::Packet>>(
          std::unique_ptr<RegularQuicPacketBuilder>&,
          uint32_t));
};

class MockReadCallback : public QuicSocket::ReadCallback {
 public:
  ~MockReadCallback() override = default;
  GMOCK_METHOD1_(, noexcept, , readAvailable, void(StreamId));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      readError,
      void(
          StreamId,
          std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>));
};

class MockPeekCallback : public QuicSocket::PeekCallback {
 public:
  ~MockPeekCallback() override = default;
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      onDataAvailable,
      void(StreamId, const folly::Range<PeekIterator>&));
};

class MockWriteCallback : public QuicSocket::WriteCallback {
 public:
  ~MockWriteCallback() override = default;

  GMOCK_METHOD2_(, noexcept, , onStreamWriteReady, void(StreamId, uint64_t));
  GMOCK_METHOD1_(, noexcept, , onConnectionWriteReady, void(uint64_t));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      onStreamWriteError,
      void(
          StreamId,
          std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>));
  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      onConnectionWriteError,
      void(std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>));
};

class MockConnectionCallback : public QuicSocket::ConnectionCallback {
 public:
  ~MockConnectionCallback() override = default;

  GMOCK_METHOD1_(, noexcept, , onFlowControlUpdate, void(StreamId));
  GMOCK_METHOD1_(, noexcept, , onNewBidirectionalStream, void(StreamId));
  GMOCK_METHOD1_(, noexcept, , onNewUnidirectionalStream, void(StreamId));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      onStopSending,
      void(StreamId, ApplicationErrorCode));
  GMOCK_METHOD0_(, noexcept, , onConnectionEnd, void());
  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      onConnectionError,
      void(std::pair<QuicErrorCode, std::string>));
  GMOCK_METHOD0_(, noexcept, , onReplaySafe, void());
  GMOCK_METHOD0_(, noexcept, , onTransportReady, void());
};

class MockDeliveryCallback : public QuicSocket::DeliveryCallback {
 public:
  ~MockDeliveryCallback() override = default;
  MOCK_METHOD3(
      onDeliveryAck,
      void(StreamId, uint64_t, std::chrono::microseconds));
  MOCK_METHOD2(onCanceled, void(StreamId, uint64_t));
};

class MockDataExpiredCallback : public QuicSocket::DataExpiredCallback {
 public:
  ~MockDataExpiredCallback() override = default;
  GMOCK_METHOD2_(, noexcept, , onDataExpired, void(StreamId, uint64_t));
};

class MockDataRejectedCallback : public QuicSocket::DataRejectedCallback {
 public:
  ~MockDataRejectedCallback() override = default;
  GMOCK_METHOD2_(, noexcept, , onDataRejected, void(StreamId, uint64_t));
};

class MockQuicTransport : public QuicServerTransport {
 public:
  using Ptr = std::shared_ptr<MockQuicTransport>;

  class RoutingCallback : public QuicServerTransport::RoutingCallback {
   public:
    virtual ~RoutingCallback() = default;

    // Called when a connection id is available
    virtual void onConnectionIdAvailable(
        QuicServerTransport::Ptr transport,
        ConnectionId id) noexcept = 0;

    // Called when a connecton id is bound and ip address should not
    // be used any more for routing.
    virtual void onConnectionIdBound(
        QuicServerTransport::Ptr transport) noexcept = 0;

    // Called when the connection is finished and needs to be Unbound.
    virtual void onConnectionUnbound(
        const QuicServerTransport::SourceIdentity& address,
        folly::Optional<ConnectionId> connectionId) noexcept = 0;
  };

  MockQuicTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      ConnectionCallback& cb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx)
      : QuicServerTransport(evb, std::move(sock), cb, ctx) {}

  virtual ~MockQuicTransport() = default;

  GMOCK_METHOD0_(, const, , getEventBase, folly::EventBase*());

  MOCK_CONST_METHOD0(getPeerAddress, const folly::SocketAddress&());

  MOCK_CONST_METHOD0(getOriginalPeerAddress, const folly::SocketAddress&());

  GMOCK_METHOD1_(
      ,
      ,
      ,
      setOriginalPeerAddress,
      void(const folly::SocketAddress&));

  GMOCK_METHOD0_(, , , accept, void());

  GMOCK_METHOD1_(, , , setTransportSettings, void(TransportSettings));

  GMOCK_METHOD1_(, noexcept, , setPacingTimer, void(TimerHighRes::SharedPtr));

  void onNetworkData(
      const folly::SocketAddress& peer,
      NetworkData&& networkData) noexcept override {
    onNetworkData(peer, networkData.data.get());
  }

  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      onNetworkData,
      void(const folly::SocketAddress&, const folly::IOBuf*));

  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      setRoutingCallback,
      void(QuicServerTransport::RoutingCallback*));

  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      setSupportedVersions,
      void(const std::vector<QuicVersion>&));

  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      setServerConnectionIdParams,
      void(ServerConnectionIdParams));

  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      close,
      void(folly::Optional<std::pair<QuicErrorCode, std::string>>));

  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      closeNow,
      void(folly::Optional<std::pair<QuicErrorCode, std::string>>));

  GMOCK_METHOD0_(, const, , hasShutdown, bool());

  GMOCK_METHOD0_(
      ,
      const,
      ,
      getClientConnectionId,
      folly::Optional<ConnectionId>());

  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      setTransportInfoCallback,
      void(QuicTransportStatsCallback*));

  GMOCK_METHOD1_(, noexcept, , setConnectionIdAlgo, void(ConnectionIdAlgo*));
};

class MockLoopDetectorCallback : public LoopDetectorCallback {
 public:
  ~MockLoopDetectorCallback() override = default;
  MOCK_METHOD4(
      onSuspiciousLoops,
      void(uint64_t, WriteDataReason, NoWriteReason, const std::string&));
};

inline std::ostream& operator<<(std::ostream& os, const MockQuicTransport&) {
  return os;
}
} // namespace quic
