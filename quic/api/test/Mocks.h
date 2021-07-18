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
  SchedulingResult scheduleFramesForPacket(
      PacketBuilderInterface&& builderIn,
      uint32_t writableBytes) override {
    return _scheduleFramesForPacket(&builderIn, writableBytes);
  }

  GMOCK_METHOD0_(, const, , hasData, bool());
  MOCK_METHOD2(
      _scheduleFramesForPacket,
      SchedulingResult(PacketBuilderInterface*, uint32_t));
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
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      peekError,
      void(
          StreamId,
          std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>));
};

class MockDatagramCallback : public QuicSocket::DatagramCallback {
 public:
  ~MockDatagramCallback() override = default;
  GMOCK_METHOD0_(, noexcept, , onDatagramsAvailable, void());
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
  GMOCK_METHOD0_(, noexcept, , onFirstPeerPacketProcessed, void());
  GMOCK_METHOD1_(, noexcept, , onBidirectionalStreamsAvailable, void(uint64_t));
  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      onUnidirectionalStreamsAvailable,
      void(uint64_t));
  GMOCK_METHOD0_(, noexcept, , onAppRateLimited, void());
  GMOCK_METHOD3_(
      ,
      noexcept,
      ,
      onKnobMock,
      void(uint64_t, uint64_t, folly::IOBuf*));

  void onKnob(uint64_t knobSpace, uint64_t knobId, Buf knobBlob) override {
    onKnobMock(knobSpace, knobId, knobBlob.get());
  }
};

class MockDeliveryCallback : public QuicSocket::DeliveryCallback {
 public:
  ~MockDeliveryCallback() override = default;
  MOCK_METHOD3(
      onDeliveryAck,
      void(StreamId, uint64_t, std::chrono::microseconds));
  MOCK_METHOD2(onCanceled, void(StreamId, uint64_t));
};

class MockByteEventCallback : public QuicSocket::ByteEventCallback {
 public:
  ~MockByteEventCallback() override = default;
  MOCK_METHOD1(onByteEventRegistered, void(QuicSocket::ByteEvent));
  MOCK_METHOD1(onByteEvent, void(QuicSocket::ByteEvent));
  MOCK_METHOD1(onByteEventCanceled, void(QuicSocket::ByteEvent));

  static auto getTxMatcher(StreamId id, uint64_t offset) {
    return AllOf(
        testing::Field(
            &QuicSocket::ByteEvent::type,
            testing::Eq(QuicSocket::ByteEvent::Type::TX)),
        testing::Field(&QuicSocket::ByteEvent::id, testing::Eq(id)),
        testing::Field(&QuicSocket::ByteEvent::offset, testing::Eq(offset)));
  }

  static auto getAckMatcher(StreamId id, uint64_t offset) {
    return AllOf(
        testing::Field(
            &QuicSocket::ByteEvent::type,
            testing::Eq(QuicSocket::ByteEvent::Type::ACK)),
        testing::Field(&QuicSocket::ByteEvent::id, testing::Eq(id)),
        testing::Field(&QuicSocket::ByteEvent::offset, testing::Eq(offset)));
  }
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
        QuicServerTransport*,
        const QuicServerTransport::SourceIdentity& address,
        const std::vector<ConnectionIdData>& connectionIdData) noexcept = 0;
  };

  MockQuicTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      ConnectionCallback& cb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx)
      : QuicServerTransport(evb, std::move(sock), cb, ctx) {}

  virtual ~MockQuicTransport() {
    customDestructor();
  }

  MOCK_METHOD0(customDestructor, void());

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
    onNetworkData(peer, networkData);
  }

  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      onNetworkData,
      void(const folly::SocketAddress&, const NetworkData&));

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
  GMOCK_METHOD0_(
      ,
      const,
      ,
      getClientChosenDestConnectionId,
      folly::Optional<ConnectionId>());

  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      setTransportStatsCallback,
      void(QuicTransportStatsCallback*));

  GMOCK_METHOD1_(, noexcept, , setConnectionIdAlgo, void(ConnectionIdAlgo*));

  MOCK_METHOD1(setBufAccessor, void(BufAccessor*));
};

class MockLoopDetectorCallback : public LoopDetectorCallback {
 public:
  ~MockLoopDetectorCallback() override = default;
  MOCK_METHOD4(
      onSuspiciousWriteLoops,
      void(uint64_t, WriteDataReason, NoWriteReason, const std::string&));
  MOCK_METHOD2(onSuspiciousReadLoops, void(uint64_t, NoReadReason));
};

class MockObserver : public Observer {
 public:
  MockObserver() : Observer(Observer::Config()) {}
  MockObserver(const Observer::Config& observerConfig)
      : Observer(observerConfig) {}
  GMOCK_METHOD1_(, noexcept, , observerAttach, void(QuicSocket*));
  GMOCK_METHOD1_(, noexcept, , observerDetach, void(QuicSocket*));
  GMOCK_METHOD1_(, noexcept, , destroy, void(QuicSocket*));
  GMOCK_METHOD2_(, noexcept, , evbAttach, void(QuicSocket*, folly::EventBase*));
  GMOCK_METHOD2_(, noexcept, , evbDetach, void(QuicSocket*, folly::EventBase*));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      close,
      void(
          QuicSocket*,
          const folly::Optional<std::pair<QuicErrorCode, std::string>>&));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      startWritingFromAppLimited,
      void(QuicSocket*, const AppLimitedEvent&));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      packetsWritten,
      void(QuicSocket*, const AppLimitedEvent&));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      appRateLimited,
      void(QuicSocket*, const AppLimitedEvent&));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      packetLossDetected,
      void(QuicSocket*, const LossEvent&));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      rttSampleGenerated,
      void(QuicSocket*, const PacketRTT&));
  GMOCK_METHOD1_(, noexcept, , pmtuProbingStarted, void(QuicSocket*));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      pmtuBlackholeDetected,
      void(QuicSocket*, const PMTUBlackholeEvent&));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      pmtuUpperBoundDetected,
      void(QuicSocket*, const PMTUUpperBoundEvent&));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      spuriousLossDetected,
      void(QuicSocket*, const SpuriousLossEvent&));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      knobFrameReceived,
      void(QuicSocket*, const KnobFrameEvent&));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      packetsRemoved,
      void(QuicSocket*, const std::shared_ptr<std::vector<OutstandingPacket>>));

  static auto getPacketNum(PacketNum packetNum) {
    return testing::Field(
        &OutstandingPacket::packet,
        testing::Field(
            &RegularPacket::header,
            testing::Property(&PacketHeader::getPacketSequenceNum, packetNum)));
  }

  static auto getLossPacketMatcher(
      PacketNum packetNum,
      bool reorderLoss,
      bool timeoutLoss) {
    return AllOf(
        testing::Field(
            &Observer::LostPacket::lostByReorderThreshold,
            testing::Eq(reorderLoss)),
        testing::Field(
            &Observer::LostPacket::lostByTimeout, testing::Eq(timeoutLoss)),
        testing::Field(&Observer::LostPacket::packet, getPacketNum(packetNum)));
  }
};

inline std::ostream& operator<<(std::ostream& os, const MockQuicTransport&) {
  return os;
}
} // namespace quic
