/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
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

  explicit MockFrameScheduler(QuicConnectionStateBase* conn)
      : FrameScheduler("mock", *conn) {}

  // override methods accepting rvalue ref since gmock doesn't support it
  SchedulingResult scheduleFramesForPacket(
      PacketBuilderInterface&& builderIn,
      uint32_t writableBytes) override {
    return _scheduleFramesForPacket(&builderIn, writableBytes);
  }

#if defined(MOCK_METHOD)
  MOCK_METHOD((bool), hasData, (), (const));
#else
  GMOCK_METHOD0_(, const, , hasData, bool());
#endif
  MOCK_METHOD2(
      _scheduleFramesForPacket,
      SchedulingResult(PacketBuilderInterface*, uint32_t));
};

class MockReadCallback : public QuicSocket::ReadCallback {
 public:
  ~MockReadCallback() override = default;
#if defined(MOCK_METHOD)
  MOCK_METHOD((void), readAvailable, (StreamId), (noexcept));
  MOCK_METHOD((void), readError, (StreamId, QuicError), (noexcept));
#else
  GMOCK_METHOD1_(, noexcept, , readAvailable, void(StreamId));
  GMOCK_METHOD2_(, noexcept, , readError, void(StreamId, QuicError));
#endif
};

class MockPeekCallback : public QuicSocket::PeekCallback {
 public:
  ~MockPeekCallback() override = default;
#if defined(MOCK_METHOD)
  MOCK_METHOD(
      (void),
      onDataAvailable,
      (StreamId, const folly::Range<PeekIterator>&),
      (noexcept));
  MOCK_METHOD((void), peekError, (StreamId, QuicError), (noexcept));
#else
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      onDataAvailable,
      void(StreamId, const folly::Range<PeekIterator>&));
  GMOCK_METHOD2_(, noexcept, , peekError, void(StreamId, QuicError));
#endif
};

class MockDatagramCallback : public QuicSocket::DatagramCallback {
 public:
  ~MockDatagramCallback() override = default;
#if defined(MOCK_METHOD)
  MOCK_METHOD((void), onDatagramsAvailable, (), (noexcept));
#else
  GMOCK_METHOD0_(, noexcept, , onDatagramsAvailable, void());
#endif
};

class MockWriteCallback : public QuicSocket::WriteCallback {
 public:
  ~MockWriteCallback() override = default;

#if defined(MOCK_METHOD)
  MOCK_METHOD((void), onStreamWriteReady, (StreamId, uint64_t), (noexcept));
  MOCK_METHOD((void), onConnectionWriteReady, (uint64_t), (noexcept));
  MOCK_METHOD((void), onStreamWriteError, (StreamId, QuicError), (noexcept));
  MOCK_METHOD((void), onConnectionWriteError, (QuicError), (noexcept));
#else
  GMOCK_METHOD2_(, noexcept, , onStreamWriteReady, void(StreamId, uint64_t));
  GMOCK_METHOD1_(, noexcept, , onConnectionWriteReady, void(uint64_t));
  GMOCK_METHOD2_(, noexcept, , onStreamWriteError, void(StreamId, QuicError));
  GMOCK_METHOD1_(, noexcept, , onConnectionWriteError, void(QuicError));
#endif
};

class MockConnectionSetupCallback : public QuicSocket::ConnectionSetupCallback {
 public:
  ~MockConnectionSetupCallback() override = default;
#if defined(MOCK_METHOD)
  MOCK_METHOD((void), onConnectionSetupError, (QuicError), (noexcept));
  MOCK_METHOD((void), onReplaySafe, (), (noexcept));
  MOCK_METHOD((void), onTransportReady, (), (noexcept));
  MOCK_METHOD((void), onFirstPeerPacketProcessed, (), (noexcept));
#else
  GMOCK_METHOD1_(, noexcept, , onConnectionSetupError, void(QuicError));
  GMOCK_METHOD0_(, noexcept, , onReplaySafe, void());
  GMOCK_METHOD0_(, noexcept, , onTransportReady, void());
  GMOCK_METHOD0_(, noexcept, , onFirstPeerPacketProcessed, void());
#endif
};

class MockConnectionCallbackNew : public QuicSocket::ConnectionCallbackNew {
 public:
  ~MockConnectionCallbackNew() override = default;

#if defined(MOCK_METHOD)
  MOCK_METHOD((void), onFlowControlUpdate, (StreamId), (noexcept));
  MOCK_METHOD((void), onNewBidirectionalStream, (StreamId), (noexcept));
  MOCK_METHOD((void), onNewUnidirectionalStream, (StreamId), (noexcept));
  MOCK_METHOD(
      (void),
      onStopSending,
      (StreamId, ApplicationErrorCode),
      (noexcept));
  MOCK_METHOD((void), onConnectionEnd, (), (noexcept));
  MOCK_METHOD((void), onConnectionError, (QuicError), (noexcept));
  MOCK_METHOD((void), onBidirectionalStreamsAvailable, (uint64_t), (noexcept));
  MOCK_METHOD((void), onUnidirectionalStreamsAvailable, (uint64_t), (noexcept));
  MOCK_METHOD((void), onAppRateLimited, (), (noexcept));
  MOCK_METHOD(
      (void),
      onKnobMock,
      (uint64_t, uint64_t, folly::IOBuf*),
      (noexcept));
#else
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
  GMOCK_METHOD1_(, noexcept, , onConnectionError, void(QuicError));
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
#endif

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
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallbackNew* connCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx)
      : QuicServerTransport(evb, std::move(sock), connSetupCb, connCb, ctx) {}

  virtual ~MockQuicTransport() {
    customDestructor();
  }

  MOCK_METHOD0(customDestructor, void());
  MOCK_CONST_METHOD0(getPeerAddress, const folly::SocketAddress&());
  MOCK_CONST_METHOD0(getOriginalPeerAddress, const folly::SocketAddress&());

#if defined(MOCK_METHOD)
  MOCK_METHOD((folly::EventBase*), getEventBase, (), (const));
  MOCK_METHOD((void), accept, (), ());
  MOCK_METHOD((void), setTransportSettings, (TransportSettings), ());
  MOCK_METHOD((void), setOriginalPeerAddress, (const folly::SocketAddress&));
  MOCK_METHOD((void), setPacingTimer, (TimerHighRes::SharedPtr), (noexcept));
  MOCK_METHOD(
      (void),
      onNetworkData,
      (const folly::SocketAddress&, const NetworkData&),
      (noexcept));
  MOCK_METHOD(
      (void),
      setRoutingCallback,
      (QuicServerTransport::RoutingCallback*),
      (noexcept));
  MOCK_METHOD(
      (void),
      setHandshakeFinishedCallback,
      (QuicServerTransport::HandshakeFinishedCallback*),
      (noexcept));
  MOCK_METHOD(
      (void),
      setSupportedVersions,
      (const std::vector<QuicVersion>&),
      (noexcept));
  MOCK_METHOD(
      (void),
      setServerConnectionIdParams,
      (ServerConnectionIdParams),
      (noexcept));
  MOCK_METHOD((void), close, (folly::Optional<QuicError>), (noexcept));
  MOCK_METHOD((void), closeNow, (folly::Optional<QuicError>), (noexcept));
  MOCK_METHOD((bool), hasShutdown, (), (const));
  MOCK_METHOD(
      (folly::Optional<ConnectionId>),
      getClientConnectionId,
      (),
      (const));
  MOCK_METHOD(
      (folly::Optional<ConnectionId>),
      getClientChosenDestConnectionId,
      (),
      (const));
  MOCK_METHOD(
      (void),
      setTransportStatsCallback,
      (QuicTransportStatsCallback*),
      (noexcept));
  MOCK_METHOD((void), setConnectionIdAlgo, (ConnectionIdAlgo*), (noexcept));
#else
  GMOCK_METHOD0_(, const, , getEventBase, folly::EventBase*());
  GMOCK_METHOD0_(, , , accept, void());
  GMOCK_METHOD1_(
      ,
      ,
      ,
      setOriginalPeerAddress,
      void(const folly::SocketAddress&));
  GMOCK_METHOD1_(, , , setTransportSettings, void(TransportSettings));
  GMOCK_METHOD1_(, noexcept, , setPacingTimer, void(TimerHighRes::SharedPtr));
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
      setHandshakeFinishedCallback,
      void(QuicServerTransport::HandshakeFinishedCallback*));
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
  GMOCK_METHOD1_(, noexcept, , close, void(folly::Optional<QuicError>));
  GMOCK_METHOD1_(, noexcept, , closeNow, void(folly::Optional<QuicError>));
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
#endif

  void onNetworkData(
      const folly::SocketAddress& peer,
      NetworkData&& networkData) noexcept override {
    onNetworkData(peer, networkData);
  }
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
#if defined(MOCK_METHOD)
  MOCK_METHOD((void), observerAttach, (QuicSocket*), (noexcept));
  MOCK_METHOD((void), observerDetach, (QuicSocket*), (noexcept));
  MOCK_METHOD((void), destroy, (QuicSocket*), (noexcept));
  MOCK_METHOD((void), evbAttach, (QuicSocket*, folly::EventBase*), (noexcept));
  MOCK_METHOD((void), evbDetach, (QuicSocket*, folly::EventBase*), (noexcept));
  MOCK_METHOD(
      (void),
      close,
      (QuicSocket*, const folly::Optional<QuicError>&),
      (noexcept));
  MOCK_METHOD(
      (void),
      startWritingFromAppLimited,
      (QuicSocket*, const AppLimitedEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      packetsWritten,
      (QuicSocket*, const PacketsWrittenEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      appRateLimited,
      (QuicSocket*, const AppLimitedEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      acksProcessed,
      (QuicSocket*, const AcksProcessedEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      packetLossDetected,
      (QuicSocket*, const LossEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      rttSampleGenerated,
      (QuicSocket*, const PacketRTT&),
      (noexcept));
  MOCK_METHOD((void), pmtuProbingStarted, (QuicSocket*), (noexcept));
  MOCK_METHOD(
      (void),
      pmtuBlackholeDetected,
      (QuicSocket*, const PMTUBlackholeEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      pmtuUpperBoundDetected,
      (QuicSocket*, const PMTUUpperBoundEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      spuriousLossDetected,
      (QuicSocket*, const SpuriousLossEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      knobFrameReceived,
      (QuicSocket*, const KnobFrameEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      streamOpened,
      (QuicSocket*, const StreamOpenEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      streamClosed,
      (QuicSocket*, const StreamCloseEvent&),
      (noexcept));
#else
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
      void(QuicSocket*, const folly::Optional<QuicError>&));
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
      void(QuicSocket*, const PacketsWrittenEvent&));
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
      acksProcessed,
      void(QuicSocket*, const AcksProcessedEvent&));
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
      streamOpened,
      void(QuicSocket*, const StreamOpenEvent&));
  GMOCK_METHOD2_(
      ,
      noexcept,
      ,
      streamClosed,
      void(QuicSocket*, const StreamCloseEvent&));
#endif

  static auto getLossPacketNum(PacketNum packetNum) {
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
        testing::Field(
            &Observer::LostPacket::packet, getLossPacketNum(packetNum)));
  }

  static auto getStreamEventMatcher(
      const StreamId id,
      StreamInitiator initiator,
      StreamDirectionality directionality) {
    return AllOf(
        testing::Field(&StreamEvent::streamId, testing::Eq(id)),
        testing::Field(&StreamEvent::streamInitiator, testing::Eq(initiator)),
        testing::Field(
            &StreamEvent::streamDirectionality, testing::Eq(directionality)));
  }
};

inline std::ostream& operator<<(std::ostream& os, const MockQuicTransport&) {
  return os;
}
} // namespace quic
