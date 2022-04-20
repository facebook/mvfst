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

  MOCK_METHOD((bool), hasData, (), (const));
  MOCK_METHOD((bool), hasImmediateData, (), (const));
  MOCK_METHOD(
      SchedulingResult,
      _scheduleFramesForPacket,
      (PacketBuilderInterface*, uint32_t));
};

class MockReadCallback : public QuicSocket::ReadCallback {
 public:
  ~MockReadCallback() override = default;
  MOCK_METHOD((void), readAvailable, (StreamId), (noexcept));
  MOCK_METHOD((void), readError, (StreamId, QuicError), (noexcept));
};

class MockPeekCallback : public QuicSocket::PeekCallback {
 public:
  ~MockPeekCallback() override = default;
  MOCK_METHOD(
      (void),
      onDataAvailable,
      (StreamId, const folly::Range<PeekIterator>&),
      (noexcept));
  MOCK_METHOD((void), peekError, (StreamId, QuicError), (noexcept));
};

class MockDatagramCallback : public QuicSocket::DatagramCallback {
 public:
  ~MockDatagramCallback() override = default;
  MOCK_METHOD((void), onDatagramsAvailable, (), (noexcept));
};

class MockWriteCallback : public QuicSocket::WriteCallback {
 public:
  ~MockWriteCallback() override = default;
  MOCK_METHOD((void), onStreamWriteReady, (StreamId, uint64_t), (noexcept));
  MOCK_METHOD((void), onConnectionWriteReady, (uint64_t), (noexcept));
  MOCK_METHOD((void), onStreamWriteError, (StreamId, QuicError), (noexcept));
  MOCK_METHOD((void), onConnectionWriteError, (QuicError), (noexcept));
};

class MockConnectionSetupCallback : public QuicSocket::ConnectionSetupCallback {
 public:
  ~MockConnectionSetupCallback() override = default;
  MOCK_METHOD((void), onConnectionSetupError, (QuicError), (noexcept));
  MOCK_METHOD((void), onReplaySafe, (), (noexcept));
  MOCK_METHOD((void), onTransportReady, (), (noexcept));
  MOCK_METHOD((void), onFirstPeerPacketProcessed, (), (noexcept));
  MOCK_METHOD((void), onFullHandshakeDone, (), (noexcept));
};

class MockConnectionCallback : public QuicSocket::ConnectionCallback {
 public:
  ~MockConnectionCallback() override = default;

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

  void onKnob(uint64_t knobSpace, uint64_t knobId, Buf knobBlob) override {
    onKnobMock(knobSpace, knobId, knobBlob.get());
  }
};

class MockDeliveryCallback : public QuicSocket::DeliveryCallback {
 public:
  ~MockDeliveryCallback() override = default;
  MOCK_METHOD(
      void,
      onDeliveryAck,
      (StreamId, uint64_t, std::chrono::microseconds));
  MOCK_METHOD(void, onCanceled, (StreamId, uint64_t));
};

class MockByteEventCallback : public QuicSocket::ByteEventCallback {
 public:
  ~MockByteEventCallback() override = default;
  MOCK_METHOD(void, onByteEventRegistered, (QuicSocket::ByteEvent));
  MOCK_METHOD(void, onByteEvent, (QuicSocket::ByteEvent));
  MOCK_METHOD(void, onByteEventCanceled, (QuicSocket::ByteEvent));

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
      ConnectionCallback* connCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx)
      : QuicServerTransport(evb, std::move(sock), connSetupCb, connCb, ctx) {}

  virtual ~MockQuicTransport() {
    customDestructor();
  }

  MOCK_METHOD(void, customDestructor, ());
  MOCK_METHOD(const folly::SocketAddress&, getPeerAddress, (), (const));
  MOCK_METHOD(const folly::SocketAddress&, getOriginalPeerAddress, (), (const));

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

  void onNetworkData(
      const folly::SocketAddress& peer,
      NetworkData&& networkData) noexcept override {
    onNetworkData(peer, networkData);
  }
  MOCK_METHOD(void, setBufAccessor, (BufAccessor*));
};

class MockLoopDetectorCallback : public LoopDetectorCallback {
 public:
  ~MockLoopDetectorCallback() override = default;
  MOCK_METHOD(
      void,
      onSuspiciousWriteLoops,
      (uint64_t, WriteDataReason, NoWriteReason, const std::string&));
  MOCK_METHOD(void, onSuspiciousReadLoops, (uint64_t, NoReadReason));
};

class MockObserver : public QuicSocket::ManagedObserver {
 public:
  using QuicSocket::ManagedObserver::ManagedObserver;
  MOCK_METHOD((void), attached, (QuicSocket*), (noexcept));
  MOCK_METHOD((void), detached, (QuicSocket*), (noexcept));
  MOCK_METHOD(
      (void),
      destroyed,
      (QuicSocket*, QuicSocket::Observer::DestroyContext* ctx),
      (noexcept));
  MOCK_METHOD(
      (void),
      close,
      (QuicSocket*, const folly::Optional<QuicError>&),
      (noexcept));
};

class MockLegacyObserver : public LegacyObserver {
 public:
  using LegacyObserver::LegacyObserver;
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
      packetsReceived,
      (QuicSocket*, const PacketsReceivedEvent&),
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
            &SocketObserverInterface::LostPacket::lostByReorderThreshold,
            testing::Eq(reorderLoss)),
        testing::Field(
            &SocketObserverInterface::LostPacket::lostByTimeout,
            testing::Eq(timeoutLoss)),
        testing::Field(
            &SocketObserverInterface::LostPacket::packet,
            getLossPacketNum(packetNum)));
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
