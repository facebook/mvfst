/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>

#include <quic/QuicException.h>
#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicCallbacks.h>
#include <quic/api/QuicSocket.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/common/NetworkData.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/events/QuicTimer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/state/StateData.h>

namespace quic {

class MockFrameScheduler : public FrameScheduler {
 public:
  ~MockFrameScheduler() override = default;

  explicit MockFrameScheduler(QuicConnectionStateBase* conn)
      : FrameScheduler("mock", *conn) {}

  // override methods accepting rvalue ref since gmock doesn't support it
  quic::Expected<SchedulingResult, QuicError> scheduleFramesForPacket(
      PacketBuilderInterface&& builderIn,
      uint32_t writableBytes) override {
    return _scheduleFramesForPacket(&builderIn, writableBytes);
  }

  MOCK_METHOD((bool), hasData, (), (const));
  MOCK_METHOD((bool), hasImmediateData, (), (const));
  MOCK_METHOD(
      (quic::Expected<SchedulingResult, QuicError>),
      _scheduleFramesForPacket,
      (PacketBuilderInterface*, uint32_t));
};

class MockReadCallback : public QuicSocket::ReadCallback {
 public:
  ~MockReadCallback() override = default;
  MOCK_METHOD((void), readAvailable, (StreamId), (noexcept));
  MOCK_METHOD(
      (void),
      readAvailableWithGroup,
      (StreamId, StreamGroupId),
      (noexcept));
  MOCK_METHOD((void), readError, (StreamId, QuicError), (noexcept));
  MOCK_METHOD(
      (void),
      readErrorWithGroup,
      (StreamId, StreamGroupId, QuicError),
      (noexcept));
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
  MOCK_METHOD(
      (void),
      onPrimingDataAvailable,
      (std::vector<quic::BufPtr>&&),
      (noexcept));
};

class MockConnectionCallback : public QuicSocket::ConnectionCallback {
 public:
  ~MockConnectionCallback() override = default;

  MOCK_METHOD((void), onFlowControlUpdate, (StreamId), (noexcept));
  MOCK_METHOD((void), onNewBidirectionalStream, (StreamId), (noexcept));
  MOCK_METHOD(
      (void),
      onNewBidirectionalStreamGroup,
      (StreamGroupId),
      (noexcept));
  MOCK_METHOD(
      (void),
      onNewBidirectionalStreamInGroup,
      (StreamId, StreamGroupId),
      (noexcept));
  MOCK_METHOD((void), onNewUnidirectionalStream, (StreamId), (noexcept));
  MOCK_METHOD(
      (void),
      onNewUnidirectionalStreamGroup,
      (StreamGroupId),
      (noexcept));
  MOCK_METHOD(
      (void),
      onNewUnidirectionalStreamInGroup,
      (StreamId, StreamGroupId),
      (noexcept));
  MOCK_METHOD((void), onStreamPreReaped, (StreamId), (noexcept));
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

  void onKnob(uint64_t knobSpace, uint64_t knobId, BufPtr knobBlob) override {
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

class MockByteEventCallback : public ByteEventCallback {
 public:
  ~MockByteEventCallback() override = default;
  MOCK_METHOD(void, onByteEventRegistered, (ByteEvent));
  MOCK_METHOD(void, onByteEvent, (ByteEvent));
  MOCK_METHOD(void, onByteEventCanceled, (ByteEvent));

  static auto getTxMatcher(StreamId id, uint64_t offset) {
    return AllOf(
        testing::Field(&ByteEvent::type, testing::Eq(ByteEvent::Type::TX)),
        testing::Field(&ByteEvent::id, testing::Eq(id)),
        testing::Field(&ByteEvent::offset, testing::Eq(offset)));
  }

  static auto getAckMatcher(StreamId id, uint64_t offset) {
    return AllOf(
        testing::Field(&ByteEvent::type, testing::Eq(ByteEvent::Type::ACK)),
        testing::Field(&ByteEvent::id, testing::Eq(id)),
        testing::Field(&ByteEvent::offset, testing::Eq(offset)));
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

    // Called when a connection id is bound and ip address should not
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
      std::shared_ptr<FollyQuicEventBase> evb,
      std::unique_ptr<FollyQuicAsyncUDPSocket> sock,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connCb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx)
      : QuicTransportBaseLite(evb, std::move(sock)),
        QuicServerTransport(
            std::move(evb),
            nullptr /* Initialized through the QuicTransportBaseLite constructor
                     */
            ,
            connSetupCb,
            connCb,
            ctx) {}

  virtual ~MockQuicTransport() {
    customDestructor();
  }

  MOCK_METHOD(void, customDestructor, ());
  MOCK_METHOD(const folly::SocketAddress&, getPeerAddress, (), (const));
  MOCK_METHOD(const folly::SocketAddress&, getOriginalPeerAddress, (), (const));

  MOCK_METHOD((std::shared_ptr<QuicEventBase>), getEventBase, (), (const));
  MOCK_METHOD((void), accept, (), ());
  MOCK_METHOD((void), setTransportSettings, (TransportSettings), ());
  MOCK_METHOD((void), setOriginalPeerAddress, (const folly::SocketAddress&));
  MOCK_METHOD((void), setPacingTimer, (QuicTimer::SharedPtr), (noexcept));
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
  MOCK_METHOD((void), close, (Optional<QuicError>), (noexcept));
  MOCK_METHOD((void), closeNow, (Optional<QuicError>), (noexcept));
  MOCK_METHOD((bool), hasShutdown, (), (const));
  MOCK_METHOD((Optional<ConnectionId>), getClientConnectionId, (), (const));
  MOCK_METHOD(
      (Optional<ConnectionId>),
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

  MOCK_METHOD(void, addPacketProcessor, (std::shared_ptr<PacketProcessor>));
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

class MockObserver : public QuicSocketLite::ManagedObserver {
 public:
  using QuicSocketLite::ManagedObserver::ManagedObserver;
  MOCK_METHOD((void), attached, (QuicSocketLite*), (noexcept));
  MOCK_METHOD((void), detached, (QuicSocketLite*), (noexcept));
  MOCK_METHOD(
      (void),
      packetsReceived,
      (QuicSocketLite*, const SocketObserverInterface::PacketsReceivedEvent&));
  MOCK_METHOD(
      (void),
      destroyed,
      (QuicSocketLite*, QuicSocket::Observer::DestroyContext* ctx),
      (noexcept));
  MOCK_METHOD(
      (void),
      closeStarted,
      (QuicSocketLite*, const CloseStartedEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      closing,
      (QuicSocketLite*, const ClosingEvent&),
      (noexcept));
};

class MockLegacyObserver : public LegacyObserver {
 public:
  using LegacyObserver::LegacyObserver;
  MOCK_METHOD((void), observerAttach, (QuicSocketLite*), (noexcept));
  MOCK_METHOD((void), observerDetach, (QuicSocketLite*), (noexcept));
  MOCK_METHOD((void), destroy, (QuicSocketLite*), (noexcept));
  MOCK_METHOD(
      (void),
      closeStarted,
      (QuicSocketLite*, const CloseStartedEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      closing,
      (QuicSocketLite*, const ClosingEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      evbAttach,
      (QuicSocketLite*, quic::QuicEventBase*),
      (noexcept));
  MOCK_METHOD(
      (void),
      evbDetach,
      (QuicSocketLite*, quic::QuicEventBase*),
      (noexcept));
  MOCK_METHOD(
      (void),
      startWritingFromAppLimited,
      (QuicSocketLite*, const AppLimitedEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      packetsWritten,
      (QuicSocketLite*, const PacketsWrittenEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      appRateLimited,
      (QuicSocketLite*, const AppLimitedEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      packetsReceived,
      (QuicSocketLite*, const PacketsReceivedEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      acksProcessed,
      (QuicSocketLite*, const AcksProcessedEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      packetLossDetected,
      (QuicSocketLite*, const LossEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      rttSampleGenerated,
      (QuicSocketLite*, const PacketRTT&),
      (noexcept));
  MOCK_METHOD(
      (void),
      spuriousLossDetected,
      (QuicSocketLite*, const SpuriousLossEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      knobFrameReceived,
      (QuicSocketLite*, const KnobFrameEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      streamOpened,
      (QuicSocketLite*, const StreamOpenEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      streamClosed,
      (QuicSocketLite*, const StreamCloseEvent&),
      (noexcept));
  MOCK_METHOD(
      (void),
      l4sWeightUpdated,
      (QuicSocketLite*, const L4sWeightUpdateEvent&),
      (noexcept));

  static auto getLossPacketNum(PacketNum packetNum) {
    return testing::Field(
        &OutstandingPacketWrapper::packet,
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
            &LostPacket::lostByReorderThreshold, testing::Eq(reorderLoss)),
        testing::Field(&LostPacket::lostByTimeout, testing::Eq(timeoutLoss)),
        testing::Field(&LostPacket::packetNum, testing::Eq(packetNum)));
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
