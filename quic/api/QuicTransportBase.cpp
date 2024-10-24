/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicTransportBase.h>

#include <folly/Chrono.h>
#include <folly/ScopeGuard.h>
#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/Optional.h>
#include <quic/common/TimeUtil.h>
#include <quic/congestion_control/EcnL4sTracker.h>
#include <quic/congestion_control/Pacer.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <memory>

namespace {
/**
 * Helper function - if given error is not set, returns a generic app error.
 * Used by close() and closeNow().
 */
constexpr auto APP_NO_ERROR = quic::GenericApplicationErrorCode::NO_ERROR;
} // namespace

namespace quic {

QuicTransportBase::QuicTransportBase(
    std::shared_ptr<QuicEventBase> evb,
    std::unique_ptr<QuicAsyncUDPSocket> socket,
    bool useConnectionEndWithErrorCallback)
    : QuicTransportBaseLite(
          std::move(evb),
          std::move(socket),
          useConnectionEndWithErrorCallback) {
  writeLooper_->setPacingFunction([this]() -> auto {
    if (isConnectionPaced(*conn_)) {
      return conn_->pacer->getTimeUntilNextWrite();
    }
    return 0us;
  });
  if (socket_) {
    folly::Function<Optional<folly::SocketCmsgMap>()> func = [&]() {
      return getAdditionalCmsgsForAsyncUDPSocket();
    };
    socket_->setAdditionalCmsgsFunc(std::move(func));
  }
}

void QuicTransportBase::setPacingTimer(
    QuicTimer::SharedPtr pacingTimer) noexcept {
  if (pacingTimer) {
    writeLooper_->setPacingTimer(std::move(pacingTimer));
  }
}

void QuicTransportBase::setCongestionControllerFactory(
    std::shared_ptr<CongestionControllerFactory> ccFactory) {
  CHECK(ccFactory);
  CHECK(conn_);
  conn_->congestionControllerFactory = ccFactory;
  conn_->congestionController.reset();
}

const std::shared_ptr<QLogger> QuicTransportBase::getQLogger() const {
  return conn_->qLogger;
}

void QuicTransportBase::setQLogger(std::shared_ptr<QLogger> qLogger) {
  // setQLogger can be called multiple times for the same connection and with
  // the same qLogger we track the number of times it gets set and the number
  // of times it gets reset, and only stop qlog collection when the number of
  // resets equals the number of times the logger was set
  if (!conn_->qLogger) {
    CHECK_EQ(qlogRefcnt_, 0);
  } else {
    CHECK_GT(qlogRefcnt_, 0);
  }

  if (qLogger) {
    conn_->qLogger = std::move(qLogger);
    conn_->qLogger->setDcid(conn_->clientChosenDestConnectionId);
    if (conn_->nodeType == QuicNodeType::Server) {
      conn_->qLogger->setScid(conn_->serverConnectionId);
    } else {
      conn_->qLogger->setScid(conn_->clientConnectionId);
    }
    qlogRefcnt_++;
  } else {
    if (conn_->qLogger) {
      qlogRefcnt_--;
      if (qlogRefcnt_ == 0) {
        conn_->qLogger = nullptr;
      }
    }
  }
}

Optional<ConnectionId> QuicTransportBase::getClientConnectionId() const {
  return conn_->clientConnectionId;
}

Optional<ConnectionId> QuicTransportBase::getServerConnectionId() const {
  return conn_->serverConnectionId;
}

Optional<ConnectionId> QuicTransportBase::getClientChosenDestConnectionId()
    const {
  return conn_->clientChosenDestConnectionId;
}

const folly::SocketAddress& QuicTransportBase::getOriginalPeerAddress() const {
  return conn_->originalPeerAddress;
}

const folly::SocketAddress& QuicTransportBase::getLocalAddress() const {
  return socket_ && socket_->isBound() ? socket_->address()
                                       : localFallbackAddress;
}

QuicTransportBase::~QuicTransportBase() {
  resetConnectionCallbacks();
  // Just in case this ended up hanging around.
  cancelTimeout(&drainTimeout_);

  // closeImpl and closeUdpSocket should have been triggered by destructor of
  // derived class to ensure that observers are properly notified
  DCHECK_NE(CloseState::OPEN, closeState_);
  DCHECK(!socket_.get()); // should be no socket
}

bool QuicTransportBase::replaySafe() const {
  return (conn_->oneRttWriteCipher != nullptr);
}

void QuicTransportBase::closeGracefully() {
  if (closeState_ == CloseState::CLOSED ||
      closeState_ == CloseState::GRACEFUL_CLOSING) {
    return;
  }
  [[maybe_unused]] auto self = sharedGuard();
  resetConnectionCallbacks();
  closeState_ = CloseState::GRACEFUL_CLOSING;
  updatePacingOnClose(*conn_);
  if (conn_->qLogger) {
    conn_->qLogger->addConnectionClose(kNoError, kGracefulExit, true, false);
  }

  // Stop reads and cancel all the app callbacks.
  VLOG(10) << "Stopping read and peek loopers due to graceful close " << *this;
  readLooper_->stop();
  peekLooper_->stop();
  cancelAllAppCallbacks(
      QuicError(QuicErrorCode(LocalErrorCode::NO_ERROR), "Graceful Close"));
  // All streams are closed, close the transport for realz.
  if (conn_->streamManager->streamCount() == 0) {
    closeImpl(none);
  }
}

folly::Expected<size_t, LocalErrorCode> QuicTransportBase::getStreamReadOffset(
    StreamId) const {
  return 0;
}

folly::Expected<size_t, LocalErrorCode> QuicTransportBase::getStreamWriteOffset(
    StreamId id) const {
  if (isReceivingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  try {
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
    return stream->currentWriteOffset;
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return folly::makeUnexpected(ex.errorCode());
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return folly::makeUnexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return folly::makeUnexpected(LocalErrorCode::INTERNAL_ERROR);
  }
}

folly::Expected<size_t, LocalErrorCode>
QuicTransportBase::getStreamWriteBufferedBytes(StreamId id) const {
  if (isReceivingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  try {
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
    return stream->pendingWrites.chainLength();
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return folly::makeUnexpected(ex.errorCode());
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return folly::makeUnexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return folly::makeUnexpected(LocalErrorCode::INTERNAL_ERROR);
  }
}

/**
 * Getters for details from the transport/security layers such as
 * RTT, rxmit, cwnd, mss, app protocol, handshake latency,
 * client proposed ciphers, etc.
 */

QuicSocket::TransportInfo QuicTransportBase::getTransportInfo() const {
  CongestionControlType congestionControlType = CongestionControlType::None;
  uint64_t writableBytes = std::numeric_limits<uint64_t>::max();
  uint64_t congestionWindow = std::numeric_limits<uint64_t>::max();
  Optional<CongestionController::State> maybeCCState;
  uint64_t burstSize = 0;
  std::chrono::microseconds pacingInterval = 0ms;
  if (conn_->congestionController) {
    congestionControlType = conn_->congestionController->type();
    writableBytes = conn_->congestionController->getWritableBytes();
    congestionWindow = conn_->congestionController->getCongestionWindow();
    maybeCCState = conn_->congestionController->getState();
    if (isConnectionPaced(*conn_)) {
      burstSize = conn_->pacer->getCachedWriteBatchSize();
      pacingInterval = conn_->pacer->getTimeUntilNextWrite();
    }
  }
  TransportInfo transportInfo;
  transportInfo.connectionTime = conn_->connectionTime;
  transportInfo.srtt = conn_->lossState.srtt;
  transportInfo.rttvar = conn_->lossState.rttvar;
  transportInfo.lrtt = conn_->lossState.lrtt;
  transportInfo.maybeLrtt = conn_->lossState.maybeLrtt;
  transportInfo.maybeLrttAckDelay = conn_->lossState.maybeLrttAckDelay;
  if (conn_->lossState.mrtt != kDefaultMinRtt) {
    transportInfo.maybeMinRtt = conn_->lossState.mrtt;
  }
  transportInfo.maybeMinRttNoAckDelay = conn_->lossState.maybeMrttNoAckDelay;
  transportInfo.mss = conn_->udpSendPacketLen;
  transportInfo.congestionControlType = congestionControlType;
  transportInfo.writableBytes = writableBytes;
  transportInfo.congestionWindow = congestionWindow;
  transportInfo.pacingBurstSize = burstSize;
  transportInfo.pacingInterval = pacingInterval;
  transportInfo.packetsRetransmitted = conn_->lossState.rtxCount;
  transportInfo.totalPacketsSent = conn_->lossState.totalPacketsSent;
  transportInfo.totalAckElicitingPacketsSent =
      conn_->lossState.totalAckElicitingPacketsSent;
  transportInfo.totalPacketsMarkedLost =
      conn_->lossState.totalPacketsMarkedLost;
  transportInfo.totalPacketsMarkedLostByTimeout =
      conn_->lossState.totalPacketsMarkedLostByTimeout;
  transportInfo.totalPacketsMarkedLostByReorderingThreshold =
      conn_->lossState.totalPacketsMarkedLostByReorderingThreshold;
  transportInfo.totalPacketsSpuriouslyMarkedLost =
      conn_->lossState.totalPacketsSpuriouslyMarkedLost;
  transportInfo.timeoutBasedLoss = conn_->lossState.timeoutBasedRtxCount;
  transportInfo.totalBytesRetransmitted =
      conn_->lossState.totalBytesRetransmitted;
  transportInfo.pto = calculatePTO(*conn_);
  transportInfo.bytesSent = conn_->lossState.totalBytesSent;
  transportInfo.bytesAcked = conn_->lossState.totalBytesAcked;
  transportInfo.bytesRecvd = conn_->lossState.totalBytesRecvd;
  transportInfo.bytesInFlight = conn_->lossState.inflightBytes;
  transportInfo.bodyBytesSent = conn_->lossState.totalBodyBytesSent;
  transportInfo.bodyBytesAcked = conn_->lossState.totalBodyBytesAcked;
  transportInfo.totalStreamBytesSent = conn_->lossState.totalStreamBytesSent;
  transportInfo.totalNewStreamBytesSent =
      conn_->lossState.totalNewStreamBytesSent;
  transportInfo.ptoCount = conn_->lossState.ptoCount;
  transportInfo.totalPTOCount = conn_->lossState.totalPTOCount;
  transportInfo.largestPacketAckedByPeer =
      conn_->ackStates.appDataAckState.largestAckedByPeer;
  transportInfo.largestPacketSent = conn_->lossState.largestSent;
  transportInfo.usedZeroRtt = conn_->usedZeroRtt;
  transportInfo.maybeCCState = maybeCCState;
  return transportInfo;
}

folly::Expected<QuicSocket::FlowControlState, LocalErrorCode>
QuicTransportBase::getConnectionFlowControl() const {
  return QuicSocket::FlowControlState(
      getSendConnFlowControlBytesAPI(*conn_),
      conn_->flowControlState.peerAdvertisedMaxOffset,
      getRecvConnFlowControlBytes(*conn_),
      conn_->flowControlState.advertisedMaxOffset);
}

folly::Expected<uint64_t, LocalErrorCode>
QuicTransportBase::getMaxWritableOnStream(StreamId id) const {
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (isReceivingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }

  auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
  return maxWritableOnStream(*stream);
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setConnectionFlowControlWindow(uint64_t windowSize) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  conn_->flowControlState.windowSize = windowSize;
  maybeSendConnWindowUpdate(*conn_, Clock::now());
  updateWriteLooper(true);
  return folly::unit;
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setStreamFlowControlWindow(
    StreamId id,
    uint64_t windowSize) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
  stream->flowControlState.windowSize = windowSize;
  maybeSendStreamWindowUpdate(*stream, Clock::now());
  updateWriteLooper(true);
  return folly::unit;
}

void QuicTransportBase::unsetAllReadCallbacks() {
  for (const auto& [id, _] : readCallbacks_) {
    setReadCallbackInternal(id, nullptr, APP_NO_ERROR);
  }
}

void QuicTransportBase::unsetAllPeekCallbacks() {
  for (const auto& [id, _] : peekCallbacks_) {
    setPeekCallbackInternal(id, nullptr);
  }
}

void QuicTransportBase::unsetAllDeliveryCallbacks() {
  auto deliveryCallbacksCopy = deliveryCallbacks_;
  for (const auto& [id, _] : deliveryCallbacksCopy) {
    cancelDeliveryCallbacksForStream(id);
  }
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::pauseRead(
    StreamId id) {
  VLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumeRead(id, false);
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::resumeRead(
    StreamId id) {
  VLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumeRead(id, true);
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::pauseOrResumeRead(StreamId id, bool resume) {
  if (isSendingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto readCb = readCallbacks_.find(id);
  if (readCb == readCallbacks_.end()) {
    return folly::makeUnexpected(LocalErrorCode::APP_ERROR);
  }
  if (readCb->second.resumed != resume) {
    readCb->second.resumed = resume;
    updateReadLooper();
  }
  return folly::unit;
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::setPeekCallback(
    StreamId id,
    PeekCallback* cb) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  setPeekCallbackInternal(id, cb);
  return folly::unit;
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setPeekCallbackInternal(
    StreamId id,
    PeekCallback* cb) noexcept {
  VLOG(4) << "Setting setPeekCallback for stream=" << id << " cb=" << cb << " "
          << *this;
  auto peekCbIt = peekCallbacks_.find(id);
  if (peekCbIt == peekCallbacks_.end()) {
    // Don't allow initial setting of a nullptr callback.
    if (!cb) {
      return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
    }
    peekCbIt = peekCallbacks_.emplace(id, PeekCallbackData(cb)).first;
  }
  if (!cb) {
    VLOG(10) << "Resetting the peek callback to nullptr " << "stream=" << id
             << " peekCb=" << peekCbIt->second.peekCb;
  }
  peekCbIt->second.peekCb = cb;
  updatePeekLooper();
  return folly::unit;
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::pausePeek(
    StreamId id) {
  VLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumePeek(id, false);
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::resumePeek(
    StreamId id) {
  VLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumePeek(id, true);
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::pauseOrResumePeek(StreamId id, bool resume) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto peekCb = peekCallbacks_.find(id);
  if (peekCb == peekCallbacks_.end()) {
    return folly::makeUnexpected(LocalErrorCode::APP_ERROR);
  }
  if (peekCb->second.resumed != resume) {
    peekCb->second.resumed = resume;
    updatePeekLooper();
  }
  return folly::unit;
}

void QuicTransportBase::invokeStreamsAvailableCallbacks() {
  if (conn_->streamManager->consumeMaxLocalBidirectionalStreamIdIncreased()) {
    // check in case new streams were created in preceding callbacks
    // and max is already reached
    auto numOpenableStreams = getNumOpenableBidirectionalStreams();
    if (numOpenableStreams > 0) {
      connCallback_->onBidirectionalStreamsAvailable(numOpenableStreams);
    }
  }
  if (conn_->streamManager->consumeMaxLocalUnidirectionalStreamIdIncreased()) {
    // check in case new streams were created in preceding callbacks
    // and max is already reached
    auto numOpenableStreams = getNumOpenableUnidirectionalStreams();
    if (numOpenableStreams > 0) {
      connCallback_->onUnidirectionalStreamsAvailable(numOpenableStreams);
    }
  }
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::peek(
    StreamId id,
    const folly::Function<void(StreamId id, const folly::Range<PeekIterator>&)
                              const>& peekCallback) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    updatePeekLooper();
    updateWriteLooper(true);
  };

  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));

  if (stream->streamReadError) {
    switch (stream->streamReadError->type()) {
      case QuicErrorCode::Type::LocalErrorCode:
        return folly::makeUnexpected(
            *stream->streamReadError->asLocalErrorCode());
      default:
        return folly::makeUnexpected(LocalErrorCode::INTERNAL_ERROR);
    }
  }

  peekDataFromQuicStream(*stream, std::move(peekCallback));
  return folly::makeExpected<LocalErrorCode>(folly::Unit());
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::consume(
    StreamId id,
    size_t amount) {
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
  auto result = consume(id, stream->currentReadOffset, amount);
  if (result.hasError()) {
    return folly::makeUnexpected(result.error().first);
  }
  return folly::makeExpected<LocalErrorCode>(result.value());
}

folly::Expected<folly::Unit, std::pair<LocalErrorCode, Optional<uint64_t>>>
QuicTransportBase::consume(StreamId id, uint64_t offset, size_t amount) {
  using ConsumeError = std::pair<LocalErrorCode, Optional<uint64_t>>;
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(
        ConsumeError{LocalErrorCode::CONNECTION_CLOSED, none});
  }
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    updatePeekLooper();
    updateReadLooper(); // consume may affect "read" API
    updateWriteLooper(true);
  };
  Optional<uint64_t> readOffset;
  try {
    // Need to check that the stream exists first so that we don't
    // accidentally let the API create a peer stream that was not
    // sent by the peer.
    if (!conn_->streamManager->streamExists(id)) {
      return folly::makeUnexpected(
          ConsumeError{LocalErrorCode::STREAM_NOT_EXISTS, readOffset});
    }
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
    readOffset = stream->currentReadOffset;
    if (stream->currentReadOffset != offset) {
      return folly::makeUnexpected(
          ConsumeError{LocalErrorCode::INTERNAL_ERROR, readOffset});
    }

    if (stream->streamReadError) {
      switch (stream->streamReadError->type()) {
        case QuicErrorCode::Type::LocalErrorCode:
          return folly::makeUnexpected(
              ConsumeError{*stream->streamReadError->asLocalErrorCode(), none});
        default:
          return folly::makeUnexpected(
              ConsumeError{LocalErrorCode::INTERNAL_ERROR, none});
      }
    }

    consumeDataFromQuicStream(*stream, amount);
    return folly::makeExpected<ConsumeError>(folly::Unit());
  } catch (const QuicTransportException& ex) {
    VLOG(4) << "consume() error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("consume() error")));
    return folly::makeUnexpected(
        ConsumeError{LocalErrorCode::TRANSPORT_ERROR, readOffset});
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("consume() error")));
    return folly::makeUnexpected(ConsumeError{ex.errorCode(), readOffset});
  } catch (const std::exception& ex) {
    VLOG(4) << "consume() error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("consume() error")));
    return folly::makeUnexpected(
        ConsumeError{LocalErrorCode::INTERNAL_ERROR, readOffset});
  }
}

void QuicTransportBase::handlePingCallbacks() {
  if (conn_->pendingEvents.notifyPingReceived && pingCallback_ != nullptr) {
    conn_->pendingEvents.notifyPingReceived = false;
    if (pingCallback_ != nullptr) {
      pingCallback_->onPing();
    }
  }

  if (!conn_->pendingEvents.cancelPingTimeout) {
    return; // nothing to cancel
  }
  if (!isTimeoutScheduled(&pingTimeout_)) {
    // set cancelpingTimeOut to false, delayed acks
    conn_->pendingEvents.cancelPingTimeout = false;
    return; // nothing to do, as timeout has already fired
  }
  cancelTimeout(&pingTimeout_);
  if (pingCallback_ != nullptr) {
    pingCallback_->pingAcknowledged();
  }
  conn_->pendingEvents.cancelPingTimeout = false;
}

void QuicTransportBase::handleKnobCallbacks() {
  if (!conn_->transportSettings.advertisedKnobFrameSupport) {
    VLOG(4) << "Received knob frames without advertising support";
    conn_->pendingEvents.knobs.clear();
    return;
  }

  for (auto& knobFrame : conn_->pendingEvents.knobs) {
    if (knobFrame.knobSpace != kDefaultQuicTransportKnobSpace) {
      if (getSocketObserverContainer() &&
          getSocketObserverContainer()
              ->hasObserversForEvent<
                  SocketObserverInterface::Events::knobFrameEvents>()) {
        getSocketObserverContainer()
            ->invokeInterfaceMethod<
                SocketObserverInterface::Events::knobFrameEvents>(
                [event = quic::SocketObserverInterface::KnobFrameEvent(
                     Clock::now(), knobFrame)](auto observer, auto observed) {
                  observer->knobFrameReceived(observed, event);
                });
      }
      connCallback_->onKnob(
          knobFrame.knobSpace, knobFrame.id, std::move(knobFrame.blob));
    } else {
      // KnobId is ignored
      onTransportKnobs(std::move(knobFrame.blob));
    }
  }
  conn_->pendingEvents.knobs.clear();
}

void QuicTransportBase::handleAckEventCallbacks() {
  auto& lastProcessedAckEvents = conn_->lastProcessedAckEvents;
  if (lastProcessedAckEvents.empty()) {
    return; // nothing to do
  }

  if (getSocketObserverContainer() &&
      getSocketObserverContainer()
          ->hasObserversForEvent<
              SocketObserverInterface::Events::acksProcessedEvents>()) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<
            SocketObserverInterface::Events::acksProcessedEvents>(
            [event =
                 quic::SocketObserverInterface::AcksProcessedEvent::Builder()
                     .setAckEvents(lastProcessedAckEvents)
                     .build()](auto observer, auto observed) {
              observer->acksProcessed(observed, event);
            });
  }
  lastProcessedAckEvents.clear();
}

void QuicTransportBase::handleCancelByteEventCallbacks() {
  for (auto pendingResetIt = conn_->pendingEvents.resets.begin();
       pendingResetIt != conn_->pendingEvents.resets.end();
       pendingResetIt++) {
    cancelByteEventCallbacksForStream(pendingResetIt->first);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }
}

void QuicTransportBase::logStreamOpenEvent(StreamId streamId) {
  if (getSocketObserverContainer() &&
      getSocketObserverContainer()
          ->hasObserversForEvent<
              SocketObserverInterface::Events::streamEvents>()) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<SocketObserverInterface::Events::streamEvents>(
            [event = SocketObserverInterface::StreamOpenEvent(
                 streamId,
                 getStreamInitiator(streamId),
                 getStreamDirectionality(streamId))](
                auto observer, auto observed) {
              observer->streamOpened(observed, event);
            });
  }
}

void QuicTransportBase::handleNewStreams(std::vector<StreamId>& streamStorage) {
  const auto& newPeerStreamIds = streamStorage;
  for (const auto& streamId : newPeerStreamIds) {
    CHECK_NOTNULL(connCallback_.get());
    if (isBidirectionalStream(streamId)) {
      connCallback_->onNewBidirectionalStream(streamId);
    } else {
      connCallback_->onNewUnidirectionalStream(streamId);
    }

    logStreamOpenEvent(streamId);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }
  streamStorage.clear();
}

void QuicTransportBase::handleNewGroupedStreams(
    std::vector<StreamId>& streamStorage) {
  const auto& newPeerStreamIds = streamStorage;
  for (const auto& streamId : newPeerStreamIds) {
    CHECK_NOTNULL(connCallback_.get());
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));
    CHECK(stream->groupId);
    if (isBidirectionalStream(streamId)) {
      connCallback_->onNewBidirectionalStreamInGroup(
          streamId, *stream->groupId);
    } else {
      connCallback_->onNewUnidirectionalStreamInGroup(
          streamId, *stream->groupId);
    }

    logStreamOpenEvent(streamId);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }
  streamStorage.clear();
}

bool QuicTransportBase::hasDeliveryCallbacksToCall(
    StreamId streamId,
    uint64_t maxOffsetToDeliver) const {
  auto callbacksIt = deliveryCallbacks_.find(streamId);
  if (callbacksIt == deliveryCallbacks_.end() || callbacksIt->second.empty()) {
    return false;
  }

  return (callbacksIt->second.front().offset <= maxOffsetToDeliver);
}

void QuicTransportBase::handleNewStreamCallbacks(
    std::vector<StreamId>& streamStorage) {
  streamStorage = conn_->streamManager->consumeNewPeerStreams();
  handleNewStreams(streamStorage);
}

void QuicTransportBase::handleNewGroupedStreamCallbacks(
    std::vector<StreamId>& streamStorage) {
  auto newStreamGroups = conn_->streamManager->consumeNewPeerStreamGroups();
  for (auto newStreamGroupId : newStreamGroups) {
    if (isBidirectionalStream(newStreamGroupId)) {
      connCallback_->onNewBidirectionalStreamGroup(newStreamGroupId);
    } else {
      connCallback_->onNewUnidirectionalStreamGroup(newStreamGroupId);
    }
  }

  streamStorage = conn_->streamManager->consumeNewGroupedPeerStreams();
  handleNewGroupedStreams(streamStorage);
}

void QuicTransportBase::handleDeliveryCallbacks() {
  auto deliverableStreamId = conn_->streamManager->popDeliverable();
  while (deliverableStreamId.has_value()) {
    auto streamId = *deliverableStreamId;
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));
    auto maxOffsetToDeliver = getLargestDeliverableOffset(*stream);

    if (maxOffsetToDeliver.has_value()) {
      size_t amountTrimmed = stream->writeBuffer.trimStartAtMost(
          *maxOffsetToDeliver - stream->writeBufferStartOffset);
      stream->writeBufferStartOffset += amountTrimmed;
    }

    if (maxOffsetToDeliver.has_value()) {
      while (hasDeliveryCallbacksToCall(streamId, *maxOffsetToDeliver)) {
        auto& deliveryCallbacksForAckedStream = deliveryCallbacks_.at(streamId);
        auto deliveryCallbackAndOffset =
            deliveryCallbacksForAckedStream.front();
        deliveryCallbacksForAckedStream.pop_front();
        auto currentDeliveryCallbackOffset = deliveryCallbackAndOffset.offset;
        auto deliveryCallback = deliveryCallbackAndOffset.callback;

        ByteEvent byteEvent{
            streamId,
            currentDeliveryCallbackOffset,
            ByteEvent::Type::ACK,
            conn_->lossState.srtt};
        deliveryCallback->onByteEvent(byteEvent);

        if (closeState_ != CloseState::OPEN) {
          return;
        }
      }
    }
    auto deliveryCallbacksForAckedStream = deliveryCallbacks_.find(streamId);
    if (deliveryCallbacksForAckedStream != deliveryCallbacks_.end() &&
        deliveryCallbacksForAckedStream->second.empty()) {
      deliveryCallbacks_.erase(deliveryCallbacksForAckedStream);
    }
    deliverableStreamId = conn_->streamManager->popDeliverable();
  }
}

void QuicTransportBase::handleStreamFlowControlUpdatedCallbacks(
    std::vector<StreamId>& streamStorage) {
  // Iterate over streams that changed their flow control window and give
  // their registered listeners their updates.
  // We don't really need flow control notifications when we are closed.
  streamStorage = conn_->streamManager->consumeFlowControlUpdated();
  const auto& flowControlUpdated = streamStorage;
  for (auto streamId : flowControlUpdated) {
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));
    if (!stream->writable()) {
      pendingWriteCallbacks_.erase(streamId);
      continue;
    }
    connCallback_->onFlowControlUpdate(streamId);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
    // In case the callback modified the stream map, get it again.
    stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));
    auto maxStreamWritable = maxWritableOnStream(*stream);
    if (maxStreamWritable != 0 && !pendingWriteCallbacks_.empty()) {
      auto pendingWriteIt = pendingWriteCallbacks_.find(stream->id);
      if (pendingWriteIt != pendingWriteCallbacks_.end()) {
        auto wcb = pendingWriteIt->second;
        pendingWriteCallbacks_.erase(stream->id);
        wcb->onStreamWriteReady(stream->id, maxStreamWritable);
        if (closeState_ != CloseState::OPEN) {
          return;
        }
      }
    }
  }

  streamStorage.clear();
}

void QuicTransportBase::handleStreamStopSendingCallbacks() {
  const auto stopSendingStreamsCopy =
      conn_->streamManager->consumeStopSending();
  for (const auto& itr : stopSendingStreamsCopy) {
    connCallback_->onStopSending(itr.first, itr.second);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }
}

void QuicTransportBase::handleConnWritable() {
  auto maxConnWrite = maxWritableOnConn();
  if (maxConnWrite != 0) {
    // If the connection now has flow control, we may either have been blocked
    // before on a pending write to the conn, or a stream's write.
    if (connWriteCallback_) {
      auto connWriteCallback = connWriteCallback_;
      connWriteCallback_ = nullptr;
      connWriteCallback->onConnectionWriteReady(maxConnWrite);
    }

    // If the connection flow control is unblocked, we might be unblocked
    // on the streams now.
    auto writeCallbackIt = pendingWriteCallbacks_.begin();

    while (writeCallbackIt != pendingWriteCallbacks_.end()) {
      auto streamId = writeCallbackIt->first;
      auto wcb = writeCallbackIt->second;
      ++writeCallbackIt;
      auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));
      if (!stream->writable()) {
        pendingWriteCallbacks_.erase(streamId);
        continue;
      }
      auto maxStreamWritable = maxWritableOnStream(*stream);
      if (maxStreamWritable != 0) {
        pendingWriteCallbacks_.erase(streamId);
        wcb->onStreamWriteReady(streamId, maxStreamWritable);
        if (closeState_ != CloseState::OPEN) {
          return;
        }
      }
    }
  }
}

void QuicTransportBase::cleanupAckEventState() {
  // if there's no bytes in flight, clear any memory allocated for AckEvents
  if (conn_->outstandings.packets.empty()) {
    std::vector<AckEvent> empty;
    conn_->lastProcessedAckEvents.swap(empty);
  } // memory allocated for vector will be freed
}

void QuicTransportBase::processCallbacksAfterNetworkData() {
  if (closeState_ != CloseState::OPEN) {
    return;
  }
  // We reuse this storage for storing streams which need callbacks.
  std::vector<StreamId> tempStorage;

  handleNewStreamCallbacks(tempStorage);
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleNewGroupedStreamCallbacks(tempStorage);
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handlePingCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleKnobCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleAckEventCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleCancelByteEventCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleDeliveryCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleStreamFlowControlUpdatedCallbacks(tempStorage);
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleStreamStopSendingCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleConnWritable();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  invokeStreamsAvailableCallbacks();
  cleanupAckEventState();
}

void QuicTransportBase::onNetworkData(
    const folly::SocketAddress& peer,
    NetworkData&& networkData) noexcept {
  [[maybe_unused]] auto self = sharedGuard();
  bool scheduleUpdateWriteLooper = true;
  SCOPE_EXIT {
    checkForClosedStream();
    updateReadLooper();
    updatePeekLooper();
    if (scheduleUpdateWriteLooper) {
      updateWriteLooper(true, conn_->transportSettings.inlineWriteAfterRead);
    }
  };
  try {
    // If networkDataPerSocketRead is on, we will run the write looper manually
    // after processing packets.
    scheduleUpdateWriteLooper =
        !conn_->transportSettings.networkDataPerSocketRead;
    conn_->lossState.totalBytesRecvd += networkData.getTotalData();
    auto originalAckVersion = currentAckStateVersion(*conn_);

    // handle PacketsReceivedEvent if requested by observers
    if (getSocketObserverContainer() &&
        getSocketObserverContainer()
            ->hasObserversForEvent<
                SocketObserverInterface::Events::packetsReceivedEvents>()) {
      auto builder = SocketObserverInterface::PacketsReceivedEvent::Builder()
                         .setReceiveLoopTime(TimePoint::clock::now())
                         .setNumPacketsReceived(networkData.getPackets().size())
                         .setNumBytesReceived(networkData.getTotalData());
      for (auto& packet : networkData.getPackets()) {
        auto receivedUdpPacketBuilder =
            SocketObserverInterface::PacketsReceivedEvent::ReceivedUdpPacket::
                Builder()
                    .setPacketReceiveTime(packet.timings.receiveTimePoint)
                    .setPacketNumBytes(packet.buf.chainLength())
                    .setPacketTos(packet.tosValue);
        if (packet.timings.maybeSoftwareTs) {
          receivedUdpPacketBuilder.setPacketSoftwareRxTimestamp(
              packet.timings.maybeSoftwareTs->systemClock.raw);
        }
        builder.addReceivedUdpPacket(
            std::move(receivedUdpPacketBuilder).build());
      }

      getSocketObserverContainer()
          ->invokeInterfaceMethod<
              SocketObserverInterface::Events::packetsReceivedEvents>(
              [event = std::move(builder).build()](
                  auto observer, auto observed) {
                observer->packetsReceived(observed, event);
              });
    }

    auto packets = std::move(networkData).movePackets();
    bool processedCallbacks = false;
    for (auto& packet : packets) {
      onReadData(peer, std::move(packet));
      if (conn_->peerConnectionError) {
        closeImpl(QuicError(
            QuicErrorCode(TransportErrorCode::NO_ERROR), "Peer closed"));
        return;
      } else if (conn_->transportSettings.processCallbacksPerPacket) {
        processCallbacksAfterNetworkData();
        invokeReadDataAndCallbacks();
        processedCallbacks = true;
      }
    }

    // This avoids calling it again for the last packet.
    if (!processedCallbacks) {
      processCallbacksAfterNetworkData();
    }
    if (closeState_ != CloseState::CLOSED) {
      if (currentAckStateVersion(*conn_) != originalAckVersion) {
        setIdleTimer();
        conn_->receivedNewPacketBeforeWrite = true;
        if (conn_->loopDetectorCallback) {
          conn_->readDebugState.noReadReason = NoReadReason::READ_OK;
          conn_->readDebugState.loopCount = 0;
        }
      } else if (conn_->loopDetectorCallback) {
        conn_->readDebugState.noReadReason = NoReadReason::STALE_DATA;
        conn_->loopDetectorCallback->onSuspiciousReadLoops(
            ++conn_->readDebugState.loopCount,
            conn_->readDebugState.noReadReason);
      }
      // Reading data could process an ack and change the loss timer.
      setLossDetectionAlarm(*conn_, *self);
      // Reading data could change the state of the acks which could change
      // the ack timer. But we need to call scheduleAckTimeout() for it to
      // take effect.
      scheduleAckTimeout();
      // Received data could contain valid path response, in which case
      // path validation timeout should be canceled
      schedulePathValidationTimeout();

      // If ECN is enabled, make sure that the packet marking is happening as
      // expected
      validateECNState();
    } else {
      // In the closed state, we would want to write a close if possible
      // however the write looper will not be set.
      writeSocketData();
    }
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    return closeImpl(
        QuicError(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    return closeImpl(
        QuicError(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicApplicationException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    return closeImpl(
        QuicError(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    return closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("error onNetworkData()")));
  }
}

folly::Expected<StreamGroupId, LocalErrorCode>
QuicTransportBase::createBidirectionalStreamGroup() {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  return conn_->streamManager->createNextBidirectionalStreamGroup();
}

folly::Expected<StreamGroupId, LocalErrorCode>
QuicTransportBase::createUnidirectionalStreamGroup() {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  return conn_->streamManager->createNextUnidirectionalStreamGroup();
}

folly::Expected<StreamId, LocalErrorCode>
QuicTransportBase::createBidirectionalStreamInGroup(StreamGroupId groupId) {
  return createStreamInternal(true, groupId);
}

folly::Expected<StreamId, LocalErrorCode>
QuicTransportBase::createUnidirectionalStreamInGroup(StreamGroupId groupId) {
  return createStreamInternal(false, groupId);
}

bool QuicTransportBase::isClientStream(StreamId stream) noexcept {
  return quic::isClientStream(stream);
}

bool QuicTransportBase::isServerStream(StreamId stream) noexcept {
  return quic::isServerStream(stream);
}

StreamDirectionality QuicTransportBase::getStreamDirectionality(
    StreamId stream) noexcept {
  return quic::getStreamDirectionality(stream);
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::registerTxCallback(
    StreamId id,
    uint64_t offset,
    ByteEventCallback* cb) {
  return registerByteEventCallback(ByteEvent::Type::TX, id, offset, cb);
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::resetStream(
    StreamId id,
    ApplicationErrorCode errorCode) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    checkForClosedStream();
    updateReadLooper();
    updatePeekLooper();
    updateWriteLooper(true);
  };
  try {
    // Check whether stream exists before calling getStream to avoid
    // creating a peer stream if it does not exist yet.
    if (!conn_->streamManager->streamExists(id)) {
      return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
    // Invoke state machine
    sendRstSMHandler(*stream, errorCode);

    for (auto pendingResetIt = conn_->pendingEvents.resets.begin();
         closeState_ == CloseState::OPEN &&
         pendingResetIt != conn_->pendingEvents.resets.end();
         pendingResetIt++) {
      cancelByteEventCallbacksForStream(pendingResetIt->first);
    }
    pendingWriteCallbacks_.erase(id);
    QUIC_STATS(conn_->statsCallback, onQuicStreamReset, errorCode);
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("resetStream() error")));
    return folly::makeUnexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("resetStream() error")));
    return folly::makeUnexpected(ex.errorCode());
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("resetStream() error")));
    return folly::makeUnexpected(LocalErrorCode::INTERNAL_ERROR);
  }
  return folly::unit;
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::setPingCallback(
    PingCallback* cb) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  VLOG(4) << "Setting ping callback " << " cb=" << cb << " " << *this;

  pingCallback_ = cb;
  return folly::unit;
}

void QuicTransportBase::sendPing(std::chrono::milliseconds pingTimeout) {
  /* Step 0: Connection should not be closed */
  if (closeState_ == CloseState::CLOSED) {
    return;
  }

  // Step 1: Send a simple ping frame
  conn_->pendingEvents.sendPing = true;
  updateWriteLooper(true);

  // Step 2: Schedule the timeout on event base
  if (pingCallback_ && pingTimeout != 0ms) {
    schedulePingTimeout(pingCallback_, pingTimeout);
  }
}

void QuicTransportBase::schedulePingTimeout(
    PingCallback* pingCb,
    std::chrono::milliseconds timeout) {
  // if a ping timeout is already scheduled, nothing to do, return
  if (isTimeoutScheduled(&pingTimeout_)) {
    return;
  }

  pingCallback_ = pingCb;
  scheduleTimeout(&pingTimeout_, timeout);
}

void QuicTransportBase::setSupportedVersions(
    const std::vector<QuicVersion>& versions) {
  conn_->originalVersion = versions.at(0);
  conn_->supportedVersions = versions;
}

void QuicTransportBase::setAckRxTimestampsEnabled(bool enableAckRxTimestamps) {
  if (!enableAckRxTimestamps) {
    conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer.clear();
  }
}

void QuicTransportBase::setEarlyDataAppParamsFunctions(
    folly::Function<bool(const Optional<std::string>&, const Buf&) const>
        validator,
    folly::Function<Buf()> getter) {
  conn_->earlyDataAppParamsValidator = std::move(validator);
  conn_->earlyDataAppParamsGetter = std::move(getter);
}

void QuicTransportBase::resetNonControlStreams(
    ApplicationErrorCode error,
    folly::StringPiece errorMsg) {
  std::vector<StreamId> nonControlStreamIds;
  nonControlStreamIds.reserve(conn_->streamManager->streamCount());
  conn_->streamManager->streamStateForEach(
      [&nonControlStreamIds](const auto& stream) {
        if (!stream.isControl) {
          nonControlStreamIds.push_back(stream.id);
        }
      });
  for (auto id : nonControlStreamIds) {
    if (isSendingStream(conn_->nodeType, id) || isBidirectionalStream(id)) {
      auto writeCallbackIt = pendingWriteCallbacks_.find(id);
      if (writeCallbackIt != pendingWriteCallbacks_.end()) {
        writeCallbackIt->second->onStreamWriteError(
            id, QuicError(error, errorMsg.str()));
      }
      resetStream(id, error);
    }
    if (isReceivingStream(conn_->nodeType, id) || isBidirectionalStream(id)) {
      auto readCallbackIt = readCallbacks_.find(id);
      if (readCallbackIt != readCallbacks_.end() &&
          readCallbackIt->second.readCb) {
        auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
        if (!stream->groupId) {
          readCallbackIt->second.readCb->readError(
              id, QuicError(error, errorMsg.str()));
        } else {
          readCallbackIt->second.readCb->readErrorWithGroup(
              id, *stream->groupId, QuicError(error, errorMsg.str()));
        }
      }
      peekCallbacks_.erase(id);
      stopSending(id, error);
    }
  }
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setDatagramCallback(DatagramCallback* cb) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  VLOG(4) << "Setting datagram callback " << " cb=" << cb << " " << *this;

  datagramCallback_ = cb;
  updateReadLooper();
  return folly::unit;
}

uint16_t QuicTransportBase::getDatagramSizeLimit() const {
  CHECK(conn_);
  auto maxDatagramPacketSize = std::min<decltype(conn_->udpSendPacketLen)>(
      conn_->datagramState.maxWriteFrameSize, conn_->udpSendPacketLen);
  return std::max<decltype(maxDatagramPacketSize)>(
      0, maxDatagramPacketSize - kMaxDatagramPacketOverhead);
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::writeDatagram(
    Buf buf) {
  // TODO(lniccolini) update max datagram frame size
  // https://github.com/quicwg/datagram/issues/3
  // For now, max_datagram_size > 0 means the peer supports datagram frames
  if (conn_->datagramState.maxWriteFrameSize == 0) {
    QUIC_STATS(conn_->statsCallback, onDatagramDroppedOnWrite);
    return folly::makeUnexpected(LocalErrorCode::INVALID_WRITE_DATA);
  }
  if (conn_->datagramState.writeBuffer.size() >=
      conn_->datagramState.maxWriteBufferSize) {
    QUIC_STATS(conn_->statsCallback, onDatagramDroppedOnWrite);
    if (!conn_->transportSettings.datagramConfig.sendDropOldDataFirst) {
      // TODO(lniccolini) use different return codes to signal the application
      // exactly why the datagram got dropped
      return folly::makeUnexpected(LocalErrorCode::INVALID_WRITE_DATA);
    } else {
      conn_->datagramState.writeBuffer.pop_front();
    }
  }
  conn_->datagramState.writeBuffer.emplace_back(std::move(buf));
  updateWriteLooper(true);
  return folly::unit;
}

folly::Expected<std::vector<ReadDatagram>, LocalErrorCode>
QuicTransportBase::readDatagrams(size_t atMost) {
  CHECK(conn_);
  auto datagrams = &conn_->datagramState.readBuffer;
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (atMost == 0) {
    atMost = datagrams->size();
  } else {
    atMost = std::min(atMost, datagrams->size());
  }
  std::vector<ReadDatagram> retDatagrams;
  retDatagrams.reserve(atMost);
  std::transform(
      datagrams->begin(),
      datagrams->begin() + atMost,
      std::back_inserter(retDatagrams),
      [](ReadDatagram& dg) { return std::move(dg); });
  datagrams->erase(datagrams->begin(), datagrams->begin() + atMost);
  return retDatagrams;
}

folly::Expected<std::vector<Buf>, LocalErrorCode>
QuicTransportBase::readDatagramBufs(size_t atMost) {
  CHECK(conn_);
  auto datagrams = &conn_->datagramState.readBuffer;
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (atMost == 0) {
    atMost = datagrams->size();
  } else {
    atMost = std::min(atMost, datagrams->size());
  }
  std::vector<Buf> retDatagrams;
  retDatagrams.reserve(atMost);
  std::transform(
      datagrams->begin(),
      datagrams->begin() + atMost,
      std::back_inserter(retDatagrams),
      [](ReadDatagram& dg) { return dg.bufQueue().move(); });
  datagrams->erase(datagrams->begin(), datagrams->begin() + atMost);
  return retDatagrams;
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setMaxPacingRate(uint64_t maxRateBytesPerSec) {
  if (conn_->pacer) {
    conn_->pacer->setMaxPacingRate(maxRateBytesPerSec);
    return folly::unit;
  } else {
    LOG(WARNING)
        << "Cannot set max pacing rate without a pacer. Pacing Enabled = "
        << conn_->transportSettings.pacingEnabled;
    return folly::makeUnexpected(LocalErrorCode::PACER_NOT_AVAILABLE);
  }
}

folly::Expected<Priority, LocalErrorCode> QuicTransportBase::getStreamPriority(
    StreamId id) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (auto stream = conn_->streamManager->findStream(id)) {
    return stream->priority;
  }
  return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
}

void QuicTransportBase::setThrottlingSignalProvider(
    std::shared_ptr<ThrottlingSignalProvider> throttlingSignalProvider) {
  DCHECK(conn_);
  conn_->throttlingSignalProvider = throttlingSignalProvider;
}

bool QuicTransportBase::isDetachable() {
  // only the client is detachable.
  return conn_->nodeType == QuicNodeType::Client;
}

void QuicTransportBase::attachEventBase(std::shared_ptr<QuicEventBase> evbIn) {
  VLOG(10) << __func__ << " " << *this;
  DCHECK(!getEventBase());
  DCHECK(evbIn && evbIn->isInEventBaseThread());
  evb_ = std::move(evbIn);
  if (socket_) {
    socket_->attachEventBase(evb_);
  }

  scheduleAckTimeout();
  schedulePathValidationTimeout();
  setIdleTimer();

  readLooper_->attachEventBase(evb_);
  peekLooper_->attachEventBase(evb_);
  writeLooper_->attachEventBase(evb_);
  updateReadLooper();
  updatePeekLooper();
  updateWriteLooper(false);

#ifndef MVFST_USE_LIBEV
  if (getSocketObserverContainer() &&
      getSocketObserverContainer()
          ->hasObserversForEvent<
              SocketObserverInterface::Events::evbEvents>()) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<SocketObserverInterface::Events::evbEvents>(
            [this](auto observer, auto observed) {
              observer->evbAttach(observed, evb_.get());
            });
  }
#endif
}

void QuicTransportBase::detachEventBase() {
  VLOG(10) << __func__ << " " << *this;
  DCHECK(getEventBase() && getEventBase()->isInEventBaseThread());
  if (socket_) {
    socket_->detachEventBase();
  }
  connWriteCallback_ = nullptr;
  pendingWriteCallbacks_.clear();
  cancelTimeout(&lossTimeout_);
  cancelTimeout(&ackTimeout_);
  cancelTimeout(&pathValidationTimeout_);
  cancelTimeout(&idleTimeout_);
  cancelTimeout(&keepaliveTimeout_);
  cancelTimeout(&drainTimeout_);
  readLooper_->detachEventBase();
  peekLooper_->detachEventBase();
  writeLooper_->detachEventBase();

#ifndef MVFST_USE_LIBEV
  if (getSocketObserverContainer() &&
      getSocketObserverContainer()
          ->hasObserversForEvent<
              SocketObserverInterface::Events::evbEvents>()) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<SocketObserverInterface::Events::evbEvents>(
            [this](auto observer, auto observed) {
              observer->evbDetach(observed, evb_.get());
            });
  }
#endif

  evb_ = nullptr;
}

void QuicTransportBase::onSocketWritable() noexcept {
  // Remove the writable callback.
  socket_->pauseWrite();

  // Try to write.
  // If write fails again, pacedWriteDataToSocket() will re-arm the write event
  // and stop the write looper.
  writeLooper_->run(true /* thisIteration */);
}

inline std::ostream& operator<<(
    std::ostream& os,
    const CloseState& closeState) {
  switch (closeState) {
    case CloseState::OPEN:
      os << "OPEN";
      break;
    case CloseState::GRACEFUL_CLOSING:
      os << "GRACEFUL_CLOSING";
      break;
    case CloseState::CLOSED:
      os << "CLOSED";
      break;
  }
  return os;
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::maybeResetStreamFromReadError(
    StreamId id,
    QuicErrorCode error) {
  if (quic::ApplicationErrorCode* code = error.asApplicationErrorCode()) {
    return resetStream(id, *code);
  }
  return folly::Expected<folly::Unit, LocalErrorCode>(folly::unit);
}

void QuicTransportBase::onTransportKnobs(Buf knobBlob) {
  // Not yet implemented,
  VLOG(4) << "Received transport knobs: "
          << std::string(
                 reinterpret_cast<const char*>(knobBlob->data()),
                 knobBlob->length());
}

void QuicTransportBase::notifyStartWritingFromAppRateLimited() {
  if (getSocketObserverContainer() &&
      getSocketObserverContainer()
          ->hasObserversForEvent<
              SocketObserverInterface::Events::appRateLimitedEvents>()) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<
            SocketObserverInterface::Events::appRateLimitedEvents>(
            [event =
                 SocketObserverInterface::AppLimitedEvent::Builder()
                     .setOutstandingPackets(conn_->outstandings.packets)
                     .setWriteCount(conn_->writeCount)
                     .setLastPacketSentTime(
                         conn_->lossState.maybeLastPacketSentTime)
                     .setCwndInBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getCongestionWindow())
                             : none)
                     .setWritableBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getWritableBytes())
                             : none)
                     .build()](auto observer, auto observed) {
              observer->startWritingFromAppLimited(observed, event);
            });
  }
}

void QuicTransportBase::notifyPacketsWritten(
    uint64_t numPacketsWritten,
    uint64_t numAckElicitingPacketsWritten,
    uint64_t numBytesWritten) {
  if (getSocketObserverContainer() &&
      getSocketObserverContainer()
          ->hasObserversForEvent<
              SocketObserverInterface::Events::packetsWrittenEvents>()) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<
            SocketObserverInterface::Events::packetsWrittenEvents>(
            [event =
                 SocketObserverInterface::PacketsWrittenEvent::Builder()
                     .setOutstandingPackets(conn_->outstandings.packets)
                     .setWriteCount(conn_->writeCount)
                     .setLastPacketSentTime(
                         conn_->lossState.maybeLastPacketSentTime)
                     .setCwndInBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getCongestionWindow())
                             : none)
                     .setWritableBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getWritableBytes())
                             : none)
                     .setNumPacketsWritten(numPacketsWritten)
                     .setNumAckElicitingPacketsWritten(
                         numAckElicitingPacketsWritten)
                     .setNumBytesWritten(numBytesWritten)
                     .build()](auto observer, auto observed) {
              observer->packetsWritten(observed, event);
            });
  }
}

void QuicTransportBase::notifyAppRateLimited() {
  if (getSocketObserverContainer() &&
      getSocketObserverContainer()
          ->hasObserversForEvent<
              SocketObserverInterface::Events::appRateLimitedEvents>()) {
    getSocketObserverContainer()
        ->invokeInterfaceMethod<
            SocketObserverInterface::Events::appRateLimitedEvents>(
            [event =
                 SocketObserverInterface::AppLimitedEvent::Builder()
                     .setOutstandingPackets(conn_->outstandings.packets)
                     .setWriteCount(conn_->writeCount)
                     .setLastPacketSentTime(
                         conn_->lossState.maybeLastPacketSentTime)
                     .setCwndInBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getCongestionWindow())
                             : none)
                     .setWritableBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getWritableBytes())
                             : none)
                     .build()](auto observer, auto observed) {
              observer->appRateLimited(observed, event);
            });
  }
}

void QuicTransportBase::setCmsgs(const folly::SocketCmsgMap& options) {
  socket_->setCmsgs(options);
}

void QuicTransportBase::appendCmsgs(const folly::SocketCmsgMap& options) {
  socket_->appendCmsgs(options);
}

void QuicTransportBase::setBackgroundModeParameters(
    PriorityLevel maxBackgroundPriority,
    float backgroundUtilizationFactor) {
  backgroundPriorityThreshold_.assign(maxBackgroundPriority);
  backgroundUtilizationFactor_.assign(backgroundUtilizationFactor);
  conn_->streamManager->setPriorityChangesObserver(this);
  onStreamPrioritiesChange();
}

void QuicTransportBase::clearBackgroundModeParameters() {
  backgroundPriorityThreshold_.clear();
  backgroundUtilizationFactor_.clear();
  conn_->streamManager->resetPriorityChangesObserver();
  onStreamPrioritiesChange();
}

// If backgroundPriorityThreshold_ and backgroundUtilizationFactor_ are set
// and all streams have equal or lower priority than the threshold (value >=
// threshold), set the connection's congestion controller to use background
// mode with the set utilization factor. In all other cases, turn off the
// congestion controller's background mode.
void QuicTransportBase::onStreamPrioritiesChange() {
  if (conn_->congestionController == nullptr) {
    return;
  }
  if (!backgroundPriorityThreshold_.hasValue() ||
      !backgroundUtilizationFactor_.hasValue()) {
    conn_->congestionController->setBandwidthUtilizationFactor(1.0);
    return;
  }
  bool allStreamsBackground = conn_->streamManager->getHighestPriorityLevel() >=
      backgroundPriorityThreshold_.value();
  float targetUtilization =
      allStreamsBackground ? backgroundUtilizationFactor_.value() : 1.0f;
  VLOG(10) << fmt::format(
      "Updating transport background mode. Highest Priority={} Threshold={} TargetUtilization={}",
      conn_->streamManager->getHighestPriorityLevel(),
      backgroundPriorityThreshold_.value(),
      targetUtilization);
  conn_->congestionController->setBandwidthUtilizationFactor(targetUtilization);
}

bool QuicTransportBase::checkCustomRetransmissionProfilesEnabled() const {
  return quic::checkCustomRetransmissionProfilesEnabled(*conn_);
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setStreamGroupRetransmissionPolicy(
    StreamGroupId groupId,
    std::optional<QuicStreamGroupRetransmissionPolicy> policy) noexcept {
  // Reset the policy to default one.
  if (policy == std::nullopt) {
    conn_->retransmissionPolicies.erase(groupId);
    return folly::unit;
  }

  if (!checkCustomRetransmissionProfilesEnabled()) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }

  if (conn_->retransmissionPolicies.size() >=
      conn_->transportSettings.advertisedMaxStreamGroups) {
    return folly::makeUnexpected(LocalErrorCode::RTX_POLICIES_LIMIT_EXCEEDED);
  }

  conn_->retransmissionPolicies.emplace(groupId, *policy);
  return folly::unit;
}

void QuicTransportBase::validateECNState() {
  if (conn_->ecnState == ECNState::NotAttempted ||
      conn_->ecnState == ECNState::FailedValidation) {
    // Verification not needed
    return;
  }
  const auto& minExpectedMarkedPacketsCount =
      conn_->ackStates.appDataAckState.minimumExpectedEcnMarksEchoed;
  if (minExpectedMarkedPacketsCount < 10) {
    // We wait for 10 ack-eliciting app data packets to be marked before trying
    // to validate ECN.
    return;
  }
  const auto& maxExpectedMarkedPacketsCount = conn_->lossState.totalPacketsSent;

  auto markedPacketCount = conn_->ackStates.appDataAckState.ecnCECountEchoed;

  if (conn_->ecnState == ECNState::AttemptingECN ||
      conn_->ecnState == ECNState::ValidatedECN) {
    // Check the number of marks seen (ECT0 + CE). ECT1 should be zero.
    markedPacketCount += conn_->ackStates.appDataAckState.ecnECT0CountEchoed;

    if (markedPacketCount >= minExpectedMarkedPacketsCount &&
        markedPacketCount <= maxExpectedMarkedPacketsCount &&
        conn_->ackStates.appDataAckState.ecnECT1CountEchoed == 0) {
      if (conn_->ecnState != ECNState::ValidatedECN) {
        conn_->ecnState = ECNState::ValidatedECN;
        VLOG(4) << fmt::format(
            "ECN validation successful. Marked {} of {} expected",
            markedPacketCount,
            minExpectedMarkedPacketsCount);
      }
    } else {
      conn_->ecnState = ECNState::FailedValidation;
      VLOG(4) << fmt::format(
          "ECN validation failed. Marked {} of {} expected",
          markedPacketCount,
          minExpectedMarkedPacketsCount);
    }
  } else if (
      conn_->ecnState == ECNState::AttemptingL4S ||
      conn_->ecnState == ECNState::ValidatedL4S) {
    // Check the number of marks seen (ECT1 + CE). ECT0 should be zero.
    markedPacketCount += conn_->ackStates.appDataAckState.ecnECT1CountEchoed;

    if (markedPacketCount >= minExpectedMarkedPacketsCount &&
        markedPacketCount <= maxExpectedMarkedPacketsCount &&
        conn_->ackStates.appDataAckState.ecnECT0CountEchoed == 0) {
      if (conn_->ecnState != ECNState::ValidatedL4S) {
        if (!conn_->ecnL4sTracker) {
          conn_->ecnL4sTracker = std::make_shared<EcnL4sTracker>(*conn_);
          addPacketProcessor(conn_->ecnL4sTracker);
        }
        conn_->ecnState = ECNState::ValidatedL4S;
        VLOG(4) << fmt::format(
            "L4S validation successful. Marked {} of {} expected",
            markedPacketCount,
            minExpectedMarkedPacketsCount);
      }
    } else {
      conn_->ecnState = ECNState::FailedValidation;
      VLOG(4) << fmt::format(
          "L4S validation failed. Marked {} of {} expected",
          markedPacketCount,
          minExpectedMarkedPacketsCount);
    }
  }

  if (conn_->ecnState == ECNState::FailedValidation) {
    conn_->socketTos.fields.ecn = 0;
    CHECK(socket_ && socket_->isBound());
    socket_->setTosOrTrafficClass(conn_->socketTos.value);
    VLOG(4) << "ECN validation failed. Disabling ECN";
    if (conn_->ecnL4sTracker) {
      conn_->packetProcessors.erase(
          std::remove(
              conn_->packetProcessors.begin(),
              conn_->packetProcessors.end(),
              conn_->ecnL4sTracker),
          conn_->packetProcessors.end());
      conn_->ecnL4sTracker.reset();
    }
  }
}

Optional<folly::SocketCmsgMap>
QuicTransportBase::getAdditionalCmsgsForAsyncUDPSocket() {
  if (conn_->socketCmsgsState.additionalCmsgs) {
    // This callback should be happening for the target write
    DCHECK(conn_->writeCount == conn_->socketCmsgsState.targetWriteCount);
    return conn_->socketCmsgsState.additionalCmsgs;
  }
  return none;
}

WriteQuicDataResult QuicTransportBase::handleInitialWriteDataCommon(
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    uint64_t packetLimit,
    const std::string& token) {
  CHECK(conn_->initialWriteCipher);
  auto version = conn_->version.value_or(*(conn_->originalVersion));
  auto& initialCryptoStream =
      *getCryptoStream(*conn_->cryptoState, EncryptionLevel::Initial);
  CryptoStreamScheduler initialScheduler(*conn_, initialCryptoStream);
  auto& numProbePackets =
      conn_->pendingEvents.numProbePackets[PacketNumberSpace::Initial];
  if ((initialCryptoStream.retransmissionBuffer.size() &&
       conn_->outstandings.packetCount[PacketNumberSpace::Initial] &&
       numProbePackets) ||
      initialScheduler.hasData() || toWriteInitialAcks(*conn_) ||
      hasBufferedDataToWrite(*conn_)) {
    CHECK(conn_->initialHeaderCipher);
    return writeCryptoAndAckDataToSocket(
        *socket_,
        *conn_,
        srcConnId /* src */,
        dstConnId /* dst */,
        LongHeader::Types::Initial,
        *conn_->initialWriteCipher,
        *conn_->initialHeaderCipher,
        version,
        packetLimit,
        token);
  }
  return WriteQuicDataResult{};
}

WriteQuicDataResult QuicTransportBase::handleHandshakeWriteDataCommon(
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    uint64_t packetLimit) {
  auto version = conn_->version.value_or(*(conn_->originalVersion));
  CHECK(conn_->handshakeWriteCipher);
  auto& handshakeCryptoStream =
      *getCryptoStream(*conn_->cryptoState, EncryptionLevel::Handshake);
  CryptoStreamScheduler handshakeScheduler(*conn_, handshakeCryptoStream);
  auto& numProbePackets =
      conn_->pendingEvents.numProbePackets[PacketNumberSpace::Handshake];
  if ((conn_->outstandings.packetCount[PacketNumberSpace::Handshake] &&
       handshakeCryptoStream.retransmissionBuffer.size() && numProbePackets) ||
      handshakeScheduler.hasData() || toWriteHandshakeAcks(*conn_) ||
      hasBufferedDataToWrite(*conn_)) {
    CHECK(conn_->handshakeWriteHeaderCipher);
    return writeCryptoAndAckDataToSocket(
        *socket_,
        *conn_,
        srcConnId /* src */,
        dstConnId /* dst */,
        LongHeader::Types::Handshake,
        *conn_->handshakeWriteCipher,
        *conn_->handshakeWriteHeaderCipher,
        version,
        packetLimit);
  }
  return WriteQuicDataResult{};
}

} // namespace quic
