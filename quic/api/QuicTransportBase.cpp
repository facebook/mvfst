/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/QuicTransportBase.h>

#include <folly/ScopeGuard.h>
#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/TimeUtil.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/stream/StreamStateMachine.h>

namespace quic {

QuicTransportBase::QuicTransportBase(
    folly::EventBase* evb,
    std::unique_ptr<folly::AsyncUDPSocket> socket)
    : evb_(evb),
      socket_(std::move(socket)),
      lossTimeout_(this),
      ackTimeout_(this),
      pathValidationTimeout_(this),
      idleTimeout_(this),
      drainTimeout_(this),
      readLooper_(new FunctionLooper(
          evb,
          [this](bool /* ignored */) { invokeReadDataAndCallbacks(); },
          LooperType::ReadLooper)),
      peekLooper_(new FunctionLooper(
          evb,
          [this](bool /* ignored */) { invokePeekDataAndCallbacks(); },
          LooperType::PeekLooper)),
      writeLooper_(new FunctionLooper(
          evb,
          [this](bool fromTimer) { pacedWriteDataToSocket(fromTimer); },
          LooperType::WriteLooper)) {
  writeLooper_->setPacingFunction([this]() -> auto {
    if (isConnectionPaced(*conn_)) {
      conn_->congestionController->markPacerTimeoutScheduled(Clock::now());
      return conn_->congestionController->getPacingInterval();
    }
    return 0us;
  });
}

void QuicTransportBase::setPacingTimer(
    TimerHighRes::SharedPtr pacingTimer) noexcept {
  if (pacingTimer) {
    writeLooper_->setPacingTimer(std::move(pacingTimer));
    if (conn_->congestionController) {
      conn_->congestionController->setMinimalPacingInterval(
          writeLooper_->getTimerTickInterval().value());
    }
  }
}

void QuicTransportBase::setCongestionControllerFactory(
    std::shared_ptr<CongestionControllerFactory> ccFactory) {
  CHECK(ccFactory);
  ccFactory_ = ccFactory;
}

folly::EventBase* QuicTransportBase::getEventBase() const {
  return evb_.load();
}

const std::shared_ptr<QLogger> QuicTransportBase::getQLogger() const {
  return conn_->qLogger;
}

folly::Optional<ConnectionId> QuicTransportBase::getClientConnectionId() const {
  return conn_->clientConnectionId;
}

folly::Optional<ConnectionId> QuicTransportBase::getServerConnectionId() const {
  return conn_->serverConnectionId;
}

const folly::SocketAddress& QuicTransportBase::getPeerAddress() const {
  return conn_->peerAddress;
}

const folly::SocketAddress& QuicTransportBase::getOriginalPeerAddress() const {
  return conn_->originalPeerAddress;
}

const folly::SocketAddress& QuicTransportBase::getLocalAddress() const {
  return socket_ && socket_->isBound() ? socket_->address()
                                       : localFallbackAddress;
}

QuicTransportBase::~QuicTransportBase() {
  connCallback_ = nullptr;
  QUIC_TRACE(
      conn_close,
      *conn_,
      (uint64_t) false,
      (uint64_t) true,
      "destructor",
      "no_error");
  closeImpl(
      std::make_pair(
          QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
          std::string("Closing from base destructor")),
      false);
  // If a drainTimeout is already scheduled, then closeNow above
  // won't do anything. We have to manually clean up the socket. Timeout will be
  // canceled by timer's destructor.
  if (socket_) {
    auto sock = std::move(socket_);
    socket_ = nullptr;
    sock->pauseRead();
    sock->close();
  }
}

bool QuicTransportBase::good() const {
  return hasWriteCipher() && !error();
}

bool QuicTransportBase::replaySafe() const {
  return (conn_->oneRttWriteCipher != nullptr);
}

bool QuicTransportBase::error() const {
  return conn_->localConnectionError.hasValue();
}

void QuicTransportBase::close(
    folly::Optional<std::pair<QuicErrorCode, std::string>> errorCode) {
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  // The caller probably doesn't need a conn callback any more because they
  // explicitly called close.
  connCallback_ = nullptr;

  closeImpl(std::move(errorCode), true);
  conn_->logger.reset();
}

void QuicTransportBase::closeNow(
    folly::Optional<std::pair<QuicErrorCode, std::string>> errorCode) {
  DCHECK(getEventBase() && getEventBase()->isInEventBaseThread());
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  VLOG(4) << __func__ << " " << *this;
  closeImpl(std::move(errorCode), false);
  // the drain timeout may have been scheduled by a previous close, in which
  // case, our close would not take effect. This cancels the drain timeout in
  // this case and expires the timeout.
  // TODO: fix this in a better way.
  if (drainTimeout_.isScheduled()) {
    drainTimeout_.cancelTimeout();
    drainTimeoutExpired();
  }

  conn_->logger.reset();
}

void QuicTransportBase::closeGracefully() {
  if (closeState_ == CloseState::CLOSED ||
      closeState_ == CloseState::GRACEFUL_CLOSING) {
    return;
  }
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  connCallback_ = nullptr;
  closeState_ = CloseState::GRACEFUL_CLOSING;
  updatePacingOnClose(*conn_);
  if (conn_->qLogger) {
    conn_->qLogger->addConnectionClose(
        kNoError.str(), kGracefulExit.str(), true, false);
  }
  QUIC_TRACE(
      conn_close,
      *conn_,
      (uint64_t) true,
      (uint64_t) false,
      "graceful",
      "no_error");

  // Stop reads and cancel all the app callbacks.
  VLOG(10) << "Stopping read and peek loopers due to graceful close " << *this;
  readLooper_->stop();
  peekLooper_->stop();
  cancelAllAppCallbacks(std::make_pair(
      QuicErrorCode(LocalErrorCode::NO_ERROR), "Graceful Close"));
  // All streams are closed, close the transport for realz.
  if (conn_->streamManager->streamCount() == 0) {
    closeImpl(folly::none);
  }
}

void QuicTransportBase::closeImpl(
    folly::Optional<std::pair<QuicErrorCode, std::string>> errorCode,
    bool drainConnection,
    bool sendCloseImmediately) {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }

  uint64_t totalCryptoDataWritten = 0;
  uint64_t totalCryptoDataRecvd = 0;

  if (conn_->cryptoState) {
    totalCryptoDataWritten +=
        conn_->cryptoState->initialStream.currentWriteOffset;
    totalCryptoDataWritten +=
        conn_->cryptoState->handshakeStream.currentWriteOffset;
    totalCryptoDataWritten +=
        conn_->cryptoState->oneRttStream.currentWriteOffset;

    totalCryptoDataRecvd += conn_->cryptoState->initialStream.maxOffsetObserved;
    totalCryptoDataRecvd +=
        conn_->cryptoState->handshakeStream.maxOffsetObserved;
    totalCryptoDataRecvd += conn_->cryptoState->oneRttStream.maxOffsetObserved;
  }

  QUIC_TRACE(
      transport_data,
      *conn_,
      conn_->lossState.totalBytesSent,
      conn_->lossState.totalBytesRecvd,
      conn_->flowControlState.sumCurWriteOffset,
      conn_->flowControlState.sumMaxObservedOffset,
      conn_->flowControlState.sumCurStreamBufferLen,
      conn_->lossState.totalBytesRetransmitted,
      conn_->lossState.totalStreamBytesCloned,
      conn_->lossState.totalBytesCloned,
      totalCryptoDataWritten,
      totalCryptoDataRecvd);

  if (conn_->qLogger) {
    conn_->qLogger->addTransportSummary(
        conn_->lossState.totalBytesSent,
        conn_->lossState.totalBytesRecvd,
        conn_->flowControlState.sumCurWriteOffset,
        conn_->flowControlState.sumMaxObservedOffset,
        conn_->flowControlState.sumCurStreamBufferLen,
        conn_->lossState.totalBytesRetransmitted,
        conn_->lossState.totalStreamBytesCloned,
        conn_->lossState.totalBytesCloned,
        totalCryptoDataWritten,
        totalCryptoDataRecvd);
  }

  // TODO: truncate the error code string to be 1MSS only.
  closeState_ = CloseState::CLOSED;
  updatePacingOnClose(*conn_);
  auto cancelCode = std::make_pair(
      QuicErrorCode(LocalErrorCode::NO_ERROR),
      toString(LocalErrorCode::NO_ERROR));
  if (conn_->peerConnectionError) {
    cancelCode = *conn_->peerConnectionError;
  } else if (errorCode) {
    cancelCode = *errorCode;
  }
  bool isReset = false;
  bool isAbandon = false;
  folly::variant_match(
      cancelCode.first,
      [&](const LocalErrorCode& err) {
        isReset = err == LocalErrorCode::CONNECTION_RESET;
        isAbandon = err == LocalErrorCode::CONNECTION_ABANDONED;
      },
      [](const auto&) {});
  VLOG_IF(4, isReset) << "Closing transport due to stateless reset " << *this;
  VLOG_IF(4, isAbandon) << "Closing transport due to abandoned connection "
                        << *this;
  if (errorCode) {
    conn_->localConnectionError = errorCode;
    std::string errorStr = conn_->localConnectionError->second;
    std::string errorCodeStr = errorCode->second;
    if (conn_->qLogger) {
      conn_->qLogger->addConnectionClose(
          errorStr, errorCodeStr, drainConnection, sendCloseImmediately);
    }
    QUIC_TRACE(
        conn_close,
        *conn_,
        (uint64_t)drainConnection,
        (uint64_t)sendCloseImmediately,
        errorStr,
        errorCode->second.c_str());
  } else {
    auto reason = folly::to<std::string>(
        "Server: ",
        kNoError.str(),
        ", Peer: isReset: ",
        isReset,
        ", Peer: isAbandon: ",
        isAbandon);
    if (conn_->qLogger) {
      conn_->qLogger->addConnectionClose(
          kNoError.str(), reason, drainConnection, sendCloseImmediately);
    }
    QUIC_TRACE(
        conn_close,
        *conn_,
        (uint64_t)drainConnection,
        (uint64_t)sendCloseImmediately,
        "no_error",
        "no_error");
  }
  cancelLossTimeout();
  if (ackTimeout_.isScheduled()) {
    ackTimeout_.cancelTimeout();
  }
  if (pathValidationTimeout_.isScheduled()) {
    pathValidationTimeout_.cancelTimeout();
  }
  if (idleTimeout_.isScheduled()) {
    idleTimeout_.cancelTimeout();
  }
  VLOG(10) << "Stopping read looper due to immediate close " << *this;
  readLooper_->stop();
  peekLooper_->stop();
  writeLooper_->stop();

  // TODO: invoke connection close callbacks.
  cancelAllAppCallbacks(cancelCode);

  // Clear out all the pending events, we don't need them any more.
  closeTransport();

  // Clear out all the streams, we don't need them any more. When the peer
  // receives the conn close they will implicitly reset all the streams.
  QUIC_STATS_FOR_EACH(
      conn_->streamManager->streams().cbegin(),
      conn_->streamManager->streams().cend(),
      conn_->infoCallback,
      onQuicStreamClosed);
  conn_->streamManager->clearOpenStreams();

  // Clear out all the pending events.
  conn_->pendingEvents = QuicConnectionStateBase::PendingEvents();
  conn_->streamManager->clearActionable();
  conn_->streamManager->clearWritable();
  conn_->ackStates.initialAckState.acks.clear();
  conn_->ackStates.handshakeAckState.acks.clear();
  conn_->ackStates.appDataAckState.acks.clear();

  // connCallback_ could be null if start() was never invoked and the
  // transport was destroyed or if the app initiated close.
  if (connCallback_) {
    bool noError = folly::variant_match(
        cancelCode.first,
        [](const LocalErrorCode& err) {
          return err == LocalErrorCode::NO_ERROR ||
              err == LocalErrorCode::IDLE_TIMEOUT;
        },
        [](const TransportErrorCode& err) {
          return err == TransportErrorCode::NO_ERROR;
        },
        [](const auto&) { return false; });
    if (noError) {
      connCallback_->onConnectionEnd();
    } else {
      connCallback_->onConnectionError(cancelCode);
    }
  }

  // can't invoke connection callbacks any more.
  connCallback_ = nullptr;

  // Don't need outstanding packets.
  conn_->outstandingPackets.clear();
  conn_->outstandingHandshakePacketsCount = 0;
  conn_->outstandingPureAckPacketsCount = 0;

  // We don't need no congestion control.
  conn_->congestionController = nullptr;

  sendCloseImmediately = sendCloseImmediately && !isReset && !isAbandon;
  if (sendCloseImmediately) {
    // We might be invoked from the destructor, so just send the connection
    // close directly.
    try {
      writeData();
    } catch (const std::exception& ex) {
      // This could happen if the writes fail.
      LOG(ERROR) << "close threw exception " << ex.what() << " " << *this;
    }
  }
  drainConnection = drainConnection && !isReset && !isAbandon;
  if (drainConnection) {
    // We ever drain once, and the object ever gets created once.
    DCHECK(!drainTimeout_.isScheduled());
    getEventBase()->timer().scheduleTimeout(
        &drainTimeout_,
        std::chrono::duration_cast<std::chrono::milliseconds>(
            kDrainFactor * calculatePTO(*conn_)));
  } else {
    drainTimeoutExpired();
  }
}

void QuicTransportBase::drainTimeoutExpired() noexcept {
  if (socket_) {
    auto sock = std::move(socket_);
    socket_ = nullptr;
    sock->pauseRead();
    sock->close();
  }
  unbindConnection();
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
    auto stream = conn_->streamManager->getStream(id);
    if (!stream) {
      return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
    }
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
    auto stream = conn_->streamManager->getStream(id);
    if (!stream) {
      return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
    }
    return stream->writeBuffer.chainLength();
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
  uint64_t writableBytes = std::numeric_limits<uint64_t>::max();
  uint64_t congestionWindow = std::numeric_limits<uint64_t>::max();
  uint64_t burstSize = 0;
  std::chrono::microseconds pacingInterval = 0ms;
  if (conn_->congestionController) {
    writableBytes = conn_->congestionController->getWritableBytes();
    congestionWindow = conn_->congestionController->getCongestionWindow();
    // Do not collect pacing stats for Cubic, since getPacingRate() call
    // modifies some internal state. TODO(yangchi): Remove this check after
    // changing Cubic implementation.
    if (conn_->congestionController->type() != CongestionControlType::Cubic &&
        isConnectionPaced(*conn_)) {
      burstSize = conn_->congestionController->getPacingRate(Clock::now());
      pacingInterval = conn_->congestionController->getPacingInterval();
    }
  }
  TransportInfo transportInfo;
  transportInfo.srtt = conn_->lossState.srtt;
  transportInfo.rttvar = conn_->lossState.rttvar;
  transportInfo.lrtt = conn_->lossState.lrtt;
  transportInfo.mrtt = conn_->lossState.mrtt;
  transportInfo.writableBytes = writableBytes;
  transportInfo.congestionWindow = congestionWindow;
  transportInfo.pacingBurstSize = burstSize;
  transportInfo.pacingInterval = pacingInterval;
  transportInfo.packetsRetransmitted = conn_->lossState.rtxCount;
  transportInfo.timeoutBasedLoss = conn_->lossState.timeoutBasedRtxCount;
  transportInfo.totalBytesRetransmitted =
      conn_->lossState.totalBytesRetransmitted;
  transportInfo.pto = calculatePTO(*conn_);
  transportInfo.bytesSent = conn_->lossState.totalBytesSent;
  transportInfo.bytesAcked = conn_->lossState.totalBytesAcked;
  transportInfo.bytesRecvd = conn_->lossState.totalBytesRecvd;
  transportInfo.ptoCount = conn_->lossState.ptoCount;
  transportInfo.totalPTOCount = conn_->lossState.totalPTOCount;
  transportInfo.largestPacketAckedByPeer =
      conn_->ackStates.appDataAckState.largestAckedByPeer;
  transportInfo.largestPacketSent = conn_->lossState.largestSent;
  return transportInfo;
}

folly::Optional<std::string> QuicTransportBase::getAppProtocol() const {
  return conn_->handshakeLayer->getApplicationProtocol();
}

void QuicTransportBase::setReceiveWindow(
    StreamId /*id*/,
    size_t /*recvWindowSize*/) {}

void QuicTransportBase::setSendBuffer(
    StreamId /*id*/,
    size_t /*maxUnacked*/,
    size_t /*maxUnsent*/) {}

uint64_t QuicTransportBase::bufferSpaceAvailable() {
  auto bytesBuffered = conn_->flowControlState.sumCurStreamBufferLen;
  auto totalBufferSpaceAvailable =
      conn_->transportSettings.totalBufferSpaceAvailable;
  return bytesBuffered > totalBufferSpaceAvailable
      ? 0
      : totalBufferSpaceAvailable - bytesBuffered;
}

folly::Expected<QuicSocket::FlowControlState, LocalErrorCode>
QuicTransportBase::getConnectionFlowControl() const {
  return QuicSocket::FlowControlState(
      getSendConnFlowControlBytesAPI(*conn_),
      conn_->flowControlState.peerAdvertisedMaxOffset,
      getRecvConnFlowControlBytes(*conn_),
      conn_->flowControlState.advertisedMaxOffset);
}

folly::Expected<QuicSocket::FlowControlState, LocalErrorCode>
QuicTransportBase::getStreamFlowControl(StreamId id) const {
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
  if (!stream->writable()) {
    VLOG(10) << "Tried to write to non writable stream=" << id << " " << *this;
    return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
  }
  return QuicSocket::FlowControlState(
      getSendStreamFlowControlBytesAPI(*stream),
      stream->flowControlState.peerAdvertisedMaxOffset,
      getRecvStreamFlowControlBytes(*stream),
      stream->flowControlState.advertisedMaxOffset);
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
  if (!stream->writable()) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
  }
  stream->flowControlState.windowSize = windowSize;
  maybeSendStreamWindowUpdate(*stream, Clock::now());
  updateWriteLooper(true);
  return folly::unit;
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::setReadCallback(
    StreamId id,
    ReadCallback* cb) {
  if (isSendingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  return setReadCallbackInternal(id, cb);
}

void QuicTransportBase::unsetAllReadCallbacks() {
  for (auto& streamCallbackPair : readCallbacks_) {
    setReadCallbackInternal(streamCallbackPair.first, nullptr);
  }
}

void QuicTransportBase::unsetAllPeekCallbacks() {
  for (auto& streamCallbackPair : peekCallbacks_) {
    setPeekCallbackInternal(streamCallbackPair.first, nullptr);
  }
}

void QuicTransportBase::unsetAllDeliveryCallbacks() {
  auto deliveryCallbacksCopy = deliveryCallbacks_;
  for (auto& streamCallbackPair : deliveryCallbacksCopy) {
    cancelDeliveryCallbacksForStream(streamCallbackPair.first);
  }
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setReadCallbackInternal(
    StreamId id,
    ReadCallback* cb) noexcept {
  VLOG(4) << "Setting setReadCallback for stream=" << id << " cb=" << cb << " "
          << *this;
  auto readCbIt = readCallbacks_.find(id);
  if (readCbIt == readCallbacks_.end()) {
    // Don't allow initial setting of a nullptr callback.
    if (!cb) {
      return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
    }
    readCbIt = readCallbacks_.emplace(id, ReadCallbackData(cb)).first;
  }
  auto& readCb = readCbIt->second.readCb;
  if (readCb == nullptr && cb != nullptr) {
    // It's already been set to nullptr we do not allow unsetting it.
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  } else {
    readCb = cb;
    if (readCb == nullptr) {
      return stopSending(id, GenericApplicationErrorCode::NO_ERROR);
    }
  }
  updateReadLooper();
  return folly::unit;
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::pauseRead(
    StreamId id) {
  VLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumeRead(id, false);
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::stopSending(
    StreamId id,
    ApplicationErrorCode error) {
  if (isSendingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  sendSimpleFrame(*conn_, StopSendingFrame(id, error));
  updateWriteLooper(true);
  return folly::unit;
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

void QuicTransportBase::invokeReadDataAndCallbacks() {
  auto self = sharedGuard();
  SCOPE_EXIT {
    self->checkForClosedStream();
    self->updateReadLooper();
    self->updateWriteLooper(true);
  };
  auto readableListCopy = self->conn_->streamManager->readableStreams();
  for (const auto& streamId : readableListCopy) {
    auto callback = self->readCallbacks_.find(streamId);
    if (callback == self->readCallbacks_.end()) {
      self->conn_->streamManager->readableStreams().erase(streamId);
      continue;
    }
    auto readCb = callback->second.readCb;
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));
    if (!stream) {
      continue;
    }
    if (readCb && stream->streamReadError) {
      self->conn_->streamManager->readableStreams().erase(streamId);
      readCallbacks_.erase(streamId);
      // if there is an error on the stream - it's not readable anymore, so
      // we cannot peek into it as well.
      VLOG(10) << "Erasing peek callback for stream=" << streamId;
      self->conn_->streamManager->peekableStreams().erase(streamId);
      peekCallbacks_.erase(streamId);
      VLOG(10) << "invoking read error callbacks on stream=" << streamId << " "
               << *this;
      readCb->readError(
          streamId, std::make_pair(*stream->streamReadError, folly::none));
    } else if (
        readCb && callback->second.resumed && stream->hasReadableData()) {
      VLOG(10) << "invoking read callbacks on stream=" << streamId << " "
               << *this;
      readCb->readAvailable(streamId);
    }
  }
}

void QuicTransportBase::updateReadLooper() {
  if (closeState_ != CloseState::OPEN) {
    VLOG(10) << "Stopping read looper " << *this;
    readLooper_->stop();
    return;
  }
  auto iter = std::find_if(
      conn_->streamManager->readableStreams().begin(),
      conn_->streamManager->readableStreams().end(),
      [& readCallbacks = readCallbacks_](StreamId s) {
        auto readCb = readCallbacks.find(s);
        if (readCb == readCallbacks.end()) {
          return false;
        }
        // TODO: if the stream has an error and it is also paused we should
        // still return an error
        return readCb->second.readCb && readCb->second.resumed;
      });
  if (iter != conn_->streamManager->readableStreams().end()) {
    VLOG(10) << "Scheduling read looper " << *this;
    readLooper_->run();
  } else {
    VLOG(10) << "Stopping read looper " << *this;
    readLooper_->stop();
  }
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
    VLOG(10) << "Resetting the peek callback to nullptr "
             << "stream=" << id << " peekCb=" << peekCbIt->second.peekCb;
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

void QuicTransportBase::invokePeekDataAndCallbacks() {
  auto self = sharedGuard();
  SCOPE_EXIT {
    self->checkForClosedStream();
    self->updatePeekLooper();
    self->updateWriteLooper(true);
  };
  // TODO: add protection from calling "consume" in the middle of the peek -
  // one way is to have a peek counter that is incremented when peek calblack
  // is called and decremented when peek is done. once counter transitions
  // to 0 we can execute "consume" calls that were done during "peek", for that,
  // we would need to keep stack of them.
  auto peekableListCopy = self->conn_->streamManager->peekableStreams();
  VLOG(10) << __func__
           << " peekableListCopy.size()=" << peekableListCopy.size();
  for (const auto& streamId : peekableListCopy) {
    auto callback = self->peekCallbacks_.find(streamId);
    // This is a likely bug. Need to think more on whether events can
    // be dropped
    // remove streamId from list of peekable - as opposed to "read",  "peek" is
    // only called once per streamId and not on every EVB loop until application
    // reads the data.
    self->conn_->streamManager->peekableStreams().erase(streamId);
    if (callback == self->peekCallbacks_.end()) {
      VLOG(10) << " No peek callback for stream=" << streamId;
      continue;
    }
    auto peekCb = callback->second.peekCb;
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));
    if (!stream) {
      continue;
    }
    if (peekCb && !stream->streamReadError && stream->hasPeekableData()) {
      VLOG(10) << "invoking peek callbacks on stream=" << streamId << " "
               << *this;

      peekDataFromQuicStream(
          *stream,
          [&](StreamId id, const folly::Range<PeekIterator>& peekRange) {
            peekCb->onDataAvailable(id, peekRange);
          });
    } else {
      VLOG(10) << "Not invoking peek callbacks on stream=" << streamId;
    }
  }
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setDataExpiredCallback(
    StreamId id,
    DataExpiredCallback* cb) {
  if (!conn_->partialReliabilityEnabled) {
    return folly::makeUnexpected(LocalErrorCode::APP_ERROR);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }

  VLOG(4) << "Setting DataExpiredCallback for stream=" << id << " cb=" << cb
          << " " << *this;

  auto dataExpiredCbIt = dataExpiredCallbacks_.find(id);
  if (dataExpiredCbIt == dataExpiredCallbacks_.end()) {
    if (!cb) {
      return folly::unit;
    }
    dataExpiredCbIt =
        dataExpiredCallbacks_.emplace(id, DataExpiredCallbackData(cb)).first;
  }

  if (!cb) {
    dataExpiredCallbacks_.erase(dataExpiredCbIt);
  } else {
    dataExpiredCbIt->second.dataExpiredCb = cb;
  }

  runOnEvbAsync([](auto self) { self->invokeDataExpiredCallbacks(); });

  return folly::unit;
}

void QuicTransportBase::invokeDataExpiredCallbacks() {
  auto self = sharedGuard();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  for (auto streamId : self->conn_->streamManager->dataExpiredStreams()) {
    auto callbackData = self->dataExpiredCallbacks_.find(streamId);
    // Data expired is edge-triggered (nag only once on arrival), unlike read
    // which is level-triggered (nag until application calls read() and
    // clears the buffer).
    if (callbackData == self->dataExpiredCallbacks_.end()) {
      continue;
    }

    auto dataExpiredCb = callbackData->second.dataExpiredCb;
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));

    if (dataExpiredCb && !stream->streamReadError) {
      // If new offset is before current read offset, skip.
      if (stream->currentReceiveOffset < stream->currentReadOffset) {
        continue;
      }
      VLOG(10) << "invoking data expired callback on stream=" << streamId << " "
               << *this;
      dataExpiredCb->onDataExpired(streamId, stream->currentReceiveOffset);
    }
  }
  self->conn_->streamManager->clearDataExpired();
}

folly::Expected<folly::Optional<uint64_t>, LocalErrorCode>
QuicTransportBase::sendDataExpired(StreamId id, uint64_t offset) {
  if (!conn_->partialReliabilityEnabled) {
    return folly::makeUnexpected(LocalErrorCode::APP_ERROR);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  auto stream = conn_->streamManager->getStream(id);
  if (!stream) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto newOffset = advanceMinimumRetransmittableOffset(stream, offset);

  // Invoke any delivery callbacks that are set for any offset below newOffset.
  if (newOffset) {
    cancelDeliveryCallbacksForStream(id, *newOffset);
  }

  updateWriteLooper(true);
  return folly::makeExpected<LocalErrorCode>(newOffset);
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setDataRejectedCallback(
    StreamId id,
    DataRejectedCallback* cb) {
  if (!conn_->partialReliabilityEnabled) {
    return folly::makeUnexpected(LocalErrorCode::APP_ERROR);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }

  VLOG(4) << "Setting DataRejectedCallback for stream=" << id << " cb=" << cb
          << " " << *this;

  auto dataRejectedCbIt = dataRejectedCallbacks_.find(id);
  if (dataRejectedCbIt == dataRejectedCallbacks_.end()) {
    if (!cb) {
      return folly::unit;
    }
    dataRejectedCbIt =
        dataRejectedCallbacks_.emplace(id, DataRejectedCallbackData(cb)).first;
  }

  if (!cb) {
    dataRejectedCallbacks_.erase(dataRejectedCbIt);
  } else {
    dataRejectedCbIt->second.dataRejectedCb = cb;
  }

  runOnEvbAsync([](auto self) { self->invokeDataRejectedCallbacks(); });

  return folly::unit;
}

void QuicTransportBase::invokeDataRejectedCallbacks() {
  auto self = sharedGuard();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  for (auto streamId : self->conn_->streamManager->dataRejectedStreams()) {
    auto callbackData = self->dataRejectedCallbacks_.find(streamId);
    // Data rejected is edge-triggered (nag only once on arrival), unlike read
    // which is level-triggered (nag until application calls read() and
    // clears the buffer).

    if (callbackData == self->dataRejectedCallbacks_.end()) {
      continue;
    }

    auto dataRejectedCb = callbackData->second.dataRejectedCb;
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));

    // Invoke any delivery callbacks that are set for any offset below newly set
    // minimumRetransmittableOffset.
    if (!stream->streamReadError) {
      cancelDeliveryCallbacksForStream(
          streamId, stream->minimumRetransmittableOffset);
    }

    if (dataRejectedCb && !stream->streamReadError) {
      VLOG(10) << "invoking data rejected callback on stream=" << streamId
               << " " << *this;
      dataRejectedCb->onDataRejected(
          streamId, stream->minimumRetransmittableOffset);
    }
  }
  self->conn_->streamManager->clearDataRejected();
}

folly::Expected<folly::Optional<uint64_t>, LocalErrorCode>
QuicTransportBase::sendDataRejected(StreamId id, uint64_t offset) {
  if (!conn_->partialReliabilityEnabled) {
    return folly::makeUnexpected(LocalErrorCode::APP_ERROR);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  auto stream = conn_->streamManager->getStream(id);
  if (!stream) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto newOffset = advanceCurrentReceiveOffset(stream, offset);
  updateWriteLooper(true);
  return folly::makeExpected<LocalErrorCode>(newOffset);
}

void QuicTransportBase::updatePeekLooper() {
  if (closeState_ != CloseState::OPEN) {
    VLOG(10) << "Stopping peek looper " << *this;
    peekLooper_->stop();
    return;
  }
  VLOG(10) << "Updating peek looper, has "
           << conn_->streamManager->peekableStreams().size()
           << " peekable streams";
  auto iter = std::find_if(
      conn_->streamManager->peekableStreams().begin(),
      conn_->streamManager->peekableStreams().end(),
      [& peekCallbacks = peekCallbacks_](StreamId s) {
        VLOG(10) << "Checking stream=" << s;
        auto peekCb = peekCallbacks.find(s);
        if (peekCb == peekCallbacks.end()) {
          VLOG(10) << "No peek callbacks for stream=" << s;
          return false;
        }
        if (!peekCb->second.resumed) {
          VLOG(10) << "peek callback for stream=" << s << " not resumed";
        }

        if (!peekCb->second.peekCb) {
          VLOG(10) << "no peekCb in peekCb stream=" << s;
        }
        return peekCb->second.peekCb && peekCb->second.resumed;
      });
  if (iter != conn_->streamManager->peekableStreams().end()) {
    VLOG(10) << "Scheduling peek looper " << *this;
    peekLooper_->run();
  } else {
    VLOG(10) << "Stopping peek looper " << *this;
    peekLooper_->stop();
  }
}

void QuicTransportBase::updateWriteLooper(bool thisIteration) {
  if (closeState_ == CloseState::CLOSED) {
    VLOG(10) << nodeToString(conn_->nodeType)
             << " stopping write looper because conn closed " << *this;
    writeLooper_->stop();
    return;
  }
  // TODO: Also listens to write event from libevent. Only schedule write when
  // the socket itself is writable.
  auto writeDataReason = shouldWriteData(*conn_);
  if (writeDataReason != WriteDataReason::NO_WRITE) {
    VLOG(10) << nodeToString(conn_->nodeType)
             << " running write looper thisIteration=" << thisIteration << " "
             << *this;
    writeLooper_->run(thisIteration);
    conn_->debugState.needsWriteLoopDetect =
        (conn_->loopDetectorCallback != nullptr);
  } else {
    VLOG(10) << nodeToString(conn_->nodeType) << " stopping write looper "
             << *this;
    writeLooper_->stop();
    conn_->debugState.needsWriteLoopDetect = false;
    conn_->debugState.currentEmptyLoopCount = 0;
  }
  conn_->debugState.writeDataReason = writeDataReason;
}

void QuicTransportBase::cancelDeliveryCallbacksForStream(StreamId streamId) {
  if (isReceivingStream(conn_->nodeType, streamId)) {
    return;
  }
  conn_->streamManager->removeDeliverable(streamId);
  auto deliveryCallbackIter = deliveryCallbacks_.find(streamId);
  if (deliveryCallbackIter == deliveryCallbacks_.end()) {
    return;
  }
  while (!deliveryCallbackIter->second.empty()) {
    auto deliveryCallback = deliveryCallbackIter->second.front();
    deliveryCallbackIter->second.pop_front();
    deliveryCallback.second->onCanceled(streamId, deliveryCallback.first);
    if (closeState_ != CloseState::OPEN) {
      // socket got closed - we can't use deliveryCallbackIter anymore,
      // closeImpl should take care of delivering callbacks that are left in
      // deliveryCallbackIter->second
      return;
    }
  }
  deliveryCallbacks_.erase(deliveryCallbackIter);
}

void QuicTransportBase::cancelDeliveryCallbacksForStream(
    StreamId streamId,
    uint64_t offset) {
  if (isReceivingStream(conn_->nodeType, streamId)) {
    return;
  }

  auto deliveryCallbackIter = deliveryCallbacks_.find(streamId);
  if (deliveryCallbackIter == deliveryCallbacks_.end()) {
    conn_->streamManager->removeDeliverable(streamId);
    return;
  }

  // Callbacks are kept sorted by offset, so we can just walk the queue and
  // invoke those with offset below provided offset.
  while (!deliveryCallbackIter->second.empty()) {
    auto deliveryCallback = deliveryCallbackIter->second.front();
    auto& cbOffset = deliveryCallback.first;
    if (cbOffset < offset) {
      deliveryCallbackIter->second.pop_front();
      deliveryCallback.second->onCanceled(streamId, cbOffset);
      if (closeState_ != CloseState::OPEN) {
        // socket got closed - we can't use deliveryCallbackIter anymore,
        // closeImpl should take care of delivering callbacks that are left in
        // deliveryCallbackIter->second
        return;
      }
    } else {
      // Only larger or equal offsets left, exit the loop.
      break;
    }
  }

  // Clean up state for this stream if no callbacks left to invoke.
  if (deliveryCallbackIter->second.empty()) {
    conn_->streamManager->removeDeliverable(streamId);
    deliveryCallbacks_.erase(deliveryCallbackIter);
  }
}

folly::Expected<std::pair<Buf, bool>, LocalErrorCode> QuicTransportBase::read(
    StreamId id,
    size_t maxLen) {
  if (isSendingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  SCOPE_EXIT {
    checkForClosedStream();
    updateReadLooper();
    updatePeekLooper(); // read can affect "peek" API
    updateWriteLooper(true);
  };
  try {
    // Need to check that the stream exists first so that we don't
    // accidentally let the API create a peer stream that was not
    // sent by the peer.
    if (!conn_->streamManager->streamExists(id)) {
      return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    auto stream = conn_->streamManager->getStream(id);
    if (!stream) {
      // This is not really possible since this should be covered
      // by the stream existence check, but might as well check this.
      return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
    }
    auto result = readDataFromQuicStream(*stream, maxLen);
    if (result.second) {
      VLOG(10) << "Delivered eof to app for stream=" << stream->id << " "
               << *this;
      auto it = readCallbacks_.find(id);
      if (it != readCallbacks_.end()) {
        // it's highly unlikely that someone called read() without having a read
        // callback so we don't deal with the case of someone installing a read
        // callback after reading the EOM.
        it->second.deliveredEOM = true;
      }
    }
    return folly::makeExpected<LocalErrorCode>(std::move(result));
  } catch (const QuicTransportException& ex) {
    VLOG(4) << "read() error " << ex.what() << " " << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
    return folly::makeUnexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
    return folly::makeUnexpected(ex.errorCode());
  } catch (const std::exception& ex) {
    VLOG(4) << "read() error " << ex.what() << " " << *this;
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string(ex.what())));
    return folly::makeUnexpected(LocalErrorCode::INTERNAL_ERROR);
  }
}

folly::Expected<folly::Unit, LocalErrorCode> QuicTransportBase::peek(
    StreamId id,
    const folly::Function<void(StreamId id, const folly::Range<PeekIterator>&)
                              const>& peekCallback) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  SCOPE_EXIT {
    checkForClosedStream();
    updatePeekLooper();
    updateWriteLooper(true);
  };

  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = conn_->streamManager->getStream(id);
  if (!stream) {
    // This is not really possible since this should be covered
    // by the stream existence check, but might as well check this.
    return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
  }

  if (stream->streamReadError) {
    return folly::variant_match(
        *stream->streamReadError,
        [](LocalErrorCode err) { return folly::makeUnexpected(err); },
        [](const auto&) {
          return folly::makeUnexpected(LocalErrorCode::INTERNAL_ERROR);
        });
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
  auto stream = conn_->streamManager->getStream(id);
  if (!stream) {
    // This is not really possible since this should be covered
    // by the stream existence check, but might as well check this.
    return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
  }
  auto result = consume(id, stream->currentReadOffset, amount);
  if (result.hasError()) {
    return folly::makeUnexpected(result.error().first);
  }
  return folly::makeExpected<LocalErrorCode>(result.value());
}

folly::
    Expected<folly::Unit, std::pair<LocalErrorCode, folly::Optional<uint64_t>>>
    QuicTransportBase::consume(StreamId id, uint64_t offset, size_t amount) {
  using ConsumeError = std::pair<LocalErrorCode, folly::Optional<uint64_t>>;
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(
        ConsumeError{LocalErrorCode::CONNECTION_CLOSED, folly::none});
  }
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  SCOPE_EXIT {
    checkForClosedStream();
    updatePeekLooper();
    updateReadLooper(); // consume may affect "read" API
    updateWriteLooper(true);
  };
  folly::Optional<uint64_t> readOffset = folly::none;
  try {
    // Need to check that the stream exists first so that we don't
    // accidentally let the API create a peer stream that was not
    // sent by the peer.
    if (!conn_->streamManager->streamExists(id)) {
      return folly::makeUnexpected(
          ConsumeError{LocalErrorCode::STREAM_NOT_EXISTS, readOffset});
    }
    auto stream = conn_->streamManager->getStream(id);
    if (!stream) {
      // This is not really possible since this should be covered
      // by the stream existence check, but might as well check this.
      return folly::makeUnexpected(
          ConsumeError{LocalErrorCode::STREAM_CLOSED, readOffset});
    }
    readOffset = stream->currentReadOffset;
    if (stream->currentReadOffset != offset) {
      return folly::makeUnexpected(
          ConsumeError{LocalErrorCode::INTERNAL_ERROR, readOffset});
    }

    if (stream->streamReadError) {
      return folly::variant_match(
          *stream->streamReadError,
          [](LocalErrorCode err) {
            return folly::makeUnexpected(ConsumeError{err, folly::none});
          },
          [](const auto&) {
            return folly::makeUnexpected(
                ConsumeError{LocalErrorCode::INTERNAL_ERROR, folly::none});
          });
    }

    consumeDataFromQuicStream(*stream, amount);
    return folly::makeExpected<ConsumeError>(folly::Unit());
  } catch (const QuicTransportException& ex) {
    VLOG(4) << "consume() error " << ex.what() << " " << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
    return folly::makeUnexpected(
        ConsumeError{LocalErrorCode::TRANSPORT_ERROR, readOffset});
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
    return folly::makeUnexpected(ConsumeError{ex.errorCode(), readOffset});
  } catch (const std::exception& ex) {
    VLOG(4) << "consume() error " << ex.what() << " " << *this;
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string(ex.what())));
    return folly::makeUnexpected(
        ConsumeError{LocalErrorCode::INTERNAL_ERROR, readOffset});
  }
}

void QuicTransportBase::processCallbacksAfterNetworkData() {
  if (UNLIKELY(closeState_ != CloseState::OPEN)) {
    return;
  }
  // TODO move all of this callback processing to individual functions.
  for (const auto& stream : conn_->streamManager->newPeerStreams()) {
    CHECK_NOTNULL(connCallback_);
    if (isBidirectionalStream(stream)) {
      connCallback_->onNewBidirectionalStream(stream);
    } else {
      connCallback_->onNewUnidirectionalStream(stream);
    }
    if (closeState_ != CloseState::OPEN) {
      break;
    }
  }
  conn_->streamManager->clearNewPeerStreams();
  // TODO: we're currently assuming that canceling write callbacks will not
  // cause reset of random streams. Maybe get rid of that assumption later.
  for (auto pendingResetIt = conn_->pendingEvents.resets.begin();
       closeState_ == CloseState::OPEN &&
       pendingResetIt != conn_->pendingEvents.resets.end();
       pendingResetIt++) {
    cancelDeliveryCallbacksForStream(pendingResetIt->first);
  }
  auto deliverableStreamId = conn_->streamManager->popDeliverable();
  while (closeState_ == CloseState::OPEN && deliverableStreamId.hasValue()) {
    auto streamId = *deliverableStreamId;
    auto stream = conn_->streamManager->getStream(streamId);
    // stream shouldn't be cleaned as long as it's still on deliveryList
    DCHECK(stream);

    while (closeState_ == CloseState::OPEN) {
      auto deliveryCallbacksForAckedStream = deliveryCallbacks_.find(streamId);
      if (deliveryCallbacksForAckedStream == deliveryCallbacks_.end() ||
          deliveryCallbacksForAckedStream->second.empty()) {
        break;
      }
      auto minOffsetToDeliver = getStreamNextOffsetToDeliver(*stream);
      if (deliveryCallbacksForAckedStream->second.front().first >
          minOffsetToDeliver) {
        break;
      }
      auto deliveryCallbackAndOffset =
          deliveryCallbacksForAckedStream->second.front();
      deliveryCallbacksForAckedStream->second.pop_front();
      auto currentDeliveryCallbackOffset = deliveryCallbackAndOffset.first;
      auto deliveryCallback = deliveryCallbackAndOffset.second;
      deliveryCallback->onDeliveryAck(
          stream->id, currentDeliveryCallbackOffset, conn_->lossState.srtt);
    }
    if (closeState_ != CloseState::OPEN) {
      break;
    }
    auto deliveryCallbacksForAckedStream = deliveryCallbacks_.find(streamId);
    if (deliveryCallbacksForAckedStream != deliveryCallbacks_.end() &&
        deliveryCallbacksForAckedStream->second.empty()) {
      deliveryCallbacks_.erase(streamId);
    }
    deliverableStreamId = conn_->streamManager->popDeliverable();
  }

  invokeDataExpiredCallbacks();
  invokeDataRejectedCallbacks();

  // Iterate over streams that changed their flow control window and give
  // their registered listeners their updates.
  // We don't really need flow control notifications when we are closed.
  for (auto streamId : conn_->streamManager->flowControlUpdated()) {
    auto stream = conn_->streamManager->getStream(streamId);
    if (!stream || !stream->writable()) {
      pendingWriteCallbacks_.erase(streamId);
      continue;
    }
    CHECK_NOTNULL(connCallback_)->onFlowControlUpdate(streamId);
    auto maxStreamWritable = maxWritableOnStream(*stream);
    if (maxStreamWritable != 0 && !pendingWriteCallbacks_.empty()) {
      auto pendingWriteIt = pendingWriteCallbacks_.find(stream->id);
      if (pendingWriteIt != pendingWriteCallbacks_.end()) {
        auto wcb = pendingWriteIt->second;
        pendingWriteCallbacks_.erase(stream->id);
        wcb->onStreamWriteReady(stream->id, maxStreamWritable);
      }
    }
    if (closeState_ != CloseState::OPEN) {
      break;
    }
  }
  conn_->streamManager->clearFlowControlUpdated();

  if (closeState_ == CloseState::OPEN) {
    for (auto itr : conn_->streamManager->stopSendingStreams()) {
      auto streamId = itr.first;
      auto stream = conn_->streamManager->getStream(streamId);
      if (stream) {
        CHECK_NOTNULL(connCallback_)->onStopSending(streamId, itr.second);
        if (closeState_ != CloseState::OPEN) {
          return;
        }
      }
    }
    conn_->streamManager->clearStopSending();
  }

  auto maxConnWrite = maxWritableOnConn();
  // We don't need onConnectionWriteReady notifications when we are closed.
  if (closeState_ == CloseState::OPEN && maxConnWrite != 0) {
    // If the connection now has flow control, we may either have been blocked
    // before on a pending write to the conn, or a stream's write.
    if (connWriteCallback_) {
      auto connWriteCallback = connWriteCallback_;
      connWriteCallback_ = nullptr;
      connWriteCallback->onConnectionWriteReady(maxConnWrite);
    }

    // If the connection flow control is unblocked, we might be unblocked
    // on the streams now. TODO: maybe do this only when we know connection
    // flow control changed.
    auto writeCallbackIt = pendingWriteCallbacks_.begin();

    // If we were closed, we would have errored out the callbacks which would
    // invalidate iterators, so just ignore all other calls.
    // We don't need writeReady notifications when we are closed.
    while (closeState_ == CloseState::OPEN &&
           writeCallbackIt != pendingWriteCallbacks_.end()) {
      auto streamId = writeCallbackIt->first;
      auto wcb = writeCallbackIt->second;
      ++writeCallbackIt;
      auto stream = conn_->streamManager->getStream(streamId);
      if (!stream || !stream->writable()) {
        pendingWriteCallbacks_.erase(streamId);
        continue;
      }
      auto maxStreamWritable = maxWritableOnStream(*stream);
      if (maxStreamWritable != 0) {
        pendingWriteCallbacks_.erase(streamId);
        wcb->onStreamWriteReady(streamId, maxStreamWritable);
      }
    }
  }
}

void QuicTransportBase::onNetworkData(
    const folly::SocketAddress& peer,
    NetworkData&& networkData) noexcept {
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  SCOPE_EXIT {
    checkForClosedStream();
    updateReadLooper();
    updatePeekLooper();
    updateWriteLooper(true);
  };
  try {
    if (networkData.data) {
      conn_->lossState.totalBytesRecvd +=
          networkData.data->computeChainDataLength();
    }
    auto originalAckVersion = currentAckStateVersion(*conn_);
    onReadData(peer, std::move(networkData));
    processCallbacksAfterNetworkData();
    if (closeState_ != CloseState::CLOSED) {
      if (currentAckStateVersion(*conn_) != originalAckVersion) {
        setIdleTimer();
        conn_->receivedNewPacketBeforeWrite = true;
      }
      // Reading data could process an ack and change the loss timer.
      setLossDetectionAlarm(*conn_, *self);
      // Reading data could change the state of the acks which could change the
      // ack timer. But we need to call scheduleAckTimeout() for it to take
      // effect.
      scheduleAckTimeout();
      // Received data could contain valid path response, in which case
      // path validation timeout should be canceled
      schedulePathValidationTimeout();
    } else {
      // In the closed state, we would want to write a close if possible however
      // the write looper will not be set.
      writeSocketData();
    }
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicApplicationException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string(ex.what())));
  }
}

void QuicTransportBase::setIdleTimer() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  if (idleTimeout_.isScheduled()) {
    idleTimeout_.cancelTimeout();
  }
  if (conn_->transportSettings.idleTimeout >
      std::chrono::milliseconds::zero()) {
    getEventBase()->timer().scheduleTimeout(
        &idleTimeout_, conn_->transportSettings.idleTimeout);
  }
}

uint64_t QuicTransportBase::getNumOpenableBidirectionalStreams() const {
  return conn_->streamManager->openableLocalBidirectionalStreams();
}

uint64_t QuicTransportBase::getNumOpenableUnidirectionalStreams() const {
  return conn_->streamManager->openableLocalUnidirectionalStreams();
}

folly::Expected<StreamId, LocalErrorCode>
QuicTransportBase::createStreamInternal(bool bidirectional) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  folly::Expected<QuicStreamState*, LocalErrorCode> streamResult;
  if (bidirectional) {
    streamResult = conn_->streamManager->createNextBidirectionalStream();
  } else {
    streamResult = conn_->streamManager->createNextUnidirectionalStream();
  }
  if (streamResult) {
    return streamResult.value()->id;
  } else {
    return folly::makeUnexpected(streamResult.error());
  }
}

folly::Expected<StreamId, LocalErrorCode>
QuicTransportBase::createBidirectionalStream(bool /*replaySafe*/) {
  return createStreamInternal(true);
}

folly::Expected<StreamId, LocalErrorCode>
QuicTransportBase::createUnidirectionalStream(bool /*replaySafe*/) {
  return createStreamInternal(false);
}

bool QuicTransportBase::isUnidirectionalStream(StreamId stream) noexcept {
  return quic::isUnidirectionalStream(stream);
}

bool QuicTransportBase::isClientStream(StreamId stream) noexcept {
  return quic::isClientStream(stream);
}

bool QuicTransportBase::isServerStream(StreamId stream) noexcept {
  return quic::isServerStream(stream);
}

bool QuicTransportBase::isBidirectionalStream(StreamId stream) noexcept {
  return quic::isBidirectionalStream(stream);
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::notifyPendingWriteOnConnection(WriteCallback* wcb) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (connWriteCallback_ != nullptr) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_WRITE_CALLBACK);
  }
  // Assign the write callback before going into the loop so that if we close
  // the connection while we are still scheduled, the write callback will get
  // an error synchronously.
  connWriteCallback_ = wcb;
  runOnEvbAsync([](auto self) {
    if (!self->connWriteCallback_) {
      // The connection was probably closed.
      return;
    }
    auto connWritableBytes = self->maxWritableOnConn();
    if (connWritableBytes != 0) {
      auto connWriteCallback = self->connWriteCallback_;
      self->connWriteCallback_ = nullptr;
      connWriteCallback->onConnectionWriteReady(connWritableBytes);
    }
  });
  return folly::unit;
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::notifyPendingWriteOnStream(StreamId id, WriteCallback* wcb) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto qStream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
  if (!qStream->writable()) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
  }

  if (wcb == nullptr) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_WRITE_CALLBACK);
  }
  // Add the callback to the pending write callbacks so that if we are closed
  // while we are scheduled in the loop, the close will error out the callbacks.
  auto wcbEmplaceResult = pendingWriteCallbacks_.emplace(id, wcb);
  if (!wcbEmplaceResult.second) {
    if ((wcbEmplaceResult.first)->second != wcb) {
      return folly::makeUnexpected(LocalErrorCode::INVALID_WRITE_CALLBACK);
    } else {
      return folly::makeUnexpected(LocalErrorCode::CALLBACK_ALREADY_INSTALLED);
    }
  }
  runOnEvbAsync([id](auto self) {
    auto wcbIt = self->pendingWriteCallbacks_.find(id);
    if (wcbIt == self->pendingWriteCallbacks_.end()) {
      // the connection was probably closed.
      return;
    }
    auto writeCallback = wcbIt->second;
    if (!self->conn_->streamManager->streamExists(id)) {
      self->pendingWriteCallbacks_.erase(wcbIt);
      writeCallback->onStreamWriteError(
          id, std::make_pair(LocalErrorCode::STREAM_NOT_EXISTS, folly::none));
      return;
    }
    auto stream = CHECK_NOTNULL(self->conn_->streamManager->getStream(id));
    if (!stream->writable()) {
      self->pendingWriteCallbacks_.erase(wcbIt);
      writeCallback->onStreamWriteError(
          id, std::make_pair(LocalErrorCode::STREAM_NOT_EXISTS, folly::none));
      return;
    }
    auto maxCanWrite = self->maxWritableOnStream(*stream);
    if (maxCanWrite != 0) {
      self->pendingWriteCallbacks_.erase(wcbIt);
      writeCallback->onStreamWriteReady(id, maxCanWrite);
    }
  });
  return folly::unit;
}

uint64_t QuicTransportBase::maxWritableOnStream(const QuicStreamState& stream) {
  auto connWritableBytes = maxWritableOnConn();
  auto streamFlowControlBytes = getSendStreamFlowControlBytesAPI(stream);
  auto flowControlAllowedBytes =
      std::min(streamFlowControlBytes, connWritableBytes);
  return flowControlAllowedBytes;
}

uint64_t QuicTransportBase::maxWritableOnConn() {
  auto connWritableBytes = getSendConnFlowControlBytesAPI(*conn_);
  auto availableBufferSpace = bufferSpaceAvailable();
  return std::min(connWritableBytes, availableBufferSpace);
}

QuicSocket::WriteResult QuicTransportBase::writeChain(
    StreamId id,
    Buf data,
    bool eof,
    bool /*cork*/,
    DeliveryCallback* cb) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  try {
    // Check whether stream exists before calling getStream to avoid
    // creating a peer stream if it does not exist yet.
    if (!conn_->streamManager->streamExists(id)) {
      return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    auto stream = conn_->streamManager->getStream(id);
    if (!stream || !stream->writable()) {
      return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
    }
    // Register DeliveryCallback for the data + eof offset.
    if (cb) {
      auto dataLength =
          (data ? data->computeChainDataLength() : 0) + (eof ? 1 : 0);
      if (dataLength) {
        auto currentLargestWriteOffset = getLargestWriteOffsetSeen(*stream);
        registerDeliveryCallback(
            id, currentLargestWriteOffset + dataLength - 1, cb);
      }
    }
    writeDataToQuicStream(*stream, std::move(data), eof);
    updateWriteLooper(true);
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
    return folly::makeUnexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
    return folly::makeUnexpected(ex.errorCode());
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string(ex.what())));
    return folly::makeUnexpected(LocalErrorCode::INTERNAL_ERROR);
  }
  return nullptr;
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::registerDeliveryCallback(
    StreamId id,
    uint64_t offset,
    DeliveryCallback* cb) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (cb) {
    if (deliveryCallbacks_.find(id) == deliveryCallbacks_.end()) {
      deliveryCallbacks_[id].emplace_back(offset, cb);
    } else {
      // Keep DeliveryCallbacks for the same stream sorted by offsets:
      auto pos = std::upper_bound(
          deliveryCallbacks_[id].begin(),
          deliveryCallbacks_[id].end(),
          offset,
          [&](uint64_t o, const std::pair<uint64_t, DeliveryCallback*>& p) {
            return o < p.first;
          });
      deliveryCallbacks_[id].emplace(pos, offset, cb);
    }
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
    auto minOffsetToDelivery = getStreamNextOffsetToDeliver(*stream);
    if (offset < minOffsetToDelivery) {
      // This offset is already delivered
      runOnEvbAsync([id, cb, offset](auto selfObj) {
        if (selfObj->closeState_ != CloseState::OPEN) {
          // Close will error out all the delivery callbacks.
          return;
        }
        auto streamDeliveryCbIt = selfObj->deliveryCallbacks_.find(id);
        if (streamDeliveryCbIt == selfObj->deliveryCallbacks_.end()) {
          return;
        }
        auto pos = std::lower_bound(
            streamDeliveryCbIt->second.begin(),
            streamDeliveryCbIt->second.end(),
            offset,
            [&](const std::pair<uint64_t, DeliveryCallback*>& p, uint64_t o) {
              return p.first < o;
            });
        streamDeliveryCbIt->second.erase(pos);
        cb->onDeliveryAck(id, offset, selfObj->conn_->lossState.srtt);
      });
    }
  }
  return folly::unit;
}

folly::Optional<LocalErrorCode> QuicTransportBase::shutdownWrite(StreamId id) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return LocalErrorCode::INVALID_OPERATION;
  }
  return folly::none;
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
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
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
    auto stream = conn_->streamManager->getStream(id);
    if (!stream) {
      // Should not happen, due to the streamExists() check above, but might
      // as well check to keep nullability checkers happy.
      return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
    }
    // Invoke state machine
    invokeStreamSendStateMachine(
        *conn_, *stream, StreamEvents::SendReset(errorCode));
    for (auto pendingResetIt = conn_->pendingEvents.resets.begin();
         closeState_ == CloseState::OPEN &&
         pendingResetIt != conn_->pendingEvents.resets.end();
         pendingResetIt++) {
      cancelDeliveryCallbacksForStream(pendingResetIt->first);
    }
    QUIC_STATS(conn_->infoCallback, onQuicStreamReset);
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
    return folly::makeUnexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
    return folly::makeUnexpected(ex.errorCode());
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string(ex.what())));
    return folly::makeUnexpected(LocalErrorCode::INTERNAL_ERROR);
  }
  return folly::unit;
}

void QuicTransportBase::checkForClosedStream() {
  // TODO: This UNLIKELY here could be premature. This isn't *that* unlikely,
  // as we call this function in closeImpl (via cancelAllAppCallbacks).
  if (UNLIKELY(closeState_ == CloseState::CLOSED)) {
    return;
  }
  auto itr = conn_->streamManager->closedStreams().begin();
  while (itr != conn_->streamManager->closedStreams().end()) {
    // We may be in an active read cb when we close the stream
    auto readCbIt = readCallbacks_.find(*itr);
    if (readCbIt != readCallbacks_.end() &&
        readCbIt->second.readCb != nullptr && !readCbIt->second.deliveredEOM) {
      VLOG(10) << "Not closing stream=" << *itr
               << " because it has active read callback";
      ++itr;
      continue;
    }
    // We may be in the active peek cb when we close the stream
    auto peekCbIt = peekCallbacks_.find(*itr);
    if (peekCbIt != peekCallbacks_.end() &&
        peekCbIt->second.peekCb != nullptr) {
      VLOG(10) << "Not closing stream=" << *itr
               << " because it has active peek callback";
      ++itr;
      continue;
    }
    // We might be in the process of delivering all the delivery callbacks for
    // the stream when we receive close stream.
    auto deliveryCbCount = deliveryCallbacks_.count(*itr);
    if (deliveryCbCount > 0) {
      VLOG(10) << "Not closing stream=" << *itr
               << " because it is waiting for the delivery callback";
      ++itr;
      continue;
    }

    VLOG(10) << "Closing stream=" << *itr;
    FOLLY_MAYBE_UNUSED auto stream = conn_->streamManager->findStream(*itr);
    QUIC_TRACE(
        holb_time,
        *conn_,
        stream->id,
        stream->totalHolbTime.count(),
        stream->holbCount);
    conn_->streamManager->removeClosedStream(*itr);
    readCallbacks_.erase(*itr);
    peekCallbacks_.erase(*itr);
    itr = conn_->streamManager->closedStreams().erase(itr);
  } // while

  if (closeState_ == CloseState::GRACEFUL_CLOSING &&
      conn_->streamManager->streamCount() == 0) {
    closeImpl(folly::none);
  }
}

void QuicTransportBase::sendPing(
    PingCallback* /*callback*/,
    std::chrono::milliseconds /*pingTimeout*/) {}

void QuicTransportBase::lossTimeoutExpired() noexcept {
  CHECK_NE(closeState_, CloseState::CLOSED);
  // onLossDetectionAlarm will set packetToSend in pending events
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  try {
    onLossDetectionAlarm(*conn_, markPacketLoss);
    // TODO: remove this trace when Pacing is ready to land
    QUIC_TRACE(fst_trace, *conn_, "LossTimeoutExpired");
    pacedWriteDataToSocket(false);
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << "  " << ex.what() << " " << *this;
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string(ex.what())));
  }
}

void QuicTransportBase::ackTimeoutExpired() noexcept {
  CHECK_NE(closeState_, CloseState::CLOSED);
  VLOG(10) << __func__ << " " << *this;
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  updateAckStateOnAckTimeout(*conn_);
  pacedWriteDataToSocket(false);
}

void QuicTransportBase::pathValidationTimeoutExpired() noexcept {
  CHECK(conn_->outstandingPathValidation);

  conn_->pendingEvents.schedulePathValidationTimeout = false;
  conn_->outstandingPathValidation = folly::none;

  // TODO junqiw probing is not supported, so pathValidation==connMigration
  // We decide to close conn when pathValidation to migrated path fails.
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  closeImpl(std::make_pair(
      QuicErrorCode(TransportErrorCode::INVALID_MIGRATION),
      std::string("Path validation timed out")));
}

void QuicTransportBase::idleTimeoutExpired(bool drain) noexcept {
  VLOG(4) << __func__ << " " << *this;
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  // idle timeout is expired, just close the connection and drain or
  // send connection close immediately depending on 'drain'
  DCHECK_NE(closeState_, CloseState::CLOSED);
  closeImpl(
      std::make_pair(
          QuicErrorCode(LocalErrorCode::IDLE_TIMEOUT),
          toString(LocalErrorCode::IDLE_TIMEOUT)),
      drain /* drainConnection */,
      !drain /* sendCloseImmediately */);
}

void QuicTransportBase::scheduleLossTimeout(std::chrono::milliseconds timeout) {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  auto& wheelTimer = getEventBase()->timer();
  timeout = timeMax(timeout, wheelTimer.getTickInterval());
  wheelTimer.scheduleTimeout(&lossTimeout_, timeout);
}

void QuicTransportBase::scheduleAckTimeout() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  if (conn_->pendingEvents.scheduleAckTimeout) {
    if (!ackTimeout_.isScheduled()) {
      auto factoredRtt = std::chrono::duration_cast<std::chrono::microseconds>(
          kAckTimerFactor * conn_->lossState.srtt);
      auto timeout =
          timeMax(kMinAckTimeout, timeMin(kMaxAckTimeout, factoredRtt));
      auto timeoutMs =
          std::chrono::duration_cast<std::chrono::milliseconds>(timeout);
      VLOG(10) << __func__ << " timeout=" << timeoutMs.count() << "ms"
               << " factoredRtt=" << factoredRtt.count() << "us"
               << " " << *this;
      getEventBase()->timer().scheduleTimeout(&ackTimeout_, timeoutMs);
    }
  } else {
    if (ackTimeout_.isScheduled()) {
      VLOG(10) << __func__ << " cancel timeout " << *this;
      ackTimeout_.cancelTimeout();
    }
  }
}

void QuicTransportBase::schedulePathValidationTimeout() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  if (!conn_->pendingEvents.schedulePathValidationTimeout) {
    if (pathValidationTimeout_.isScheduled()) {
      VLOG(10) << __func__ << " cancel timeout " << *this;
      // This means path validation succeeded, and we should have updated to
      // correct state
      pathValidationTimeout_.cancelTimeout();
    }
  } else if (!pathValidationTimeout_.isScheduled()) {
    auto pto = conn_->lossState.srtt +
        std::max(4 * conn_->lossState.rttvar, kGranularity) +
        conn_->lossState.maxAckDelay;

    auto validationTimeout = std::max(3 * pto, 6 * kDefaultInitialRtt);
    auto timeoutMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        validationTimeout);
    VLOG(10) << __func__ << " timeout=" << timeoutMs.count() << "ms " << *this;
    getEventBase()->timer().scheduleTimeout(&pathValidationTimeout_, timeoutMs);
  }
}

void QuicTransportBase::cancelLossTimeout() {
  if (lossTimeout_.isScheduled()) {
    lossTimeout_.cancelTimeout();
  }
}

bool QuicTransportBase::isLossTimeoutScheduled() const {
  return lossTimeout_.isScheduled();
}

void QuicTransportBase::setSupportedVersions(
    const std::vector<QuicVersion>& versions) {
  conn_->originalVersion = versions.at(0);
  conn_->supportedVersions = versions;
}

void QuicTransportBase::setConnectionCallback(ConnectionCallback* callback) {
  connCallback_ = CHECK_NOTNULL(callback);
}

void QuicTransportBase::setEarlyDataAppParamsFunctions(
    folly::Function<bool(const folly::Optional<std::string>&, const Buf&)>
        validator,
    folly::Function<Buf()> getter) {
  earlyDataAppParamsValidator_ = std::move(validator);
  earlyDataAppParamsGetter_ = std::move(getter);
}

void QuicTransportBase::cancelAllAppCallbacks(
    std::pair<QuicErrorCode, std::string> err) noexcept {
  SCOPE_EXIT {
    checkForClosedStream();
    updateReadLooper();
    updatePeekLooper();
    updateWriteLooper(true);
  };
  conn_->streamManager->clearActionable();
  // Move the whole delivery callback map:
  auto deliveryCallbacks = std::move(deliveryCallbacks_);
  // Invoke onCanceled on the copy
  cancelDeliveryCallbacks(deliveryCallbacks);
  // TODO: this will become simpler when we change the underlying data
  // structure of read callbacks.
  // TODO: this approach will make the app unable to setReadCallback to
  // nullptr during the loop. Need to fix that.
  // TODO: setReadCallback to nullptr closes the stream, so the app
  // may just do that...
  auto readCallbacksCopy = readCallbacks_;
  for (auto& cb : readCallbacksCopy) {
    readCallbacks_.erase(cb.first);
    if (cb.second.readCb) {
      cb.second.readCb->readError(
          cb.first, std::make_pair(err.first, folly::StringPiece(err.second)));
    }
  }
  VLOG(4) << "Clearing " << peekCallbacks_.size() << " peek callbacks";
  peekCallbacks_.clear();
  dataExpiredCallbacks_.clear();
  dataRejectedCallbacks_.clear();

  if (connWriteCallback_) {
    auto connWriteCallback = connWriteCallback_;
    connWriteCallback_ = nullptr;
    connWriteCallback->onConnectionWriteError(
        std::make_pair(err.first, folly::StringPiece(err.second)));
  }
  auto it = pendingWriteCallbacks_.begin();
  while (it != pendingWriteCallbacks_.end()) {
    auto wcb = it->second;
    wcb->onStreamWriteError(
        it->first, std::make_pair(err.first, folly::StringPiece(err.second)));
    it = pendingWriteCallbacks_.erase(it);
  }
}

void QuicTransportBase::writeSocketData() {
  if (socket_) {
    auto packetsBefore = conn_->outstandingPackets.size();
    writeData();
    if (closeState_ != CloseState::CLOSED) {
      setLossDetectionAlarm(*conn_, *this);
      auto packetsAfter = conn_->outstandingPackets.size();
      bool packetWritten = (packetsAfter > packetsBefore);
      if (packetWritten) {
        conn_->debugState.currentEmptyLoopCount = 0;
      } else if (
          conn_->debugState.needsWriteLoopDetect &&
          conn_->loopDetectorCallback) {
        // TODO: Currently we will to get some stats first. Then we may filter
        // out some errors here. For example, socket fail to write might be a
        // legit case to filter out.
        conn_->loopDetectorCallback->onSuspiciousLoops(
            ++conn_->debugState.currentEmptyLoopCount,
            conn_->debugState.writeDataReason,
            conn_->debugState.noWriteReason,
            conn_->debugState.schedulerName);
      }
      // If we sent a new packet and the new packet was either the first
      // packet
      // after quiescence or after receiving a new packet.
      if (packetsAfter > packetsBefore &&
          (packetsBefore == 0 || conn_->receivedNewPacketBeforeWrite)) {
        // Reset the idle timer because we sent some data.
        setIdleTimer();
        conn_->receivedNewPacketBeforeWrite = false;
      }
      // Check if we are app-limited after finish this round of sending
      auto currentSendBufLen = conn_->flowControlState.sumCurStreamBufferLen;
      auto lossBufferEmpty = !conn_->streamManager->hasLoss() &&
          conn_->cryptoState->initialStream.lossBuffer.empty() &&
          conn_->cryptoState->handshakeStream.lossBuffer.empty() &&
          conn_->cryptoState->oneRttStream.lossBuffer.empty();
      if (conn_->congestionController &&
          currentSendBufLen < conn_->udpSendPacketLen && lossBufferEmpty &&
          conn_->congestionController->getWritableBytes()) {
        conn_->congestionController->setAppLimited();
      }
    }
  }
  // Writing data could write out an ack which could cause us to cancel
  // the ack timer. But we need to call scheduleAckTimeout() for it to take
  // effect.
  scheduleAckTimeout();
  schedulePathValidationTimeout();
  updateWriteLooper(false);
}

void QuicTransportBase::writeSocketDataAndCatch() {
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  try {
    writeSocketData();
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << ex.what() << " " << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << ex.what() << " " << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " error=" << ex.what() << " " << *this;
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string(ex.what())));
  }
}

void QuicTransportBase::cancelDeliveryCallbacks(
    StreamId id,
    const std::deque<std::pair<uint64_t, QuicSocket::DeliveryCallback*>>&
        deliveryCallbacks) {
  for (auto iter = deliveryCallbacks.begin(); iter != deliveryCallbacks.end();
       iter++) {
    auto currentDeliveryCallbackOffset = iter->first;
    auto deliveryCallback = iter->second;
    deliveryCallback->onCanceled(id, currentDeliveryCallbackOffset);
  }
}

void QuicTransportBase::cancelDeliveryCallbacks(
    const std::unordered_map<
        StreamId,
        std::deque<std::pair<uint64_t, QuicSocket::DeliveryCallback*>>>&
        deliveryCallbacks) {
  for (auto iter = deliveryCallbacks.begin(); iter != deliveryCallbacks.end();
       iter++) {
    cancelDeliveryCallbacks(iter->first, iter->second);
  }
}

void QuicTransportBase::setTransportSettings(
    TransportSettings transportSettings) {
  conn_->transportSettings = std::move(transportSettings);
  setCongestionControl(transportSettings.defaultCongestionController);
}

const TransportSettings& QuicTransportBase::getTransportSettings() const {
  return conn_->transportSettings;
}

bool QuicTransportBase::isPartiallyReliableTransport() const {
  return conn_->partialReliabilityEnabled;
}

void QuicTransportBase::setCongestionControl(CongestionControlType type) {
  DCHECK(conn_);
  if (!conn_->congestionController ||
      type != conn_->congestionController->type()) {
    CHECK(ccFactory_);
    conn_->congestionController =
        ccFactory_->makeCongestionController(*conn_, type);
  }
}

bool QuicTransportBase::isDetachable() {
  // only the client is detachable.
  return conn_->nodeType == QuicNodeType::Client;
}

void QuicTransportBase::attachEventBase(folly::EventBase* evb) {
  VLOG(10) << __func__ << " " << *this;
  DCHECK(!getEventBase());
  DCHECK(evb && evb->isInEventBaseThread());
  evb_ = evb;
  if (socket_) {
    socket_->attachEventBase(evb);
  }

  scheduleAckTimeout();
  schedulePathValidationTimeout();
  setIdleTimer();

  readLooper_->attachEventBase(evb);
  peekLooper_->attachEventBase(evb);
  writeLooper_->attachEventBase(evb);
  updateReadLooper();
  updatePeekLooper();
  updateWriteLooper(false);
}

void QuicTransportBase::detachEventBase() {
  VLOG(10) << __func__ << " " << *this;
  DCHECK(getEventBase() && getEventBase()->isInEventBaseThread());
  if (socket_) {
    socket_->detachEventBase();
  }
  connWriteCallback_ = nullptr;
  pendingWriteCallbacks_.clear();
  lossTimeout_.cancelTimeout();
  ackTimeout_.cancelTimeout();
  pathValidationTimeout_.cancelTimeout();
  idleTimeout_.cancelTimeout();
  drainTimeout_.cancelTimeout();
  readLooper_->detachEventBase();
  peekLooper_->detachEventBase();
  writeLooper_->detachEventBase();
  evb_ = nullptr;
}

folly::Optional<LocalErrorCode> QuicTransportBase::setControlStream(
    StreamId id) {
  if (!conn_->streamManager->streamExists(id)) {
    return LocalErrorCode::STREAM_NOT_EXISTS;
  }
  auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
  conn_->streamManager->setStreamAsControl(*stream);
  return folly::none;
}

void QuicTransportBase::runOnEvbAsync(
    folly::Function<void(std::shared_ptr<QuicTransportBase>)> func) {
  auto evb = getEventBase();
  evb->runInLoop(
      [self = sharedGuard(), func = std::move(func), evb]() mutable {
        if (self->getEventBase() != evb) {
          // The eventbase changed between scheduling the loop and invoking the
          // callback, ignore this
          return;
        }
        func(std::move(self));
      },
      true);
}

void QuicTransportBase::pacedWriteDataToSocket(bool /* fromTimer */) {
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();

  if (!isConnectionPaced(*conn_)) {
    // Not paced and connection is still open, normal write. Even if pacing is
    // previously enabled and then gets disabled, and we are here due to a
    // timeout, we should do a normal write to flush out the residue from pacing
    // write.
    writeSocketDataAndCatch();
    return;
  }

  // We are in the middle of a pacing interval. Leave it be.
  if (writeLooper_->isScheduled()) {
    // The next burst is already scheduled. Since the burst size doesn't depend
    // on much data we currently have in buffer at all, no need to change
    // anything.
    return;
  }

  // Do a burst write before waiting for an interval. This will also call
  // updateWriteLooper, but inside FunctionLooper we will ignore that.
  writeSocketDataAndCatch();
}

folly::Expected<QuicSocket::StreamTransportInfo, LocalErrorCode>
QuicTransportBase::getStreamTransportInfo(StreamId id) const {
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = conn_->streamManager->getStream(id);
  if (!stream) {
    // This is not really possible since this should be covered
    // by the stream existence check, but might as well check this.
    return folly::makeUnexpected(LocalErrorCode::STREAM_CLOSED);
  }
  return StreamTransportInfo{
      .totalHeadOfLineBlockedTime = stream->totalHolbTime,
      .holbCount = stream->holbCount,
      .isHolb = bool(stream->lastHolbTime)};
}

void QuicTransportBase::describe(std::ostream& os) const {
  CHECK(conn_);
  os << *conn_;
}

std::ostream& operator<<(std::ostream& os, const QuicTransportBase& qt) {
  qt.describe(os);
  return os;
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
  return folly::variant_match(
      error,
      [this, id](quic::ApplicationErrorCode ec) { return resetStream(id, ec); },
      [](quic::LocalErrorCode) {
        return folly::Expected<folly::Unit, LocalErrorCode>(folly::unit);
      },
      [](quic::TransportErrorCode) {
        return folly::Expected<folly::Unit, LocalErrorCode>(folly::unit);
      });
}

} // namespace quic
