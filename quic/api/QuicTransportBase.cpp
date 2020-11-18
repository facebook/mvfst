/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/QuicTransportBase.h>

#include <folly/Chrono.h>
#include <folly/ScopeGuard.h>
#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/TimeUtil.h>
#include <quic/congestion_control/Pacer.h>
#include <quic/congestion_control/TokenlessPacer.h>
#include <quic/d6d/QuicD6DStateFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/stream/StreamSendHandlers.h>

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
      pingTimeout_(this),
      d6dProbeTimeout_(this),
      d6dRaiseTimeout_(this),
      d6dTxTimeout_(this),
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
      return conn_->pacer->getTimeUntilNextWrite();
    }
    return 0us;
  });
}

void QuicTransportBase::setPacingTimer(
    TimerHighRes::SharedPtr pacingTimer) noexcept {
  if (pacingTimer) {
    writeLooper_->setPacingTimer(std::move(pacingTimer));
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

folly::Optional<ConnectionId> QuicTransportBase::getClientConnectionId() const {
  return conn_->clientConnectionId;
}

folly::Optional<ConnectionId> QuicTransportBase::getServerConnectionId() const {
  return conn_->serverConnectionId;
}

folly::Optional<ConnectionId>
QuicTransportBase::getClientChosenDestConnectionId() const {
  return conn_->clientChosenDestConnectionId;
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
  for (const auto& cb : lifecycleObservers_) {
    cb->destroy(this);
  }
}

bool QuicTransportBase::good() const {
  return hasWriteCipher() && !error();
}

bool QuicTransportBase::replaySafe() const {
  return (conn_->oneRttWriteCipher != nullptr);
}

bool QuicTransportBase::error() const {
  return conn_->localConnectionError.has_value();
}

void QuicTransportBase::close(
    folly::Optional<std::pair<QuicErrorCode, std::string>> errorCode) {
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  // The caller probably doesn't need a conn callback any more because they
  // explicitly called close.
  connCallback_ = nullptr;

  // If we were called with no error code, ensure that we are going to write
  // an application close, so the peer knows it didn't come from the transport.
  if (!errorCode) {
    errorCode = std::make_pair(
        GenericApplicationErrorCode::NO_ERROR,
        toString(GenericApplicationErrorCode::NO_ERROR));
  }
  closeImpl(std::move(errorCode), true);
  conn_->logger.reset();
}

void QuicTransportBase::closeNow(
    folly::Optional<std::pair<QuicErrorCode, std::string>> errorCode) {
  DCHECK(getEventBase() && getEventBase()->isInEventBaseThread());
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  VLOG(4) << __func__ << " " << *this;
  if (!errorCode) {
    errorCode = std::make_pair(
        GenericApplicationErrorCode::NO_ERROR,
        toString(GenericApplicationErrorCode::NO_ERROR));
  }
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
    conn_->qLogger->addConnectionClose(kNoError, kGracefulExit, true, false);
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

// TODO: t64691045 change the closeImpl API to include both the sanitized and
// unsanited error message, remove exceptionCloseWhat_.
void QuicTransportBase::closeImpl(
    folly::Optional<std::pair<QuicErrorCode, std::string>> errorCode,
    bool drainConnection,
    bool sendCloseImmediately) {
  for (const auto& cb : lifecycleObservers_) {
    cb->close(this, errorCode);
  }
  for (const auto& cb : conn_->instrumentationObservers_) {
    cb->observerDetach(this);
  }
  conn_->instrumentationObservers_.clear();

  if (closeState_ == CloseState::CLOSED) {
    return;
  }

  drainConnection = drainConnection & conn_->transportSettings.shouldDrain;

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
  // cancelCode is used for communicating error message to local app layer.
  // errorCode will be used for localConnectionError, and sent in close frames.
  // It's safe to include the unsanitized error message in cancelCode
  if (exceptionCloseWhat_) {
    cancelCode.second = exceptionCloseWhat_.value();
  }

  bool isReset = false;
  bool isAbandon = false;
  bool isInvalidMigration = false;
  LocalErrorCode* localError = cancelCode.first.asLocalErrorCode();
  TransportErrorCode* transportError = cancelCode.first.asTransportErrorCode();
  if (localError) {
    isReset = *localError == LocalErrorCode::CONNECTION_RESET;
    isAbandon = *localError == LocalErrorCode::CONNECTION_ABANDONED;
  }
  isInvalidMigration = transportError &&
      *transportError == TransportErrorCode::INVALID_MIGRATION;
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
        kNoError,
        ", Peer: isReset: ",
        isReset,
        ", Peer: isAbandon: ",
        isAbandon);
    if (conn_->qLogger) {
      conn_->qLogger->addConnectionClose(
          kNoError, reason, drainConnection, sendCloseImmediately);
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
  if (pingTimeout_.isScheduled()) {
    pingTimeout_.cancelTimeout();
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
      conn_->statsCallback,
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
    bool noError = false;
    switch (cancelCode.first.type()) {
      case QuicErrorCode::Type::LocalErrorCode_E: {
        LocalErrorCode localErrorCode = *cancelCode.first.asLocalErrorCode();
        noError = localErrorCode == LocalErrorCode::NO_ERROR ||
            localErrorCode == LocalErrorCode::IDLE_TIMEOUT;
        break;
      }
      case QuicErrorCode::Type::TransportErrorCode_E: {
        TransportErrorCode transportErrorCode =
            *cancelCode.first.asTransportErrorCode();
        noError = transportErrorCode == TransportErrorCode::NO_ERROR;
        break;
      }
      case QuicErrorCode::Type::ApplicationErrorCode_E:
        auto appErrorCode = *cancelCode.first.asApplicationErrorCode();
        noError = appErrorCode == GenericApplicationErrorCode::NO_ERROR;
    }
    if (noError) {
      connCallback_->onConnectionEnd();
    } else {
      connCallback_->onConnectionError(
          std::make_pair(cancelCode.first, cancelCode.second.str()));
    }
  }

  // can't invoke connection callbacks any more.
  connCallback_ = nullptr;

  // Don't need outstanding packets.
  conn_->outstandings.packets.clear();
  conn_->outstandings.initialPacketsCount = 0;
  conn_->outstandings.handshakePacketsCount = 0;
  conn_->outstandings.clonedPacketsCount = 0;

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
  drainConnection =
      drainConnection && !isReset && !isAbandon && !isInvalidMigration;
  if (drainConnection) {
    // We ever drain once, and the object ever gets created once.
    DCHECK(!drainTimeout_.isScheduled());
    getEventBase()->timer().scheduleTimeout(
        &drainTimeout_,
        folly::chrono::ceil<std::chrono::milliseconds>(
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
  CongestionControlType congestionControlType = CongestionControlType::None;
  uint64_t writableBytes = std::numeric_limits<uint64_t>::max();
  uint64_t congestionWindow = std::numeric_limits<uint64_t>::max();
  uint64_t burstSize = 0;
  std::chrono::microseconds pacingInterval = 0ms;
  if (conn_->congestionController) {
    congestionControlType = conn_->congestionController->type();
    writableBytes = conn_->congestionController->getWritableBytes();
    congestionWindow = conn_->congestionController->getCongestionWindow();
    if (isConnectionPaced(*conn_)) {
      burstSize = conn_->pacer->getCachedWriteBatchSize();
      pacingInterval = conn_->pacer->getTimeUntilNextWrite();
    }
  }
  TransportInfo transportInfo;
  transportInfo.srtt = conn_->lossState.srtt;
  transportInfo.rttvar = conn_->lossState.rttvar;
  transportInfo.lrtt = conn_->lossState.lrtt;
  transportInfo.mrtt = conn_->lossState.mrtt;
  transportInfo.mss = conn_->udpSendPacketLen;
  transportInfo.congestionControlType = congestionControlType;
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

uint64_t QuicTransportBase::getConnectionBufferAvailable() const {
  return bufferSpaceAvailable();
}

uint64_t QuicTransportBase::bufferSpaceAvailable() const {
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
  auto stream = conn_->streamManager->getStream(id);
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
    ReadCallback* cb,
    folly::Optional<ApplicationErrorCode> err) {
  if (isSendingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  return setReadCallbackInternal(id, cb, err);
}

void QuicTransportBase::unsetAllReadCallbacks() {
  for (auto& streamCallbackPair : readCallbacks_) {
    setReadCallbackInternal(
        streamCallbackPair.first,
        nullptr,
        GenericApplicationErrorCode::NO_ERROR);
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
    ReadCallback* cb,
    folly::Optional<ApplicationErrorCode> err) noexcept {
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
    if (readCb == nullptr && err) {
      return stopSending(id, err.value());
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
  // Need a copy since the set can change during callbacks.
  std::vector<StreamId> readableStreamsCopy;
  const auto& readableStreams = self->conn_->streamManager->readableStreams();
  readableStreamsCopy.reserve(readableStreams.size());
  std::copy(
      readableStreams.begin(),
      readableStreams.end(),
      std::back_inserter(readableStreamsCopy));
  if (self->conn_->transportSettings.orderedReadCallbacks) {
    std::sort(readableStreamsCopy.begin(), readableStreamsCopy.end());
  }
  for (StreamId streamId : readableStreamsCopy) {
    auto callback = self->readCallbacks_.find(streamId);
    if (callback == self->readCallbacks_.end()) {
      self->conn_->streamManager->readableStreams().erase(streamId);
      continue;
    }
    auto readCb = callback->second.readCb;
    auto stream = conn_->streamManager->getStream(streamId);
    if (readCb && stream->streamReadError) {
      self->conn_->streamManager->readableStreams().erase(streamId);
      readCallbacks_.erase(callback);
      // if there is an error on the stream - it's not readable anymore, so
      // we cannot peek into it as well.
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
  std::vector<StreamId> peekableStreamsCopy;
  const auto& peekableStreams = self->conn_->streamManager->peekableStreams();
  peekableStreamsCopy.reserve(peekableStreams.size());
  std::copy(
      peekableStreams.begin(),
      peekableStreams.end(),
      std::back_inserter(peekableStreamsCopy));
  VLOG(10) << __func__
           << " peekableListCopy.size()=" << peekableStreamsCopy.size();
  for (StreamId streamId : peekableStreamsCopy) {
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
    auto stream = conn_->streamManager->getStream(streamId);
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
    auto stream = conn_->streamManager->getStream(streamId);

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
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = conn_->streamManager->getStream(id);
  auto newOffset = advanceMinimumRetransmittableOffset(stream, offset);

  // Cancel byte event callbacks that are set for any offset below newOffset.
  if (newOffset) {
    cancelByteEventCallbacksForStream(id, *newOffset);
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
    auto stream = conn_->streamManager->getStream(streamId);

    // Invoke any delivery callbacks that are set for any offset below newly set
    // minimumRetransmittableOffset.
    if (!stream->streamReadError) {
      cancelByteEventCallbacksForStream(
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

void QuicTransportBase::invokeStreamsAvailableCallbacks() {
  if (conn_->streamManager->consumeMaxLocalBidirectionalStreamIdIncreased()) {
    // check in case new streams were created in preceding callbacks
    // and max is already reached
    auto numStreams = getNumOpenableBidirectionalStreams();
    if (numStreams > 0) {
      connCallback_->onBidirectionalStreamsAvailable(numStreams);
    }
  }
  if (conn_->streamManager->consumeMaxLocalUnidirectionalStreamIdIncreased()) {
    // check in case new streams were created in preceding callbacks
    // and max is already reached
    auto numStreams = getNumOpenableUnidirectionalStreams();
    if (numStreams > 0) {
      connCallback_->onUnidirectionalStreamsAvailable(numStreams);
    }
  }
}

folly::Expected<folly::Optional<uint64_t>, LocalErrorCode>
QuicTransportBase::sendDataRejected(StreamId id, uint64_t offset) {
  if (!conn_->partialReliabilityEnabled) {
    return folly::makeUnexpected(LocalErrorCode::APP_ERROR);
  }
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = conn_->streamManager->getStream(id);
  auto newOffset = advanceCurrentReceiveOffset(stream, offset);
  updateWriteLooper(true);
  return folly::makeExpected<LocalErrorCode>(newOffset);
}

void QuicTransportBase::updatePeekLooper() {
  if (peekCallbacks_.empty() || closeState_ != CloseState::OPEN) {
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
    if (conn_->loopDetectorCallback) {
      conn_->writeDebugState.needsWriteLoopDetect =
          (conn_->loopDetectorCallback != nullptr);
    }
  } else {
    VLOG(10) << nodeToString(conn_->nodeType) << " stopping write looper "
             << *this;
    writeLooper_->stop();
    if (conn_->loopDetectorCallback) {
      conn_->writeDebugState.needsWriteLoopDetect = false;
      conn_->writeDebugState.currentEmptyLoopCount = 0;
    }
  }
  if (conn_->loopDetectorCallback) {
    conn_->writeDebugState.writeDataReason = writeDataReason;
  }
}

void QuicTransportBase::cancelDeliveryCallbacksForStream(StreamId id) {
  cancelByteEventCallbacksForStream(ByteEvent::Type::ACK, id);
}

void QuicTransportBase::cancelDeliveryCallbacksForStream(
    StreamId id,
    uint64_t offset) {
  cancelByteEventCallbacksForStream(ByteEvent::Type::ACK, id, offset);
}

void QuicTransportBase::cancelByteEventCallbacksForStream(
    const StreamId id,
    const folly::Optional<uint64_t>& offset) {
  invokeForEachByteEventType(([this, id, &offset](const ByteEvent::Type type) {
    cancelByteEventCallbacksForStream(type, id, offset);
  }));
}

void QuicTransportBase::cancelByteEventCallbacksForStream(
    const ByteEvent::Type type,
    const StreamId id,
    const folly::Optional<uint64_t>& offset) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return;
  }

  auto& byteEventMap = getByteEventMap(type);
  auto byteEventMapIt = byteEventMap.find(id);
  if (byteEventMapIt == byteEventMap.end()) {
    switch (type) {
      case ByteEvent::Type::ACK:
        conn_->streamManager->removeDeliverable(id);
        break;
      case ByteEvent::Type::TX:
        conn_->streamManager->removeTx(id);
        break;
    }
    return;
  }
  auto& streamByteEvents = byteEventMapIt->second;

  // Callbacks are kept sorted by offset, so we can just walk the queue and
  // invoke those with offset below provided offset.
  while (!streamByteEvents.empty()) {
    // decomposition not supported for xplat
    const auto cbOffset = streamByteEvents.front().offset;
    const auto callback = streamByteEvents.front().callback;
    if (!offset.has_value() || cbOffset < *offset) {
      streamByteEvents.pop_front();
      ByteEventCancellation cancellation = {};
      cancellation.id = id;
      cancellation.offset = cbOffset;
      cancellation.type = type;
      callback->onByteEventCanceled(cancellation);
      if (closeState_ != CloseState::OPEN) {
        // socket got closed - we can't use streamByteEvents anymore,
        // closeImpl should take care of cleaning up any remaining callbacks
        return;
      }
    } else {
      // Only larger or equal offsets left, exit the loop.
      break;
    }
  }

  // Clean up state for this stream if no callbacks left to invoke.
  if (streamByteEvents.empty()) {
    switch (type) {
      case ByteEvent::Type::ACK:
        conn_->streamManager->removeDeliverable(id);
        break;
      case ByteEvent::Type::TX:
        conn_->streamManager->removeTx(id);
        break;
    }
    byteEventMap.erase(byteEventMapIt);
  }
}

void QuicTransportBase::cancelAllByteEventCallbacks() {
  invokeForEachByteEventType(
      ([this](const ByteEvent::Type type) { cancelByteEventCallbacks(type); }));
}

void QuicTransportBase::cancelByteEventCallbacks(const ByteEvent::Type type) {
  ByteEventMap byteEventMap = std::move(getByteEventMap(type));
  for (const auto& byteEventMapIt : byteEventMap) {
    const auto streamId = byteEventMapIt.first;
    const auto callbackMap = byteEventMapIt.second;
    for (const auto& callbackMapIt : callbackMap) {
      const auto offset = callbackMapIt.offset;
      const auto callback = callbackMapIt.callback;
      ByteEventCancellation cancellation = {};
      cancellation.id = streamId;
      cancellation.offset = offset;
      cancellation.type = type;
      callback->onByteEventCanceled(cancellation);
    }
  }
}

size_t QuicTransportBase::getNumByteEventCallbacksForStream(
    const StreamId id) const {
  size_t total = 0;
  invokeForEachByteEventTypeConst(
      ([this, id, &total](const ByteEvent::Type type) {
        total += getNumByteEventCallbacksForStream(type, id);
      }));
  return total;
}

size_t QuicTransportBase::getNumByteEventCallbacksForStream(
    const ByteEvent::Type type,
    const StreamId id) const {
  const auto& byteEventMap = getByteEventMapConst(type);
  const auto byteEventMapIt = byteEventMap.find(id);
  if (byteEventMapIt == byteEventMap.end()) {
    return 0;
  }
  const auto& streamByteEvents = byteEventMapIt->second;
  return streamByteEvents.size();
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
    updateReadLooper();
    updatePeekLooper(); // read can affect "peek" API
    updateWriteLooper(true);
  };
  try {
    if (!conn_->streamManager->streamExists(id)) {
      return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    auto stream = conn_->streamManager->getStream(id);
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
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()), std::string("read() error")));
    return folly::makeUnexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()), std::string("read() error")));
    return folly::makeUnexpected(ex.errorCode());
  } catch (const std::exception& ex) {
    VLOG(4) << "read()  error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("read() error")));
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
    updatePeekLooper();
    updateWriteLooper(true);
  };

  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = conn_->streamManager->getStream(id);

  if (stream->streamReadError) {
    switch (stream->streamReadError->type()) {
      case QuicErrorCode::Type::LocalErrorCode_E:
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
  auto stream = conn_->streamManager->getStream(id);
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
    readOffset = stream->currentReadOffset;
    if (stream->currentReadOffset != offset) {
      return folly::makeUnexpected(
          ConsumeError{LocalErrorCode::INTERNAL_ERROR, readOffset});
    }

    if (stream->streamReadError) {
      switch (stream->streamReadError->type()) {
        case QuicErrorCode::Type::LocalErrorCode_E:
          return folly::makeUnexpected(ConsumeError{
              *stream->streamReadError->asLocalErrorCode(), folly::none});
        default:
          return folly::makeUnexpected(
              ConsumeError{LocalErrorCode::INTERNAL_ERROR, folly::none});
      }
    }

    consumeDataFromQuicStream(*stream, amount);
    return folly::makeExpected<ConsumeError>(folly::Unit());
  } catch (const QuicTransportException& ex) {
    VLOG(4) << "consume() error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()), std::string("consume() error")));
    return folly::makeUnexpected(
        ConsumeError{LocalErrorCode::TRANSPORT_ERROR, readOffset});
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()), std::string("consume() error")));
    return folly::makeUnexpected(ConsumeError{ex.errorCode(), readOffset});
  } catch (const std::exception& ex) {
    VLOG(4) << "consume() error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("consume() error")));
    return folly::makeUnexpected(
        ConsumeError{LocalErrorCode::INTERNAL_ERROR, readOffset});
  }
}

void QuicTransportBase::handlePingCallback() {
  if (!conn_->pendingEvents.cancelPingTimeout) {
    return; // nothing to cancel
  }
  if (!pingTimeout_.isScheduled()) {
    // set cancelpingTimeOut to false, delayed acks
    conn_->pendingEvents.cancelPingTimeout = false;
    return; // nothing to do, as timeout has already fired
  }
  pingTimeout_.cancelTimeout();
  if (pingCallback_ != nullptr) {
    runOnEvbAsync([](auto self) { self->pingCallback_->pingAcknowledged(); });
  }
  conn_->pendingEvents.cancelPingTimeout = false;
}

void QuicTransportBase::processCallbacksAfterWriteData() {
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  auto txStreamId = conn_->streamManager->popTx();
  while (txStreamId.has_value()) {
    auto streamId = *txStreamId;
    auto stream = conn_->streamManager->getStream(streamId);
    auto largestOffsetTxed = getLargestWriteOffsetTxed(*stream);
    // if it's in the set of streams with TX, we should have a valid offset
    CHECK(largestOffsetTxed.has_value());

    // lambda to help get the next callback to call for this stream
    auto getNextTxCallbackForStreamAndCleanup =
        [this, &largestOffsetTxed](
            const auto& streamId) -> folly::Optional<ByteEventDetail> {
      auto txCallbacksForStreamIt = txCallbacks_.find(streamId);
      if (txCallbacksForStreamIt == txCallbacks_.end() ||
          txCallbacksForStreamIt->second.empty()) {
        return folly::none;
      }

      auto& txCallbacksForStream = txCallbacksForStreamIt->second;
      if (txCallbacksForStream.front().offset > *largestOffsetTxed) {
        return folly::none;
      }

      // extract the callback, pop from the queue, then check for cleanup
      auto result = txCallbacksForStream.front();
      txCallbacksForStream.pop_front();
      if (txCallbacksForStream.empty()) {
        txCallbacks_.erase(txCallbacksForStreamIt);
      }
      return result;
    };

    folly::Optional<ByteEventDetail> nextOffsetAndCallback;
    while (
        (nextOffsetAndCallback =
             getNextTxCallbackForStreamAndCleanup(streamId))) {
      ByteEvent byteEvent = {};
      byteEvent.id = streamId;
      byteEvent.offset = nextOffsetAndCallback->offset;
      byteEvent.type = ByteEvent::Type::TX;
      nextOffsetAndCallback->callback->onByteEvent(byteEvent);

      // connection may be closed by callback
      if (closeState_ != CloseState::OPEN) {
        return;
      }
    }

    // pop the next stream
    txStreamId = conn_->streamManager->popTx();
  }
}

void QuicTransportBase::handleKnobCallbacks() {
  for (auto& knobFrame : conn_->pendingEvents.knobs) {
    if (knobFrame.knobSpace != kDefaultQuicTransportKnobSpace) {
      connCallback_->onKnob(
          knobFrame.knobSpace, knobFrame.id, std::move(knobFrame.blob));
    } else {
      // KnobId is ignored
      onTransportKnobs(std::move(knobFrame.blob));
    }
  }
  conn_->pendingEvents.knobs.clear();
}

void QuicTransportBase::processCallbacksAfterNetworkData() {
  if (closeState_ != CloseState::OPEN) {
    return;
  }
  // We reuse this storage for storing streams which need callbacks.
  std::vector<StreamId> tempStorage;
  // TODO move all of this callback processing to individual functions.
  tempStorage =
      conn_->streamManager->consumeNewPeerStreams(std::move(tempStorage));
  const auto& newPeerStreamsCopy = tempStorage;
  for (const auto& stream : newPeerStreamsCopy) {
    CHECK_NOTNULL(connCallback_);
    if (isBidirectionalStream(stream)) {
      connCallback_->onNewBidirectionalStream(stream);
    } else {
      connCallback_->onNewUnidirectionalStream(stream);
    }
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }

  // to call any callbacks added for observers
  for (const auto& callback : conn_->pendingCallbacks) {
    callback(this);
  }
  conn_->pendingCallbacks.clear();

  handlePingCallback();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  handleKnobCallbacks();

  // TODO: we're currently assuming that canceling write callbacks will not
  // cause reset of random streams. Maybe get rid of that assumption later.
  for (auto pendingResetIt = conn_->pendingEvents.resets.begin();
       pendingResetIt != conn_->pendingEvents.resets.end();
       pendingResetIt++) {
    cancelByteEventCallbacksForStream(pendingResetIt->first);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }
  auto deliverableStreamId = conn_->streamManager->popDeliverable();
  while (deliverableStreamId.has_value()) {
    auto streamId = *deliverableStreamId;
    auto stream = conn_->streamManager->getStream(streamId);
    auto maxOffsetToDeliver = getLargestDeliverableOffset(*stream);

    while (maxOffsetToDeliver.has_value()) {
      auto deliveryCallbacksForAckedStream = deliveryCallbacks_.find(streamId);
      if (deliveryCallbacksForAckedStream == deliveryCallbacks_.end() ||
          deliveryCallbacksForAckedStream->second.empty()) {
        break;
      }
      if (deliveryCallbacksForAckedStream->second.front().offset >
          *maxOffsetToDeliver) {
        break;
      }
      auto deliveryCallbackAndOffset =
          deliveryCallbacksForAckedStream->second.front();
      deliveryCallbacksForAckedStream->second.pop_front();
      auto currentDeliveryCallbackOffset = deliveryCallbackAndOffset.offset;
      auto deliveryCallback = deliveryCallbackAndOffset.callback;

      ByteEvent byteEvent = {};
      byteEvent.id = streamId;
      byteEvent.offset = currentDeliveryCallbackOffset;
      byteEvent.type = ByteEvent::Type::ACK;
      byteEvent.srtt = conn_->lossState.srtt;
      deliveryCallback->onByteEvent(byteEvent);
      if (closeState_ != CloseState::OPEN) {
        return;
      }
    }
    auto deliveryCallbacksForAckedStream = deliveryCallbacks_.find(streamId);
    if (deliveryCallbacksForAckedStream != deliveryCallbacks_.end() &&
        deliveryCallbacksForAckedStream->second.empty()) {
      deliveryCallbacks_.erase(deliveryCallbacksForAckedStream);
    }
    deliverableStreamId = conn_->streamManager->popDeliverable();
  }

  invokeDataExpiredCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }
  invokeDataRejectedCallbacks();
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  // Iterate over streams that changed their flow control window and give
  // their registered listeners their updates.
  // We don't really need flow control notifications when we are closed.
  tempStorage =
      conn_->streamManager->consumeFlowControlUpdated(std::move(tempStorage));
  const auto& flowControlUpdatedCopy = tempStorage;
  for (auto streamId : flowControlUpdatedCopy) {
    auto stream = conn_->streamManager->getStream(streamId);
    if (!stream->writable()) {
      pendingWriteCallbacks_.erase(streamId);
      continue;
    }
    CHECK_NOTNULL(connCallback_)->onFlowControlUpdate(streamId);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
    // In case the callback modified the stream map, get it again.
    stream = conn_->streamManager->getStream(streamId);
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

  const auto stopSendingStreamsCopy =
      conn_->streamManager->consumeStopSending();
  for (const auto& itr : stopSendingStreamsCopy) {
    CHECK_NOTNULL(connCallback_)->onStopSending(itr.first, itr.second);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }

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
    // on the streams now. TODO: maybe do this only when we know connection
    // flow control changed.
    auto writeCallbackIt = pendingWriteCallbacks_.begin();

    while (writeCallbackIt != pendingWriteCallbacks_.end()) {
      auto streamId = writeCallbackIt->first;
      auto wcb = writeCallbackIt->second;
      ++writeCallbackIt;
      auto stream = conn_->streamManager->getStream(streamId);
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

  invokeStreamsAvailableCallbacks();
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
    conn_->lossState.totalBytesRecvd += networkData.totalData;
    auto originalAckVersion = currentAckStateVersion(*conn_);
    for (auto& packet : networkData.packets) {
      onReadData(
          peer,
          NetworkDataSingle(std::move(packet), networkData.receiveTimePoint));
    }
    processCallbacksAfterNetworkData();
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
      // Reading data could change the state of the acks which could change the
      // ack timer. But we need to call scheduleAckTimeout() for it to take
      // effect.
      scheduleAckTimeout();
      // Received data could contain valid path response, in which case
      // path validation timeout should be canceled
      schedulePathValidationTimeout();
      // Received data could contain an ack to a d6d probe, in which case we
      // need to cancel the current d6d probe timeout. The ack might change d6d
      // state to SEARCH_COMPLETE, in which case we need to schedule d6d raise
      // timeout. We might also need to schedule the next probe.
      scheduleD6DProbeTimeout();
      scheduleD6DRaiseTimeout();
      scheduleD6DTxTimeout();
    } else {
      // In the closed state, we would want to write a close if possible however
      // the write looper will not be set.
      writeSocketData();
    }
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    return closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    return closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicApplicationException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    return closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    return closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("error onNetworkData()")));
  }
}

void QuicTransportBase::setIdleTimer() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  if (idleTimeout_.isScheduled()) {
    idleTimeout_.cancelTimeout();
  }
  auto localIdleTimeout = conn_->transportSettings.idleTimeout;
  // The local idle timeout being zero means it is disabled.
  if (localIdleTimeout == 0ms) {
    return;
  }
  auto peerIdleTimeout =
      conn_->peerIdleTimeout > 0ms ? conn_->peerIdleTimeout : localIdleTimeout;
  auto idleTimeout = timeMin(localIdleTimeout, peerIdleTimeout);
  getEventBase()->timer().scheduleTimeout(&idleTimeout_, idleTimeout);
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
QuicTransportBase::unregisterStreamWriteCallback(StreamId id) {
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (pendingWriteCallbacks_.find(id) == pendingWriteCallbacks_.end()) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  pendingWriteCallbacks_.erase(id);
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
  auto stream = conn_->streamManager->getStream(id);
  if (!stream->writable()) {
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
    auto stream = self->conn_->streamManager->getStream(id);
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
    if (!stream->writable()) {
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
    bool wasAppLimitedOrIdle = false;
    if (conn_->congestionController) {
      wasAppLimitedOrIdle = conn_->congestionController->isAppLimited();
      wasAppLimitedOrIdle |= conn_->streamManager->isAppIdle();
    }
    writeDataToQuicStream(*stream, std::move(data), eof);
    // If we were previously app limited, drop whatever tokens we have
    // collected while idle and restart pacing with the current rate.
    if (wasAppLimitedOrIdle && conn_->pacer) {
      conn_->pacer->resetPacingTokens();
    }
    updateWriteLooper(true);
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()), std::string("writeChain() error")));
    return folly::makeUnexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()), std::string("writeChain() error")));
    return folly::makeUnexpected(ex.errorCode());
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("writeChain() error")));
    return folly::makeUnexpected(LocalErrorCode::INTERNAL_ERROR);
  }
  return folly::unit;
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::registerDeliveryCallback(
    StreamId id,
    uint64_t offset,
    ByteEventCallback* cb) {
  return registerByteEventCallback(ByteEvent::Type::ACK, id, offset, cb);
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::registerTxCallback(
    StreamId id,
    uint64_t offset,
    ByteEventCallback* cb) {
  return registerByteEventCallback(ByteEvent::Type::TX, id, offset, cb);
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::registerByteEventCallback(
    const ByteEvent::Type type,
    const StreamId id,
    const uint64_t offset,
    ByteEventCallback* cb) {
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
  if (!cb) {
    return folly::unit;
  }

  ByteEventMap& byteEventMap = getByteEventMap(type);
  auto byteEventMapIt = byteEventMap.find(id);
  if (byteEventMapIt == byteEventMap.end()) {
    byteEventMap.emplace(
        id,
        std::initializer_list<std::remove_reference<decltype(
            byteEventMap)>::type::mapped_type::value_type>({{offset, cb}}));
  } else {
    // Keep ByteEvents for the same stream sorted by offsets:
    auto pos = std::upper_bound(
        byteEventMapIt->second.begin(),
        byteEventMapIt->second.end(),
        offset,
        [&](uint64_t o, const ByteEventDetail& p) { return o < p.offset; });
    byteEventMapIt->second.emplace(pos, offset, cb);
  }
  auto stream = conn_->streamManager->getStream(id);

  // if the callback is already ready, we still insert, but schedule to process
  folly::Optional<uint64_t> maxOffsetReady;
  switch (type) {
    case ByteEvent::Type::ACK:
      maxOffsetReady = getLargestDeliverableOffset(*stream);
      break;
    case ByteEvent::Type::TX:
      maxOffsetReady = getLargestWriteOffsetTxed(*stream);
      break;
  }
  if (maxOffsetReady.has_value() && (offset <= *maxOffsetReady)) {
    runOnEvbAsync([id, cb, offset, type](auto selfObj) {
      if (selfObj->closeState_ != CloseState::OPEN) {
        // Close will error out all byte event callbacks.
        return;
      }

      auto& byteEventMapL = selfObj->getByteEventMap(type);
      auto streamByteEventCbIt = byteEventMapL.find(id);
      if (streamByteEventCbIt == byteEventMapL.end()) {
        return;
      }
      auto pos = std::lower_bound(
          streamByteEventCbIt->second.begin(),
          streamByteEventCbIt->second.end(),
          offset,
          [&](const ByteEventDetail& p, uint64_t o) { return p.offset < o; });
      streamByteEventCbIt->second.erase(pos);

      ByteEvent byteEvent = {};
      byteEvent.id = id;
      byteEvent.offset = offset;
      byteEvent.type = type;
      cb->onByteEvent(byteEvent);
    });
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
    // Invoke state machine
    sendRstSMHandler(*stream, errorCode);

    for (auto pendingResetIt = conn_->pendingEvents.resets.begin();
         closeState_ == CloseState::OPEN &&
         pendingResetIt != conn_->pendingEvents.resets.end();
         pendingResetIt++) {
      cancelByteEventCallbacksForStream(pendingResetIt->first);
    }
    pendingWriteCallbacks_.erase(id);
    QUIC_STATS(conn_->statsCallback, onQuicStreamReset);
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()), std::string("resetStream() error")));
    return folly::makeUnexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()), std::string("resetStream() error")));
    return folly::makeUnexpected(ex.errorCode());
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("resetStream() error")));
    return folly::makeUnexpected(LocalErrorCode::INTERNAL_ERROR);
  }
  return folly::unit;
}

void QuicTransportBase::checkForClosedStream() {
  if (closeState_ == CloseState::CLOSED) {
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
    // If we have pending byte events, delay closing the stream
    auto numByteEventCb = getNumByteEventCallbacksForStream(*itr);
    if (numByteEventCb > 0) {
      VLOG(10) << "Not closing stream=" << *itr << " because it has "
               << numByteEventCb << " pending byte event callbacks";
      ++itr;
      continue;
    }

    VLOG(10) << "Closing stream=" << *itr;
    if (conn_->qLogger) {
      conn_->qLogger->addTransportStateUpdate(
          getClosingStream(folly::to<std::string>(*itr)));
    }
    conn_->streamManager->removeClosedStream(*itr);
    maybeSendStreamLimitUpdates(*conn_);
    if (readCbIt != readCallbacks_.end()) {
      readCallbacks_.erase(readCbIt);
    }
    if (peekCbIt != peekCallbacks_.end()) {
      peekCallbacks_.erase(peekCbIt);
    }
    itr = conn_->streamManager->closedStreams().erase(itr);
  } // while

  if (closeState_ == CloseState::GRACEFUL_CLOSING &&
      conn_->streamManager->streamCount() == 0) {
    closeImpl(folly::none);
  }
}

void QuicTransportBase::sendPing(
    PingCallback* callback,
    std::chrono::milliseconds pingTimeout) {
  /* Step 0: Connection should not be closed */
  if (closeState_ == CloseState::CLOSED) {
    return;
  }

  // Step 1: Send a simple ping frame
  conn_->pendingEvents.sendPing = true;
  updateWriteLooper(true);

  // Step 2: Schedule the timeout on event base
  if (callback && pingTimeout != 0ms) {
    schedulePingTimeout(callback, pingTimeout);
  }
}

void QuicTransportBase::lossTimeoutExpired() noexcept {
  CHECK_NE(closeState_, CloseState::CLOSED);
  // onLossDetectionAlarm will set packetToSend in pending events
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  try {
    onLossDetectionAlarm(*conn_, markPacketLoss);
    // TODO: remove this trace when Pacing is ready to land
    QUIC_TRACE(fst_trace, *conn_, "LossTimeoutExpired");
    if (conn_->qLogger) {
      conn_->qLogger->addTransportStateUpdate(kLossTimeoutExpired);
    }
    // loss detection might cancel d6d raise timeout, and might cause the next
    // probe to be scheduled
    scheduleD6DRaiseTimeout();
    scheduleD6DTxTimeout();
    pacedWriteDataToSocket(false);
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()),
        std::string("lossTimeoutExpired() error")));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()),
        std::string("lossTimeoutExpired() error")));
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << "  " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("lossTimeoutExpired() error")));
  }
}

void QuicTransportBase::ackTimeoutExpired() noexcept {
  CHECK_NE(closeState_, CloseState::CLOSED);
  VLOG(10) << __func__ << " " << *this;
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  updateAckStateOnAckTimeout(*conn_);
  pacedWriteDataToSocket(false);
}

void QuicTransportBase::pingTimeoutExpired() noexcept {
  // If timeout expired just call the  call back Provided
  if (pingCallback_ == nullptr) {
    return;
  }
  runOnEvbAsync([](auto self) { self->pingCallback_->pingTimeout(); });
}

void QuicTransportBase::pathValidationTimeoutExpired() noexcept {
  CHECK(conn_->outstandingPathValidation);

  conn_->pendingEvents.schedulePathValidationTimeout = false;
  conn_->outstandingPathValidation = folly::none;
  if (conn_->qLogger) {
    conn_->qLogger->addPathValidationEvent(false);
  }

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
          toString(LocalErrorCode::IDLE_TIMEOUT).str()),
      drain /* drainConnection */,
      !drain /* sendCloseImmediately */);
}

void QuicTransportBase::d6dProbeTimeoutExpired() noexcept {
  VLOG(4) << __func__ << " " << *this;
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  conn_->pendingEvents.d6d.scheduleProbeTimeout = false;
  onD6DProbeTimeoutExpired(*conn_);
}

void QuicTransportBase::d6dRaiseTimeoutExpired() noexcept {
  VLOG(4) << __func__ << " " << *this;
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  conn_->pendingEvents.d6d.scheduleRaiseTimeout = false;
  onD6DRaiseTimeoutExpired(*conn_);
}

void QuicTransportBase::d6dTxTimeoutExpired() noexcept {
  VLOG(4) << __func__ << " " << *this;
  conn_->pendingEvents.d6d.sendProbeDelay = folly::none;
  conn_->pendingEvents.d6d.sendProbePacket = true;
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
      auto& wheelTimer = getEventBase()->timer();
      auto timeout = timeMax(
          std::chrono::duration_cast<std::chrono::microseconds>(
              wheelTimer.getTickInterval()),
          timeMin(kMaxAckTimeout, factoredRtt));
      auto timeoutMs = folly::chrono::ceil<std::chrono::milliseconds>(timeout);
      VLOG(10) << __func__ << " timeout=" << timeoutMs.count() << "ms"
               << " factoredRtt=" << factoredRtt.count() << "us"
               << " " << *this;
      wheelTimer.scheduleTimeout(&ackTimeout_, timeoutMs);
    }
  } else {
    if (ackTimeout_.isScheduled()) {
      VLOG(10) << __func__ << " cancel timeout " << *this;
      ackTimeout_.cancelTimeout();
    }
  }
}

void QuicTransportBase::schedulePingTimeout(
    PingCallback* pingCb,
    std::chrono::milliseconds timeout) {
  // if a ping timeout is already scheduled, nothing to do, return
  if (pingTimeout_.isScheduled()) {
    return;
  }

  pingCallback_ = pingCb;
  auto& wheelTimer = getEventBase()->timer();
  wheelTimer.scheduleTimeout(&pingTimeout_, timeout);
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

    auto validationTimeout =
        std::max(3 * pto, 6 * conn_->transportSettings.initialRtt);
    auto timeoutMs =
        folly::chrono::ceil<std::chrono::milliseconds>(validationTimeout);
    VLOG(10) << __func__ << " timeout=" << timeoutMs.count() << "ms " << *this;
    getEventBase()->timer().scheduleTimeout(&pathValidationTimeout_, timeoutMs);
  }
}

void QuicTransportBase::scheduleD6DProbeTimeout() {
  if (conn_->pendingEvents.d6d.scheduleProbeTimeout) {
    if (!d6dProbeTimeout_.isScheduled()) {
      VLOG(10) << __func__ << "timeout=" << conn_->d6d.probeTimeout.count()
               << "ms " << *this;
      getEventBase()->timer().scheduleTimeout(
          &d6dProbeTimeout_, conn_->d6d.probeTimeout);
    }
  } else {
    if (d6dProbeTimeout_.isScheduled()) {
      VLOG(10) << __func__ << " cancel timeout " << *this;
      d6dProbeTimeout_.cancelTimeout();
    }
  }
}

void QuicTransportBase::scheduleD6DRaiseTimeout() {
  if (conn_->pendingEvents.d6d.scheduleRaiseTimeout) {
    if (!d6dRaiseTimeout_.isScheduled()) {
      VLOG(10) << __func__ << "timeout=" << conn_->d6d.raiseTimeout.count()
               << "s " << *this;
      getEventBase()->timer().scheduleTimeout(
          &d6dRaiseTimeout_, conn_->d6d.raiseTimeout);
    }
  } else {
    if (d6dRaiseTimeout_.isScheduled()) {
      VLOG(10) << __func__ << " cancel timeout " << *this;
      d6dRaiseTimeout_.cancelTimeout();
    }
  }
}

void QuicTransportBase::scheduleD6DTxTimeout() {
  auto& delay = conn_->pendingEvents.d6d.sendProbeDelay;
  if (delay) {
    if (!d6dTxTimeout_.isScheduled()) {
      VLOG(10) << __func__ << "timeout=" << conn_->d6d.raiseTimeout.count()
               << "s " << *this;
      getEventBase()->timer().scheduleTimeout(&d6dTxTimeout_, *delay);
    }
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
    folly::Function<bool(const folly::Optional<std::string>&, const Buf&) const>
        validator,
    folly::Function<Buf()> getter) {
  conn_->earlyDataAppParamsValidator = std::move(validator);
  conn_->earlyDataAppParamsGetter = std::move(getter);
}

void QuicTransportBase::cancelAllAppCallbacks(
    const std::pair<QuicErrorCode, folly::StringPiece>& err) noexcept {
  SCOPE_EXIT {
    checkForClosedStream();
    updateReadLooper();
    updatePeekLooper();
    updateWriteLooper(true);
  };
  conn_->streamManager->clearActionable();
  // Cancel any pending ByteEvent callbacks
  cancelAllByteEventCallbacks();
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
      cb.second.readCb->readError(cb.first, err);
    }
  }
  VLOG(4) << "Clearing " << peekCallbacks_.size() << " peek callbacks";
  peekCallbacks_.clear();
  dataExpiredCallbacks_.clear();
  dataRejectedCallbacks_.clear();

  if (connWriteCallback_) {
    auto connWriteCallback = connWriteCallback_;
    connWriteCallback_ = nullptr;
    connWriteCallback->onConnectionWriteError(err);
  }
  auto it = pendingWriteCallbacks_.begin();
  while (it != pendingWriteCallbacks_.end()) {
    auto wcb = it->second;
    wcb->onStreamWriteError(it->first, err);
    it = pendingWriteCallbacks_.erase(it);
  }
}

void QuicTransportBase::addLifecycleObserver(LifecycleObserver* observer) {
  lifecycleObservers_.push_back(CHECK_NOTNULL(observer));
  observer->observerAttach(this);
}

bool QuicTransportBase::removeLifecycleObserver(LifecycleObserver* observer) {
  const auto eraseIt = std::remove(
      lifecycleObservers_.begin(), lifecycleObservers_.end(), observer);
  if (eraseIt == lifecycleObservers_.end()) {
    return false;
  }

  for (auto it = eraseIt; it != lifecycleObservers_.end(); it++) {
    (*it)->observerDetach(this);
  }
  lifecycleObservers_.erase(eraseIt, lifecycleObservers_.end());
  return true;
}

const QuicTransportBase::LifecycleObserverVec&
QuicTransportBase::getLifecycleObservers() const {
  return lifecycleObservers_;
}

void QuicTransportBase::addInstrumentationObserver(
    InstrumentationObserver* observer) {
  conn_->instrumentationObservers_.push_back(CHECK_NOTNULL(observer));
}

bool QuicTransportBase::removeInstrumentationObserver(
    InstrumentationObserver* observer) {
  const auto eraseIt = std::remove(
      conn_->instrumentationObservers_.begin(),
      conn_->instrumentationObservers_.end(),
      observer);
  if (eraseIt == conn_->instrumentationObservers_.end()) {
    return false;
  }

  for (auto it = eraseIt; it != conn_->instrumentationObservers_.end(); it++) {
    (*it)->observerDetach(this);
  }
  conn_->instrumentationObservers_.erase(
      eraseIt, conn_->instrumentationObservers_.end());
  return true;
}

const InstrumentationObserverVec&
QuicTransportBase::getInstrumentationObservers() const {
  return conn_->instrumentationObservers_;
}

void QuicTransportBase::writeSocketData() {
  if (socket_) {
    auto packetsBefore = conn_->outstandings.numOutstanding();
    writeData();
    if (closeState_ != CloseState::CLOSED) {
      if (conn_->pendingEvents.closeTransport == true) {
        throw QuicTransportException(
            "Max packet number reached",
            TransportErrorCode::PROTOCOL_VIOLATION);
      }
      setLossDetectionAlarm(*conn_, *this);
      auto packetsAfter = conn_->outstandings.numOutstanding();
      bool packetWritten = (packetsAfter > packetsBefore);
      if (conn_->loopDetectorCallback && packetWritten) {
        conn_->writeDebugState.currentEmptyLoopCount = 0;
      } else if (
          conn_->writeDebugState.needsWriteLoopDetect &&
          conn_->loopDetectorCallback) {
        // TODO: Currently we will to get some stats first. Then we may filter
        // out some errors here. For example, socket fail to write might be a
        // legit case to filter out.
        conn_->loopDetectorCallback->onSuspiciousWriteLoops(
            ++conn_->writeDebugState.currentEmptyLoopCount,
            conn_->writeDebugState.writeDataReason,
            conn_->writeDebugState.noWriteReason,
            conn_->writeDebugState.schedulerName);
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
        // notify via connection call and any instrumentation callbacks
        connCallback_->onAppRateLimited();
        for (const auto& cb : conn_->instrumentationObservers_) {
          cb->appRateLimited(this);
        }
      }
    }
  }
  // Writing data could write out an ack which could cause us to cancel
  // the ack timer. But we need to call scheduleAckTimeout() for it to take
  // effect.
  scheduleAckTimeout();
  schedulePathValidationTimeout();
  // Writing data could write out a d6d probe, for which we need to schedule a
  // probe timeout
  scheduleD6DProbeTimeout();
  updateWriteLooper(false);
}

void QuicTransportBase::writeSocketDataAndCatch() {
  FOLLY_MAYBE_UNUSED auto self = sharedGuard();
  try {
    writeSocketData();
    processCallbacksAfterWriteData();
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()),
        std::string("writeSocketDataAndCatch()  error")));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(ex.errorCode()),
        std::string("writeSocketDataAndCatch()  error")));
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " error=" << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("writeSocketDataAndCatch()  error")));
  }
}

void QuicTransportBase::setTransportSettings(
    TransportSettings transportSettings) {
  if (conn_->nodeType == QuicNodeType::Client) {
    conn_->transportSettings.dataPathType = DataPathType::ChainedMemory;
  }
  // If transport parameters are encoded, we can only update congestion control
  // related params. Setting other transport settings again would be buggy.
  // TODO should we throw or return Expected here?
  if (conn_->transportParametersEncoded) {
    updateCongestionControlSettings(transportSettings);
  } else {
    // TODO: We should let chain based GSO to use bufAccessor in the future as
    // well.
    CHECK(
        conn_->bufAccessor ||
        transportSettings.dataPathType != DataPathType::ContinuousMemory);
    conn_->transportSettings = std::move(transportSettings);
    conn_->streamManager->refreshTransportSettings(conn_->transportSettings);
  }

  // A few values cannot be overridden to be lower than default:
  // TODO refactor transport settings to avoid having to update params twice.
  if (conn_->transportSettings.defaultCongestionController !=
      CongestionControlType::None) {
    conn_->transportSettings.initCwndInMss =
        std::max(conn_->transportSettings.initCwndInMss, kInitCwndInMss);
    conn_->transportSettings.minCwndInMss =
        std::max(conn_->transportSettings.initCwndInMss, kMinCwndInMss);
    conn_->transportSettings.initCwndInMss = std::max(
        conn_->transportSettings.minCwndInMss,
        conn_->transportSettings.initCwndInMss);
  }
  setCongestionControl(transportSettings.defaultCongestionController);
  if (conn_->transportSettings.pacingEnabled) {
    if (writeLooper_->hasPacingTimer()) {
      bool usingBbr = conn_->congestionController &&
          (conn_->congestionController->type() == CongestionControlType::BBR);
      auto minCwnd = usingBbr ? kMinCwndInMssForBbr
                              : conn_->transportSettings.minCwndInMss;
      if (conn_->transportSettings.tokenlessPacer) {
        conn_->pacer = std::make_unique<TokenlessPacer>(*conn_, minCwnd);
      } else {
        conn_->pacer = std::make_unique<DefaultPacer>(*conn_, minCwnd);
      }
    } else {
      LOG(ERROR) << "Pacing cannot be enabled without a timer";
      conn_->transportSettings.pacingEnabled = false;
    }
  }
}

void QuicTransportBase::updateCongestionControlSettings(
    const TransportSettings& transportSettings) {
  conn_->transportSettings.defaultCongestionController =
      transportSettings.defaultCongestionController;
  conn_->transportSettings.initCwndInMss = transportSettings.initCwndInMss;
  conn_->transportSettings.minCwndInMss = transportSettings.minCwndInMss;
  conn_->transportSettings.maxCwndInMss = transportSettings.maxCwndInMss;
  conn_->transportSettings.limitedCwndInMss =
      transportSettings.limitedCwndInMss;
  conn_->transportSettings.pacingEnabled = transportSettings.pacingEnabled;
  conn_->transportSettings.pacingTimerTickInterval =
      transportSettings.pacingTimerTickInterval;
  conn_->transportSettings.minBurstPackets = transportSettings.minBurstPackets;
  conn_->transportSettings.copaDeltaParam = transportSettings.copaDeltaParam;
  conn_->transportSettings.copaUseRttStanding =
      transportSettings.copaUseRttStanding;
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setKnob(uint64_t knobSpace, uint64_t knobId, Buf knobBlob) {
  if (isKnobSupported()) {
    sendSimpleFrame(*conn_, KnobFrame(knobSpace, knobId, std::move(knobBlob)));
    return folly::unit;
  }
  LOG(ERROR)
      << "Cannot set Knob Frame. QUIC negotiation not complete or negotiated version is not MVFST";
  return folly::makeUnexpected(LocalErrorCode::KNOB_FRAME_UNSUPPORTED);
}

bool QuicTransportBase::isKnobSupported() const {
  // We determine that the peer supports knob frames by looking at the
  // negotiated QUIC version.
  // TODO: This is temporary. Soon, we will add a transport parameter for knob
  // support and incorporate it into the check, such that if the QUIC version
  // increases/changes, this method will still continue to work, based on the
  // transport parameter setting.
  return (conn_->version && (*(conn_->version) == QuicVersion::MVFST));
}

const TransportSettings& QuicTransportBase::getTransportSettings() const {
  return conn_->transportSettings;
}

bool QuicTransportBase::isPartiallyReliableTransport() const {
  return conn_->partialReliabilityEnabled;
}

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBase::setStreamPriority(
    StreamId id,
    PriorityLevel level,
    bool incremental) {
  if (closeState_ != CloseState::OPEN) {
    return folly::makeUnexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (level > kDefaultMaxPriority) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (!conn_->streamManager->streamExists(id)) {
    // It's not an error to try to prioritize a non-existent stream.
    return folly::unit;
  }
  // It's not an error to prioritize a stream after it's sent its FIN - this
  // can reprioritize retransmissions.
  conn_->streamManager->setStreamPriority(id, level, incremental);
  if (conn_->qLogger) {
    conn_->qLogger->addPriorityUpdate(id, level, incremental);
  }
  return folly::unit;
}

void QuicTransportBase::setCongestionControl(CongestionControlType type) {
  DCHECK(conn_);
  if (!conn_->congestionController ||
      type != conn_->congestionController->type()) {
    CHECK(ccFactory_);

    // Fallback to Cubic if Pacing isn't enabled with BBR together
    if (type == CongestionControlType::BBR &&
        (!conn_->transportSettings.pacingEnabled ||
         !writeLooper_->hasPacingTimer())) {
      LOG(ERROR) << "Unpaced BBR isn't supported";
      type = CongestionControlType::Cubic;
    }

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

  for (const auto& cb : lifecycleObservers_) {
    cb->evbAttach(this, evb_);
  }
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

  for (const auto& cb : lifecycleObservers_) {
    cb->evbDetach(this, evb_);
  }
  evb_ = nullptr;
}

folly::Optional<LocalErrorCode> QuicTransportBase::setControlStream(
    StreamId id) {
  if (!conn_->streamManager->streamExists(id)) {
    return LocalErrorCode::STREAM_NOT_EXISTS;
  }
  auto stream = conn_->streamManager->getStream(id);
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
  auto packets = getNumPacketsTxWithNewData(*stream);
  return StreamTransportInfo{stream->totalHolbTime,
                             stream->holbCount,
                             bool(stream->lastHolbTime),
                             packets};
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
  quic::ApplicationErrorCode* code = error.asApplicationErrorCode();
  if (code) {
    return resetStream(id, *code);
  }
  return folly::Expected<folly::Unit, LocalErrorCode>(folly::unit);
}

QuicTransportBase::ByteEventMap& QuicTransportBase::getByteEventMap(
    const ByteEvent::Type type) {
  switch (type) {
    case ByteEvent::Type::ACK:
      return deliveryCallbacks_;
    case ByteEvent::Type::TX:
      return txCallbacks_;
  }
  LOG(FATAL) << "Unhandled case in getByteEventMap";
  folly::assume_unreachable();
}

const QuicTransportBase::ByteEventMap& QuicTransportBase::getByteEventMapConst(
    const ByteEvent::Type type) const {
  switch (type) {
    case ByteEvent::Type::ACK:
      return deliveryCallbacks_;
    case ByteEvent::Type::TX:
      return txCallbacks_;
  }
  LOG(FATAL) << "Unhandled case in getByteEventMapConst";
  folly::assume_unreachable();
}

void QuicTransportBase::onTransportKnobs(Buf knobBlob) {
  // Not yet implemented,
  VLOG(4) << "Received transport knobs: "
          << std::string(
                 reinterpret_cast<const char*>(knobBlob->data()),
                 knobBlob->length());
}

} // namespace quic
