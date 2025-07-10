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
#include <quic/congestion_control/Pacer.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/SimpleFrameFunctions.h>
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
  if (socket_) {
    std::function<Optional<folly::SocketCmsgMap>()> func = [&]() {
      return getAdditionalCmsgsForAsyncUDPSocket();
    };
    // TODO we probably should have a better way to return error from
    // creating a connection.
    // Can't really do anything with this at this point.
    CHECK(socket_->setAdditionalCmsgsFunc(std::move(func)).has_value());
  }
}

void QuicTransportBase::setPacingTimer(
    QuicTimer::SharedPtr pacingTimer) noexcept {
  if (pacingTimer) {
    writeLooper_->setPacingTimer(std::move(pacingTimer));
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
    closeImpl(std::nullopt);
  }
}

quic::Expected<size_t, LocalErrorCode> QuicTransportBase::getStreamReadOffset(
    StreamId) const {
  return 0;
}

quic::Expected<size_t, LocalErrorCode> QuicTransportBase::getStreamWriteOffset(
    StreamId id) const {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  try {
    auto stream =
        CHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));
    return stream->currentWriteOffset;
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(ex.errorCode());
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }
}

quic::Expected<size_t, LocalErrorCode>
QuicTransportBase::getStreamWriteBufferedBytes(StreamId id) const {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  try {
    auto stream =
        CHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));
    return stream->pendingWrites.chainLength();
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(ex.errorCode());
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }
}

quic::Expected<QuicSocket::FlowControlState, LocalErrorCode>
QuicTransportBase::getConnectionFlowControl() const {
  return QuicSocket::FlowControlState(
      getSendConnFlowControlBytesAPI(*conn_),
      conn_->flowControlState.peerAdvertisedMaxOffset,
      getRecvConnFlowControlBytes(*conn_),
      conn_->flowControlState.advertisedMaxOffset);
}

quic::Expected<uint64_t, LocalErrorCode>
QuicTransportBase::getMaxWritableOnStream(StreamId id) const {
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  auto stream =
      CHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));
  return maxWritableOnStream(*stream);
}

quic::Expected<void, LocalErrorCode>
QuicTransportBase::setConnectionFlowControlWindow(uint64_t windowSize) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  conn_->flowControlState.windowSize = windowSize;
  maybeSendConnWindowUpdate(*conn_, Clock::now());
  updateWriteLooper(true);
  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBase::setStreamFlowControlWindow(
    StreamId id,
    uint64_t windowSize) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream =
      CHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));
  stream->flowControlState.windowSize = windowSize;
  maybeSendStreamWindowUpdate(*stream, Clock::now());
  updateWriteLooper(true);
  return {};
}

void QuicTransportBase::unsetAllReadCallbacks() {
  for (const auto& [id, _] : readCallbacks_) {
    CHECK(setReadCallbackInternal(id, nullptr, APP_NO_ERROR).has_value());
  }
}

void QuicTransportBase::unsetAllPeekCallbacks() {
  for (const auto& [id, _] : peekCallbacks_) {
    CHECK(setPeekCallbackInternal(id, nullptr).has_value());
  }
}

void QuicTransportBase::unsetAllDeliveryCallbacks() {
  auto deliveryCallbacksCopy = deliveryCallbacks_;
  for (const auto& [id, _] : deliveryCallbacksCopy) {
    cancelDeliveryCallbacksForStream(id);
  }
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::pauseRead(StreamId id) {
  VLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumeRead(id, false);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::resumeRead(
    StreamId id) {
  VLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumeRead(id, true);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::pauseOrResumeRead(
    StreamId id,
    bool resume) {
  if (isSendingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto readCb = readCallbacks_.find(id);
  if (readCb == readCallbacks_.end()) {
    return quic::make_unexpected(LocalErrorCode::APP_ERROR);
  }
  if (readCb->second.resumed != resume) {
    readCb->second.resumed = resume;
    updateReadLooper();
  }
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::setPeekCallback(
    StreamId id,
    PeekCallback* cb) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  return setPeekCallbackInternal(id, cb);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::setPeekCallbackInternal(
    StreamId id,
    PeekCallback* cb) noexcept {
  VLOG(4) << "Setting setPeekCallback for stream=" << id << " cb=" << cb << " "
          << *this;
  auto peekCbIt = peekCallbacks_.find(id);
  if (peekCbIt == peekCallbacks_.end()) {
    // Don't allow initial setting of a nullptr callback.
    if (!cb) {
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    peekCbIt = peekCallbacks_.emplace(id, PeekCallbackData(cb)).first;
  }
  if (!cb) {
    VLOG(10) << "Resetting the peek callback to nullptr " << "stream=" << id
             << " peekCb=" << peekCbIt->second.peekCb;
  }
  peekCbIt->second.peekCb = cb;
  updatePeekLooper();
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::pausePeek(StreamId id) {
  VLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumePeek(id, false);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::resumePeek(
    StreamId id) {
  VLOG(4) << __func__ << " " << *this << " stream=" << id;
  return pauseOrResumePeek(id, true);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::pauseOrResumePeek(
    StreamId id,
    bool resume) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto peekCb = peekCallbacks_.find(id);
  if (peekCb == peekCallbacks_.end()) {
    return quic::make_unexpected(LocalErrorCode::APP_ERROR);
  }
  if (peekCb->second.resumed != resume) {
    peekCb->second.resumed = resume;
    updatePeekLooper();
  }
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::peek(
    StreamId id,
    const std::function<void(StreamId id, const folly::Range<PeekIterator>&)>&
        peekCallback) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    updatePeekLooper();
    updateWriteLooper(true);
  };

  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream =
      CHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));

  if (stream->streamReadError) {
    switch (stream->streamReadError->type()) {
      case QuicErrorCode::Type::LocalErrorCode:
        return quic::make_unexpected(
            *stream->streamReadError->asLocalErrorCode());
      default:
        return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
    }
  }

  peekDataFromQuicStream(*stream, std::move(peekCallback));
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::consume(
    StreamId id,
    size_t amount) {
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream =
      CHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));
  auto result = consume(id, stream->currentReadOffset, amount);
  if (!result.has_value()) {
    return quic::make_unexpected(result.error().first);
  }
  return {};
}

quic::Expected<void, std::pair<LocalErrorCode, Optional<uint64_t>>>
QuicTransportBase::consume(StreamId id, uint64_t offset, size_t amount) {
  using ConsumeError = std::pair<LocalErrorCode, Optional<uint64_t>>;
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(
        ConsumeError{LocalErrorCode::CONNECTION_CLOSED, std::nullopt});
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
      return quic::make_unexpected(
          ConsumeError{LocalErrorCode::STREAM_NOT_EXISTS, readOffset});
    }
    auto stream =
        CHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));
    readOffset = stream->currentReadOffset;
    if (stream->currentReadOffset != offset) {
      return quic::make_unexpected(
          ConsumeError{LocalErrorCode::INTERNAL_ERROR, readOffset});
    }

    if (stream->streamReadError) {
      switch (stream->streamReadError->type()) {
        case QuicErrorCode::Type::LocalErrorCode:
          return quic::make_unexpected(ConsumeError{
              *stream->streamReadError->asLocalErrorCode(), std::nullopt});
        default:
          return quic::make_unexpected(
              ConsumeError{LocalErrorCode::INTERNAL_ERROR, std::nullopt});
      }
    }

    auto consumeResult = consumeDataFromQuicStream(*stream, amount);
    if (!consumeResult.has_value()) {
      return quic::make_unexpected(
          ConsumeError{LocalErrorCode::INTERNAL_ERROR, std::nullopt});
    }
    return {};
  } catch (const QuicTransportException& ex) {
    VLOG(4) << "consume() error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("consume() error")));
    return quic::make_unexpected(
        ConsumeError{LocalErrorCode::TRANSPORT_ERROR, readOffset});
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("consume() error")));
    return quic::make_unexpected(ConsumeError{ex.errorCode(), readOffset});
  } catch (const std::exception& ex) {
    VLOG(4) << "consume() error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("consume() error")));
    return quic::make_unexpected(
        ConsumeError{LocalErrorCode::INTERNAL_ERROR, readOffset});
  }
}

quic::Expected<StreamGroupId, LocalErrorCode>
QuicTransportBase::createBidirectionalStreamGroup() {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  return conn_->streamManager->createNextBidirectionalStreamGroup();
}

quic::Expected<StreamGroupId, LocalErrorCode>
QuicTransportBase::createUnidirectionalStreamGroup() {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  return conn_->streamManager->createNextUnidirectionalStreamGroup();
}

quic::Expected<StreamId, LocalErrorCode>
QuicTransportBase::createBidirectionalStreamInGroup(StreamGroupId groupId) {
  return createStreamInternal(true, groupId);
}

quic::Expected<StreamId, LocalErrorCode>
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

quic::Expected<void, LocalErrorCode> QuicTransportBase::registerTxCallback(
    StreamId id,
    uint64_t offset,
    ByteEventCallback* cb) {
  return registerByteEventCallback(ByteEvent::Type::TX, id, offset, cb);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::setPingCallback(
    PingCallback* cb) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  VLOG(4) << "Setting ping callback " << " cb=" << cb << " " << *this;

  pingCallback_ = cb;
  return {};
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

void QuicTransportBase::setAckRxTimestampsEnabled(bool enableAckRxTimestamps) {
  if (!enableAckRxTimestamps) {
    conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer =
        std::nullopt;
  }
}

void QuicTransportBase::setEarlyDataAppParamsFunctions(
    std::function<bool(const Optional<std::string>&, const BufPtr&)> validator,
    std::function<BufPtr()> getter) {
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
      // TODO: Change external API signature to return Expected instead of using
      // (void). Right now we apparently partially support this as a non error.
      (void)resetStream(id, error);
    }
    if (isReceivingStream(conn_->nodeType, id) || isBidirectionalStream(id)) {
      auto readCallbackIt = readCallbacks_.find(id);
      if (readCallbackIt != readCallbacks_.end() &&
          readCallbackIt->second.readCb) {
        auto stream = CHECK_NOTNULL(
            conn_->streamManager->getStream(id).value_or(nullptr));
        if (!stream->groupId) {
          readCallbackIt->second.readCb->readError(
              id, QuicError(error, errorMsg.str()));
        } else {
          readCallbackIt->second.readCb->readErrorWithGroup(
              id, *stream->groupId, QuicError(error, errorMsg.str()));
        }
      }
      peekCallbacks_.erase(id);
      (void)stopSending(id, error);
    }
  }
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::setDatagramCallback(
    DatagramCallback* cb) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  VLOG(4) << "Setting datagram callback " << " cb=" << cb << " " << *this;

  datagramCallback_ = cb;
  updateReadLooper();
  return {};
}

uint16_t QuicTransportBase::getDatagramSizeLimit() const {
  CHECK(conn_);
  auto maxDatagramPacketSize = std::min<decltype(conn_->udpSendPacketLen)>(
      conn_->datagramState.maxWriteFrameSize, conn_->udpSendPacketLen);
  return std::max<decltype(maxDatagramPacketSize)>(
      0, maxDatagramPacketSize - kMaxDatagramPacketOverhead);
}

quic::Expected<void, LocalErrorCode> QuicTransportBase::writeDatagram(
    BufPtr buf) {
  // TODO(lniccolini) update max datagram frame size
  // https://github.com/quicwg/datagram/issues/3
  // For now, max_datagram_size > 0 means the peer supports datagram frames
  if (conn_->datagramState.maxWriteFrameSize == 0) {
    QUIC_STATS(conn_->statsCallback, onDatagramDroppedOnWrite);
    return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_DATA);
  }
  if (conn_->datagramState.writeBuffer.size() >=
      conn_->datagramState.maxWriteBufferSize) {
    QUIC_STATS(conn_->statsCallback, onDatagramDroppedOnWrite);
    if (!conn_->transportSettings.datagramConfig.sendDropOldDataFirst) {
      // TODO(lniccolini) use different return codes to signal the application
      // exactly why the datagram got dropped
      return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_DATA);
    } else {
      conn_->datagramState.writeBuffer.pop_front();
    }
  }
  conn_->datagramState.writeBuffer.emplace_back(std::move(buf));
  updateWriteLooper(true);
  return {};
}

quic::Expected<std::vector<ReadDatagram>, LocalErrorCode>
QuicTransportBase::readDatagrams(size_t atMost) {
  CHECK(conn_);
  auto datagrams = &conn_->datagramState.readBuffer;
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
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

quic::Expected<std::vector<BufPtr>, LocalErrorCode>
QuicTransportBase::readDatagramBufs(size_t atMost) {
  CHECK(conn_);
  auto datagrams = &conn_->datagramState.readBuffer;
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (atMost == 0) {
    atMost = datagrams->size();
  } else {
    atMost = std::min(atMost, datagrams->size());
  }
  std::vector<BufPtr> retDatagrams;
  retDatagrams.reserve(atMost);
  std::transform(
      datagrams->begin(),
      datagrams->begin() + atMost,
      std::back_inserter(retDatagrams),
      [](ReadDatagram& dg) { return dg.bufQueue().move(); });
  datagrams->erase(datagrams->begin(), datagrams->begin() + atMost);
  return retDatagrams;
}

quic::Expected<PriorityQueue::Priority, LocalErrorCode>
QuicTransportBase::getStreamPriority(StreamId id) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (auto stream = conn_->streamManager->findStream(id)) {
    return stream->priority;
  }
  return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
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

quic::Expected<void, LocalErrorCode>
QuicTransportBase::maybeResetStreamFromReadError(
    StreamId id,
    QuicErrorCode error) {
  if (quic::ApplicationErrorCode* code = error.asApplicationErrorCode()) {
    return resetStream(id, *code);
  }
  return {};
}

void QuicTransportBase::setCmsgs(const folly::SocketCmsgMap& options) {
  // TODO figure out what we want to do here in the unlikely error case.
  CHECK(socket_->setCmsgs(options).has_value());
}

void QuicTransportBase::appendCmsgs(const folly::SocketCmsgMap& options) {
  // TODO figure out what we want to do here in the unlikely error case.
  CHECK(socket_->appendCmsgs(options).has_value());
}

bool QuicTransportBase::checkCustomRetransmissionProfilesEnabled() const {
  return quic::checkCustomRetransmissionProfilesEnabled(*conn_);
}

quic::Expected<void, LocalErrorCode>
QuicTransportBase::setStreamGroupRetransmissionPolicy(
    StreamGroupId groupId,
    std::optional<QuicStreamGroupRetransmissionPolicy> policy) noexcept {
  // Reset the policy to default one.
  if (policy == std::nullopt) {
    conn_->retransmissionPolicies.erase(groupId);
    return {};
  }

  if (!checkCustomRetransmissionProfilesEnabled()) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  if (conn_->retransmissionPolicies.size() >=
      conn_->transportSettings.advertisedMaxStreamGroups) {
    return quic::make_unexpected(LocalErrorCode::RTX_POLICIES_LIMIT_EXCEEDED);
  }

  conn_->retransmissionPolicies.emplace(groupId, *policy);
  return {};
}

} // namespace quic
