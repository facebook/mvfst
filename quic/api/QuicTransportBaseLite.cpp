/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicTransportBaseLite.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/QuicStreamFunctions.h>

namespace {
constexpr auto APP_NO_ERROR = quic::GenericApplicationErrorCode::NO_ERROR;
} // namespace

namespace quic {

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
QuicTransportBaseLite::notifyPendingWriteOnConnection(
    ConnectionWriteCallback* wcb) {
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
QuicTransportBaseLite::unregisterStreamWriteCallback(StreamId id) {
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
QuicTransportBaseLite::notifyPendingWriteOnStream(
    StreamId id,
    StreamWriteCallback* wcb) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
  }
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

  if (wcb == nullptr) {
    return folly::makeUnexpected(LocalErrorCode::INVALID_WRITE_CALLBACK);
  }
  // Add the callback to the pending write callbacks so that if we are closed
  // while we are scheduled in the loop, the close will error out the
  // callbacks.
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
          id, QuicError(LocalErrorCode::STREAM_NOT_EXISTS));
      return;
    }
    auto stream = CHECK_NOTNULL(self->conn_->streamManager->getStream(id));
    if (!stream->writable()) {
      self->pendingWriteCallbacks_.erase(wcbIt);
      writeCallback->onStreamWriteError(
          id, QuicError(LocalErrorCode::STREAM_NOT_EXISTS));
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

folly::Expected<folly::Unit, LocalErrorCode>
QuicTransportBaseLite::registerByteEventCallback(
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
  [[maybe_unused]] auto self = sharedGuard();
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
        std::initializer_list<std::remove_reference<
            decltype(byteEventMap)>::type::mapped_type::value_type>(
            {{offset, cb}}));
  } else {
    // Keep ByteEvents for the same stream sorted by offsets:
    auto pos = std::upper_bound(
        byteEventMapIt->second.begin(),
        byteEventMapIt->second.end(),
        offset,
        [&](uint64_t o, const ByteEventDetail& p) { return o < p.offset; });
    if (pos != byteEventMapIt->second.begin()) {
      auto matchingEvent = std::find_if(
          byteEventMapIt->second.begin(),
          pos,
          [offset, cb](const ByteEventDetail& p) {
            return ((p.offset == offset) && (p.callback == cb));
          });
      if (matchingEvent != pos) {
        // ByteEvent has been already registered for the same type, id,
        // offset and for the same recipient, return an INVALID_OPERATION
        // error to prevent duplicate registrations.
        return folly::makeUnexpected(LocalErrorCode::INVALID_OPERATION);
      }
    }
    byteEventMapIt->second.emplace(pos, offset, cb);
  }
  auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));

  // Notify recipients that the registration was successful.
  cb->onByteEventRegistered(ByteEvent{id, offset, type});

  // if the callback is already ready, we still insert, but schedule to
  // process
  Optional<uint64_t> maxOffsetReady;
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

      // This is scheduled to run in the future (during the next iteration of
      // the event loop). It is possible that the ByteEventDetail list gets
      // mutated between the time it was scheduled to now when we are ready to
      // run it. Look at the current outstanding ByteEvents for this stream ID
      // and confirm that our ByteEvent's offset and recipient callback are
      // still present.
      auto pos = std::find_if(
          streamByteEventCbIt->second.begin(),
          streamByteEventCbIt->second.end(),
          [offset, cb](const ByteEventDetail& p) {
            return ((p.offset == offset) && (p.callback == cb));
          });
      // if our byteEvent is not present, it must have been delivered already.
      if (pos == streamByteEventCbIt->second.end()) {
        return;
      }
      streamByteEventCbIt->second.erase(pos);

      cb->onByteEvent(ByteEvent{id, offset, type});
    });
  }
  return folly::unit;
}

bool QuicTransportBaseLite::good() const {
  return closeState_ == CloseState::OPEN && hasWriteCipher() && !error();
}

bool QuicTransportBaseLite::error() const {
  return conn_->localConnectionError.has_value();
}

uint64_t QuicTransportBaseLite::bufferSpaceAvailable() const {
  auto bytesBuffered = conn_->flowControlState.sumCurStreamBufferLen;
  auto totalBufferSpaceAvailable =
      conn_->transportSettings.totalBufferSpaceAvailable;
  return bytesBuffered > totalBufferSpaceAvailable
      ? 0
      : totalBufferSpaceAvailable - bytesBuffered;
}

void QuicTransportBaseLite::setConnectionSetupCallback(
    folly::MaybeManagedPtr<ConnectionSetupCallback> callback) {
  connSetupCallback_ = callback;
}

void QuicTransportBaseLite::setConnectionCallback(
    folly::MaybeManagedPtr<ConnectionCallback> callback) {
  connCallback_ = callback;
}

uint64_t QuicTransportBaseLite::maxWritableOnStream(
    const QuicStreamState& stream) const {
  auto connWritableBytes = maxWritableOnConn();
  auto streamFlowControlBytes = getSendStreamFlowControlBytesAPI(stream);
  return std::min(streamFlowControlBytes, connWritableBytes);
}

void QuicTransportBaseLite::processConnectionSetupCallbacks(
    QuicError&& cancelCode) {
  // connSetupCallback_ could be null if start() was never
  // invoked and the transport was destroyed or if the app initiated close.
  if (connSetupCallback_) {
    connSetupCallback_->onConnectionSetupError(std::move(cancelCode));
  }
}

void QuicTransportBaseLite::processConnectionCallbacks(QuicError&& cancelCode) {
  // connCallback_ could be null if start() was never
  // invoked and the transport was destroyed or if the app initiated close.
  if (!connCallback_) {
    return;
  }

  if (useConnectionEndWithErrorCallback_) {
    connCallback_->onConnectionEnd(cancelCode);
    return;
  }

  if (bool noError = processCancelCode(cancelCode)) {
    connCallback_->onConnectionEnd();
  } else {
    connCallback_->onConnectionError(std::move(cancelCode));
  }
}

QuicTransportBaseLite::ByteEventMap& QuicTransportBaseLite::getByteEventMap(
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

const QuicTransportBaseLite::ByteEventMap&
QuicTransportBaseLite::getByteEventMapConst(const ByteEvent::Type type) const {
  switch (type) {
    case ByteEvent::Type::ACK:
      return deliveryCallbacks_;
    case ByteEvent::Type::TX:
      return txCallbacks_;
  }
  LOG(FATAL) << "Unhandled case in getByteEventMapConst";
  folly::assume_unreachable();
}

void QuicTransportBaseLite::checkIdleTimer(TimePoint now) {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  if (!idleTimeout_.isTimerCallbackScheduled()) {
    return;
  }
  if (!idleTimeoutCheck_.lastTimeIdleTimeoutScheduled_.has_value()) {
    return;
  }
  if (idleTimeoutCheck_.forcedIdleTimeoutScheduled_) {
    return;
  }

  if ((now - *idleTimeoutCheck_.lastTimeIdleTimeoutScheduled_) >=
      idleTimeoutCheck_.idleTimeoutMs) {
    // Call timer expiration async.
    idleTimeoutCheck_.forcedIdleTimeoutScheduled_ = true;
    runOnEvbAsync([](auto self) {
      if (!self->good() || self->closeState_ == CloseState::CLOSED) {
        // The connection was probably closed.
        return;
      }
      self->idleTimeout_.timeoutExpired();
    });
  }
}

folly::Expected<QuicSocketLite::StreamTransportInfo, LocalErrorCode>
QuicTransportBaseLite::getStreamTransportInfo(StreamId id) const {
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
  auto packets = getNumPacketsTxWithNewData(*stream);
  return StreamTransportInfo{
      stream->totalHolbTime,
      stream->holbCount,
      bool(stream->lastHolbTime),
      packets,
      stream->streamLossCount,
      stream->finalWriteOffset,
      stream->finalReadOffset,
      stream->streamReadError,
      stream->streamWriteError};
}

const folly::SocketAddress& QuicTransportBaseLite::getPeerAddress() const {
  return conn_->peerAddress;
}

std::shared_ptr<QuicEventBase> QuicTransportBaseLite::getEventBase() const {
  return evb_;
}

Optional<std::string> QuicTransportBaseLite::getAppProtocol() const {
  return conn_->handshakeLayer->getApplicationProtocol();
}

uint64_t QuicTransportBaseLite::getConnectionBufferAvailable() const {
  return bufferSpaceAvailable();
}

folly::Expected<QuicSocketLite::FlowControlState, LocalErrorCode>
QuicTransportBaseLite::getStreamFlowControl(StreamId id) const {
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
  return QuicSocketLite::FlowControlState(
      getSendStreamFlowControlBytesAPI(*stream),
      stream->flowControlState.peerAdvertisedMaxOffset,
      getRecvStreamFlowControlBytes(*stream),
      stream->flowControlState.advertisedMaxOffset);
}

void QuicTransportBaseLite::runOnEvbAsync(
    folly::Function<void(std::shared_ptr<QuicTransportBaseLite>)> func) {
  auto evb = getEventBase();
  evb->runInLoop(
      [self = sharedGuard(), func = std::move(func), evb]() mutable {
        if (self->getEventBase() != evb) {
          // The eventbase changed between scheduling the loop and invoking
          // the callback, ignore this
          return;
        }
        func(std::move(self));
      },
      true);
}

void QuicTransportBaseLite::updateWriteLooper(
    bool thisIteration,
    bool runInline) {
  if (closeState_ == CloseState::CLOSED) {
    VLOG(10) << nodeToString(conn_->nodeType)
             << " stopping write looper because conn closed " << *this;
    writeLooper_->stop();
    return;
  }

  if (conn_->transportSettings.checkIdleTimerOnWrite) {
    checkIdleTimer(Clock::now());
    if (closeState_ == CloseState::CLOSED) {
      return;
    }
  }

  // If socket writable events are in use, do nothing if we are already waiting
  // for the write event.
  if (conn_->transportSettings.useSockWritableEvents &&
      socket_->isWritableCallbackSet()) {
    return;
  }

  auto writeDataReason = shouldWriteData(*conn_);
  if (writeDataReason != WriteDataReason::NO_WRITE) {
    VLOG(10) << nodeToString(conn_->nodeType)
             << " running write looper thisIteration=" << thisIteration << " "
             << *this;
    writeLooper_->run(thisIteration, runInline);
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

void QuicTransportBaseLite::updateReadLooper() {
  if (closeState_ != CloseState::OPEN) {
    VLOG(10) << "Stopping read looper " << *this;
    readLooper_->stop();
    return;
  }
  auto iter = std::find_if(
      conn_->streamManager->readableStreams().begin(),
      conn_->streamManager->readableStreams().end(),
      [&readCallbacks = readCallbacks_](StreamId s) {
        auto readCb = readCallbacks.find(s);
        if (readCb == readCallbacks.end()) {
          return false;
        }
        // TODO: if the stream has an error and it is also paused we should
        // still return an error
        return readCb->second.readCb && readCb->second.resumed;
      });
  if (iter != conn_->streamManager->readableStreams().end() ||
      !conn_->datagramState.readBuffer.empty()) {
    VLOG(10) << "Scheduling read looper " << *this;
    readLooper_->run();
  } else {
    VLOG(10) << "Stopping read looper " << *this;
    readLooper_->stop();
  }
}

void QuicTransportBaseLite::updatePeekLooper() {
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
      [&peekCallbacks = peekCallbacks_](StreamId s) {
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

void QuicTransportBaseLite::maybeStopWriteLooperAndArmSocketWritableEvent() {
  if (!socket_ || (closeState_ == CloseState::CLOSED)) {
    return;
  }
  if (conn_->transportSettings.useSockWritableEvents &&
      !socket_->isWritableCallbackSet()) {
    // Check if all data has been written and we're not limited by flow
    // control/congestion control.
    auto writeReason = shouldWriteData(*conn_);
    bool haveBufferToRetry = writeReason == WriteDataReason::BUFFERED_WRITE;
    bool haveNewDataToWrite =
        (writeReason != WriteDataReason::NO_WRITE) && !haveBufferToRetry;
    bool haveCongestionControlWindow = true;
    if (conn_->congestionController) {
      haveCongestionControlWindow =
          conn_->congestionController->getWritableBytes() > 0;
    }
    bool haveFlowControlWindow = getSendConnFlowControlBytesAPI(*conn_) > 0;
    bool connHasWriteWindow =
        haveCongestionControlWindow && haveFlowControlWindow;
    if (haveBufferToRetry || (haveNewDataToWrite && connHasWriteWindow)) {
      // Re-arm the write event and stop the write
      // looper.
      socket_->resumeWrite(this);
      writeLooper_->stop();
    }
  }
}

void QuicTransportBaseLite::writeSocketDataAndCatch() {
  [[maybe_unused]] auto self = sharedGuard();
  try {
    writeSocketData();
    processCallbacksAfterWriteData();
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()),
        std::string("writeSocketDataAndCatch()  error")));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()),
        std::string("writeSocketDataAndCatch()  error")));
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " error=" << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("writeSocketDataAndCatch()  error")));
  }
}

void QuicTransportBaseLite::pacedWriteDataToSocket() {
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    self->maybeStopWriteLooperAndArmSocketWritableEvent();
  };

  if (!isConnectionPaced(*conn_)) {
    // Not paced and connection is still open, normal write. Even if pacing is
    // previously enabled and then gets disabled, and we are here due to a
    // timeout, we should do a normal write to flush out the residue from
    // pacing write.
    writeSocketDataAndCatch();

    if (conn_->transportSettings.scheduleTimerForExcessWrites) {
      // If we still have data to write, yield the event loop now but schedule a
      // timeout to come around and write again as soon as possible.
      auto writeDataReason = shouldWriteData(*conn_);
      if (writeDataReason != WriteDataReason::NO_WRITE &&
          !excessWriteTimeout_.isTimerCallbackScheduled()) {
        scheduleTimeout(&excessWriteTimeout_, 0ms);
      }
    }
    return;
  }

  // We are in the middle of a pacing interval. Leave it be.
  if (writeLooper_->isPacingScheduled()) {
    // The next burst is already scheduled. Since the burst size doesn't
    // depend on much data we currently have in buffer at all, no need to
    // change anything.
    return;
  }

  // Do a burst write before waiting for an interval. This will also call
  // updateWriteLooper, but inside FunctionLooper we will ignore that.
  writeSocketDataAndCatch();
}

void QuicTransportBaseLite::writeSocketData() {
  if (socket_) {
    ++(conn_->writeCount); // incremented on each write (or write attempt)

    // record current number of sent packets to detect delta
    const auto beforeTotalBytesSent = conn_->lossState.totalBytesSent;
    const auto beforeTotalPacketsSent = conn_->lossState.totalPacketsSent;
    const auto beforeTotalAckElicitingPacketsSent =
        conn_->lossState.totalAckElicitingPacketsSent;
    const auto beforeNumOutstandingPackets =
        conn_->outstandings.numOutstanding();

    updatePacketProcessorsPrewriteRequests();

    // if we're starting to write from app limited, notify observers
    if (conn_->appLimitedTracker.isAppLimited() &&
        conn_->congestionController) {
      conn_->appLimitedTracker.setNotAppLimited();
      notifyStartWritingFromAppRateLimited();
    }
    writeData();
    if (closeState_ != CloseState::CLOSED) {
      if (conn_->pendingEvents.closeTransport == true) {
        throw QuicTransportException(
            "Max packet number reached",
            TransportErrorCode::PROTOCOL_VIOLATION);
      }
      setLossDetectionAlarm(*conn_, *this);

      // check for change in number of packets
      const auto afterTotalBytesSent = conn_->lossState.totalBytesSent;
      const auto afterTotalPacketsSent = conn_->lossState.totalPacketsSent;
      const auto afterTotalAckElicitingPacketsSent =
          conn_->lossState.totalAckElicitingPacketsSent;
      const auto afterNumOutstandingPackets =
          conn_->outstandings.numOutstanding();
      CHECK_LE(beforeTotalPacketsSent, afterTotalPacketsSent);
      CHECK_LE(
          beforeTotalAckElicitingPacketsSent,
          afterTotalAckElicitingPacketsSent);
      CHECK_LE(beforeNumOutstandingPackets, afterNumOutstandingPackets);
      CHECK_EQ(
          afterNumOutstandingPackets - beforeNumOutstandingPackets,
          afterTotalAckElicitingPacketsSent -
              beforeTotalAckElicitingPacketsSent);
      const bool newPackets = (afterTotalPacketsSent > beforeTotalPacketsSent);
      const bool newOutstandingPackets =
          (afterTotalAckElicitingPacketsSent >
           beforeTotalAckElicitingPacketsSent);

      // if packets sent, notify observers
      if (newPackets) {
        notifyPacketsWritten(
            afterTotalPacketsSent - beforeTotalPacketsSent
            /* numPacketsWritten */,
            afterTotalAckElicitingPacketsSent -
                beforeTotalAckElicitingPacketsSent
            /* numAckElicitingPacketsWritten */,
            afterTotalBytesSent - beforeTotalBytesSent /* numBytesWritten */);
      }
      if (conn_->loopDetectorCallback && newOutstandingPackets) {
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
      // packet after quiescence or after receiving a new packet.
      if (newOutstandingPackets &&
          (beforeNumOutstandingPackets == 0 ||
           conn_->receivedNewPacketBeforeWrite)) {
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
        // notify via connection call and any observer callbacks
        if (transportReadyNotified_ && connCallback_) {
          connCallback_->onAppRateLimited();
        }
        conn_->appLimitedTracker.setAppLimited();
        notifyAppRateLimited();
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

void QuicTransportBaseLite::cancelTimeout(QuicTimerCallback* callback) {
  callback->cancelTimerCallback();
}

void QuicTransportBaseLite::excessWriteTimeoutExpired() noexcept {
  auto writeDataReason = shouldWriteData(*conn_);
  if (writeDataReason != WriteDataReason::NO_WRITE) {
    pacedWriteDataToSocket();
  }
}

void QuicTransportBaseLite::lossTimeoutExpired() noexcept {
  CHECK_NE(closeState_, CloseState::CLOSED);
  // onLossDetectionAlarm will set packetToSend in pending events
  [[maybe_unused]] auto self = sharedGuard();
  try {
    onLossDetectionAlarm(*conn_, markPacketLoss);
    if (conn_->qLogger) {
      conn_->qLogger->addTransportStateUpdate(kLossTimeoutExpired);
    }
    pacedWriteDataToSocket();
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()),
        std::string("lossTimeoutExpired() error")));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()),
        std::string("lossTimeoutExpired() error")));
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << "  " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("lossTimeoutExpired() error")));
  }
}

void QuicTransportBaseLite::idleTimeoutExpired(bool drain) noexcept {
  VLOG(4) << __func__ << " " << *this;
  [[maybe_unused]] auto self = sharedGuard();
  // idle timeout is expired, just close the connection and drain or
  // send connection close immediately depending on 'drain'
  DCHECK_NE(closeState_, CloseState::CLOSED);
  uint64_t numOpenStreans = conn_->streamManager->streamCount();
  auto localError =
      drain ? LocalErrorCode::IDLE_TIMEOUT : LocalErrorCode::SHUTTING_DOWN;
  closeImpl(
      quic::QuicError(
          QuicErrorCode(localError),
          folly::to<std::string>(
              toString(localError),
              ", num non control streams: ",
              numOpenStreans - conn_->streamManager->numControlStreams())),
      drain /* drainConnection */,
      !drain /* sendCloseImmediately */);
}

void QuicTransportBaseLite::keepaliveTimeoutExpired() noexcept {
  [[maybe_unused]] auto self = sharedGuard();
  conn_->pendingEvents.sendPing = true;
  updateWriteLooper(true, conn_->transportSettings.inlineWriteAfterRead);
}

bool QuicTransportBaseLite::processCancelCode(const QuicError& cancelCode) {
  bool noError = false;
  switch (cancelCode.code.type()) {
    case QuicErrorCode::Type::LocalErrorCode: {
      LocalErrorCode localErrorCode = *cancelCode.code.asLocalErrorCode();
      noError = localErrorCode == LocalErrorCode::NO_ERROR ||
          localErrorCode == LocalErrorCode::IDLE_TIMEOUT ||
          localErrorCode == LocalErrorCode::SHUTTING_DOWN;
      break;
    }
    case QuicErrorCode::Type::TransportErrorCode: {
      TransportErrorCode transportErrorCode =
          *cancelCode.code.asTransportErrorCode();
      noError = transportErrorCode == TransportErrorCode::NO_ERROR;
      break;
    }
    case QuicErrorCode::Type::ApplicationErrorCode:
      auto appErrorCode = *cancelCode.code.asApplicationErrorCode();
      noError = appErrorCode == APP_NO_ERROR;
  }
  return noError;
}

uint64_t QuicTransportBaseLite::maxWritableOnConn() const {
  auto connWritableBytes = getSendConnFlowControlBytesAPI(*conn_);
  auto availableBufferSpace = bufferSpaceAvailable();
  uint64_t ret = std::min(connWritableBytes, availableBufferSpace);
  uint8_t multiplier = conn_->transportSettings.backpressureHeadroomFactor;
  if (multiplier > 0) {
    auto headRoom = multiplier * congestionControlWritableBytes(*conn_);
    auto bufferLen = conn_->flowControlState.sumCurStreamBufferLen;
    headRoom -= bufferLen > headRoom ? headRoom : bufferLen;
    ret = std::min(ret, headRoom);
  }
  return ret;
}

void QuicTransportBaseLite::scheduleTimeout(
    QuicTimerCallback* callback,
    std::chrono::milliseconds timeout) {
  if (evb_) {
    evb_->scheduleTimeout(callback, timeout);
  }
}

void QuicTransportBaseLite::scheduleLossTimeout(
    std::chrono::milliseconds timeout) {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  timeout = timeMax(timeout, evb_->getTimerTickInterval());
  scheduleTimeout(&lossTimeout_, timeout);
}

void QuicTransportBaseLite::cancelLossTimeout() {
  cancelTimeout(&lossTimeout_);
}

bool QuicTransportBaseLite::isLossTimeoutScheduled() {
  return isTimeoutScheduled(&lossTimeout_);
}

bool QuicTransportBaseLite::isTimeoutScheduled(
    QuicTimerCallback* callback) const {
  return callback->isTimerCallbackScheduled();
}

void QuicTransportBaseLite::invokeReadDataAndCallbacks() {
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
      // Stream doesn't have a read callback set, skip it.
      continue;
    }
    auto readCb = callback->second.readCb;
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));
    if (readCb && stream->streamReadError) {
      self->conn_->streamManager->readableStreams().erase(streamId);
      readCallbacks_.erase(callback);
      // if there is an error on the stream - it's not readable anymore, so
      // we cannot peek into it as well.
      self->conn_->streamManager->peekableStreams().erase(streamId);
      peekCallbacks_.erase(streamId);
      VLOG(10) << "invoking read error callbacks on stream=" << streamId << " "
               << *this;
      if (!stream->groupId) {
        readCb->readError(streamId, QuicError(*stream->streamReadError));
      } else {
        readCb->readErrorWithGroup(
            streamId, *stream->groupId, QuicError(*stream->streamReadError));
      }
    } else if (
        readCb && callback->second.resumed && stream->hasReadableData()) {
      VLOG(10) << "invoking read callbacks on stream=" << streamId << " "
               << *this;
      if (!stream->groupId) {
        readCb->readAvailable(streamId);
      } else {
        readCb->readAvailableWithGroup(streamId, *stream->groupId);
      }
    }
  }
  if (self->datagramCallback_ && !conn_->datagramState.readBuffer.empty()) {
    self->datagramCallback_->onDatagramsAvailable();
  }
}

void QuicTransportBaseLite::invokePeekDataAndCallbacks() {
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
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));
    if (peekCb && stream->streamReadError) {
      VLOG(10) << "invoking peek error callbacks on stream=" << streamId << " "
               << *this;
      peekCb->peekError(streamId, QuicError(*stream->streamReadError));
    } else if (
        peekCb && !stream->streamReadError && stream->hasPeekableData()) {
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

void QuicTransportBaseLite::processCallbacksAfterWriteData() {
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  auto txStreamId = conn_->streamManager->popTx();
  while (txStreamId.has_value()) {
    auto streamId = *txStreamId;
    auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(streamId));
    auto largestOffsetTxed = getLargestWriteOffsetTxed(*stream);
    // if it's in the set of streams with TX, we should have a valid offset
    CHECK(largestOffsetTxed.has_value());

    // lambda to help get the next callback to call for this stream
    auto getNextTxCallbackForStreamAndCleanup =
        [this, &largestOffsetTxed](
            const auto& streamId) -> Optional<ByteEventDetail> {
      auto txCallbacksForStreamIt = txCallbacks_.find(streamId);
      if (txCallbacksForStreamIt == txCallbacks_.end() ||
          txCallbacksForStreamIt->second.empty()) {
        return none;
      }

      auto& txCallbacksForStream = txCallbacksForStreamIt->second;
      if (txCallbacksForStream.front().offset > *largestOffsetTxed) {
        return none;
      }

      // extract the callback, pop from the queue, then check for cleanup
      auto result = txCallbacksForStream.front();
      txCallbacksForStream.pop_front();
      if (txCallbacksForStream.empty()) {
        txCallbacks_.erase(txCallbacksForStreamIt);
      }
      return result;
    };

    Optional<ByteEventDetail> nextOffsetAndCallback;
    while (
        (nextOffsetAndCallback =
             getNextTxCallbackForStreamAndCleanup(streamId))) {
      ByteEvent byteEvent{
          streamId, nextOffsetAndCallback->offset, ByteEvent::Type::TX};
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

void QuicTransportBaseLite::setIdleTimer() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  cancelTimeout(&idleTimeout_);
  cancelTimeout(&keepaliveTimeout_);
  auto localIdleTimeout = conn_->transportSettings.idleTimeout;
  // The local idle timeout being zero means it is disabled.
  if (localIdleTimeout == 0ms) {
    return;
  }
  auto peerIdleTimeout =
      conn_->peerIdleTimeout > 0ms ? conn_->peerIdleTimeout : localIdleTimeout;
  auto idleTimeout = timeMin(localIdleTimeout, peerIdleTimeout);

  idleTimeoutCheck_.idleTimeoutMs = idleTimeout;
  idleTimeoutCheck_.lastTimeIdleTimeoutScheduled_ = Clock::now();

  scheduleTimeout(&idleTimeout_, idleTimeout);
  auto idleTimeoutCount = idleTimeout.count();
  if (conn_->transportSettings.enableKeepalive) {
    std::chrono::milliseconds keepaliveTimeout = std::chrono::milliseconds(
        idleTimeoutCount - static_cast<int64_t>(idleTimeoutCount * .15));
    scheduleTimeout(&keepaliveTimeout_, keepaliveTimeout);
  }
}

void QuicTransportBaseLite::updatePacketProcessorsPrewriteRequests() {
  folly::SocketCmsgMap cmsgs;
  for (const auto& pp : conn_->packetProcessors) {
    // In case of overlapping cmsg keys, the priority is given to
    // that were added to the QuicSocket first.
    auto writeRequest = pp->prewrite();
    if (writeRequest && writeRequest->cmsgs) {
      cmsgs.insert(writeRequest->cmsgs->begin(), writeRequest->cmsgs->end());
    }
  }
  if (!cmsgs.empty()) {
    conn_->socketCmsgsState.additionalCmsgs = cmsgs;
  } else {
    conn_->socketCmsgsState.additionalCmsgs.reset();
  }
  conn_->socketCmsgsState.targetWriteCount = conn_->writeCount;
}

void QuicTransportBaseLite::describe(std::ostream& os) const {
  CHECK(conn_);
  os << *conn_;
}

std::ostream& operator<<(std::ostream& os, const QuicTransportBaseLite& qt) {
  qt.describe(os);
  return os;
}

} // namespace quic
