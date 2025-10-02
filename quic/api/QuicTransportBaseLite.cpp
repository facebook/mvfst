/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicTransportBaseLite.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/EcnL4sTracker.h>
#include <quic/congestion_control/TokenlessPacer.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <sstream>

namespace {
constexpr auto APP_NO_ERROR = quic::GenericApplicationErrorCode::NO_ERROR;

quic::QuicError maybeSetGenericAppError(
    quic::Optional<quic::QuicError>&& error) {
  return std::move(error).value_or(
      quic::QuicError{APP_NO_ERROR, quic::toString(APP_NO_ERROR)});
}
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

QuicTransportBaseLite::QuicTransportBaseLite(
    std::shared_ptr<QuicEventBase> evb,
    std::unique_ptr<QuicAsyncUDPSocket> socket,
    bool useConnectionEndWithErrorCallback)
    : evb_(std::move(evb)),
      socket_(std::move(socket)),
      useConnectionEndWithErrorCallback_(useConnectionEndWithErrorCallback),
      lossTimeout_(this),
      excessWriteTimeout_(this),
      idleTimeout_(this),
      keepaliveTimeout_(this),
      ackTimeout_(this),
      pathValidationTimeout_(this),
      drainTimeout_(this),
      pingTimeout_(this),
      writeLooper_(new FunctionLooper(
          evb_,
          [this]() { pacedWriteDataToSocket(); },
          LooperType::WriteLooper)),
      readLooper_(new FunctionLooper(
          evb_,
          [this]() { invokeReadDataAndCallbacks(true); },
          LooperType::ReadLooper)),
      peekLooper_(new FunctionLooper(
          evb_,
          [this]() { invokePeekDataAndCallbacks(); },
          LooperType::PeekLooper)) {}

void QuicTransportBaseLite::onNetworkData(
    const folly::SocketAddress& localAddress,
    NetworkData&& networkData,
    const folly::SocketAddress& peerAddress) noexcept {
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    if (!conn_->transportSettings.networkDataPerSocketRead) {
      checkForClosedStream();
      updateReadLooper();
      updatePeekLooper();
      updateWriteLooper(true);
    }
  };
  try {
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
    for (auto& packet : packets) {
      auto res = onReadData(localAddress, std::move(packet), peerAddress);
      if (!res.has_value()) {
        VLOG(4) << __func__ << " " << res.error().message << " " << *this;
        exceptionCloseWhat_ = res.error().message;
        return closeImpl(res.error());
      }
      if (conn_->peerConnectionError) {
        closeImpl(QuicError(
            QuicErrorCode(TransportErrorCode::NO_ERROR), "Peer closed"));
        return;
      } else if (conn_->transportSettings.processCallbacksPerPacket) {
        invokeReadDataAndCallbacks(false);
      }
    }

    if (!conn_->transportSettings.networkDataPerSocketRead) {
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
      auto ecnResult = validateECNState();
      if (!ecnResult.has_value()) {
        VLOG(4) << __func__ << " " << ecnResult.error().message << " " << *this;
        exceptionCloseWhat_ = ecnResult.error().message;
        closeImpl(ecnResult.error());
      }
    } else {
      // In the closed state, we would want to write a close if possible
      // however the write looper will not be set.
      auto result = writeSocketData();
      if (!result.has_value()) {
        VLOG(4) << __func__ << " " << result.error().message << " " << *this;
        exceptionCloseWhat_ = result.error().message;
        closeImpl(result.error());
      }
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

void QuicTransportBaseLite::close(Optional<QuicError> errorCode) {
  [[maybe_unused]] auto self = sharedGuard();
  // The caller probably doesn't need a conn callback any more because they
  // explicitly called close.
  resetConnectionCallbacks();

  // If we were called with no error code, ensure that we are going to write
  // an application close, so the peer knows it didn't come from the transport.
  errorCode = maybeSetGenericAppError(std::move(errorCode));
  closeImpl(std::move(errorCode), true);
}

void QuicTransportBaseLite::closeNow(Optional<QuicError> errorCode) {
  DCHECK(getEventBase() && getEventBase()->isInEventBaseThread());
  [[maybe_unused]] auto self = sharedGuard();
  VLOG(4) << __func__ << " " << *this;
  errorCode = maybeSetGenericAppError(std::move(errorCode));
  closeImpl(std::move(errorCode), false);
  // the drain timeout may have been scheduled by a previous close, in which
  // case, our close would not take effect. This cancels the drain timeout in
  // this case and expires the timeout.
  if (isTimeoutScheduled(&drainTimeout_)) {
    cancelTimeout(&drainTimeout_);
    drainTimeoutExpired();
  }
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::stopSending(
    StreamId id,
    ApplicationErrorCode error) {
  if (isSendingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto* stream = conn_->streamManager->getStream(id).value_or(nullptr);
  CHECK(stream) << "Invalid stream in " << __func__ << ": " << id;
  if (stream->recvState == StreamRecvState::Closed) {
    // skip STOP_SENDING if ingress is already closed
    return {};
  }

  if (conn_->transportSettings.dropIngressOnStopSending) {
    processTxStopSending(*stream);
  }
  // send STOP_SENDING frame to peer
  sendSimpleFrame(*conn_, StopSendingFrame(id, error));
  updateWriteLooper(true);
  return {};
}

quic::Expected<StreamId, LocalErrorCode>
QuicTransportBaseLite::createBidirectionalStream(bool /*replaySafe*/) {
  return createStreamInternal(true);
}

quic::Expected<StreamId, LocalErrorCode>
QuicTransportBaseLite::createUnidirectionalStream(bool /*replaySafe*/) {
  return createStreamInternal(false);
}

uint64_t QuicTransportBaseLite::getNumOpenableBidirectionalStreams() const {
  return conn_->streamManager->openableLocalBidirectionalStreams();
}

uint64_t QuicTransportBaseLite::getNumOpenableUnidirectionalStreams() const {
  return conn_->streamManager->openableLocalUnidirectionalStreams();
}

bool QuicTransportBaseLite::isUnidirectionalStream(StreamId stream) noexcept {
  return quic::isUnidirectionalStream(stream);
}

bool QuicTransportBaseLite::isBidirectionalStream(StreamId stream) noexcept {
  return quic::isBidirectionalStream(stream);
}

QuicSocketLite::WriteResult QuicTransportBaseLite::writeChain(
    StreamId id,
    BufPtr data,
    bool eof,
    ByteEventCallback* cb) {
  if (conn_->version == QuicVersion::MVFST_PRIMING &&
      isBidirectionalStream(id)) {
    // Once data is available to write on a stream,
    // the Priming connection can be closed
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::NO_ERROR),
        std::string("no error: priming connection closed")));
    return quic::make_unexpected(LocalErrorCode::NO_ERROR);
  }

  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  try {
    // Check whether stream exists before calling getStream to avoid
    // creating a peer stream if it does not exist yet.
    if (!conn_->streamManager->streamExists(id)) {
      return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    auto stream = conn_->streamManager->getStream(id).value_or(nullptr);
    CHECK(stream) << "Invalid stream in " << __func__ << ": " << id;
    if (!stream->writable()) {
      return quic::make_unexpected(LocalErrorCode::STREAM_CLOSED);
    }
    // Register DeliveryCallback for the data + eof offset.
    if (cb) {
      auto dataLength =
          (data ? data->computeChainDataLength() : 0) + (eof ? 1 : 0);
      if (dataLength) {
        auto currentLargestWriteOffset = getLargestWriteOffsetSeen(*stream);
        auto deliveryResult = registerDeliveryCallback(
            id, currentLargestWriteOffset + dataLength - 1, cb);
        if (!deliveryResult.has_value()) {
          VLOG(4) << "Failed to register delivery callback: "
                  << toString(deliveryResult.error());
          exceptionCloseWhat_ = "Failed to register delivery callback";
          closeImpl(QuicError(
              deliveryResult.error(),
              std::string("registerDeliveryCallback() error")));
          return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
        }
      }
    }
    bool wasAppLimitedOrIdle = false;
    if (conn_->congestionController) {
      wasAppLimitedOrIdle = conn_->congestionController->isAppLimited();
      wasAppLimitedOrIdle |= conn_->streamManager->isAppIdle();
    }
    auto result = writeDataToQuicStream(*stream, std::move(data), eof);
    if (!result.has_value()) {
      VLOG(4) << __func__ << " streamId=" << id << " " << result.error().message
              << " " << *this;
      exceptionCloseWhat_ = result.error().message;
      closeImpl(
          QuicError(result.error().code, std::string("writeChain() error")));
      return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
    }
    // If we were previously app limited restart pacing with the current rate.
    if (wasAppLimitedOrIdle && conn_->pacer) {
      conn_->pacer->reset();
    }
    updateWriteLooper(true);
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("writeChain() error")));
    return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("writeChain() error")));
    return quic::make_unexpected(ex.errorCode());
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("writeChain() error")));
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }
  return {};
}

Optional<LocalErrorCode> QuicTransportBaseLite::shutdownWrite(StreamId id) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return LocalErrorCode::INVALID_OPERATION;
  }
  return std::nullopt;
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::registerDeliveryCallback(
    StreamId id,
    uint64_t offset,
    ByteEventCallback* cb) {
  return registerByteEventCallback(ByteEvent::Type::ACK, id, offset, cb);
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::notifyPendingWriteOnConnection(
    ConnectionWriteCallback* wcb) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (connWriteCallback_ != nullptr) {
    return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_CALLBACK);
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
  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::unregisterStreamWriteCallback(StreamId id) {
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (pendingWriteCallbacks_.find(id) == pendingWriteCallbacks_.end()) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  pendingWriteCallbacks_.erase(id);
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::resetStream(
    StreamId id,
    ApplicationErrorCode errorCode) {
  return resetStreamInternal(id, errorCode, false /* reliable */);
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::updateReliableDeliveryCheckpoint(StreamId id) {
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream =
      CHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));
  if (stream->sendState == StreamSendState::ResetSent) {
    // We already sent a reset, so there's really no reason why we should be
    // doing any more checkpointing, especially since we cannot
    // increase the reliable size in subsequent resets.
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  stream->reliableResetCheckpoint =
      stream->currentWriteOffset + stream->pendingWrites.chainLength();
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::resetStreamReliably(
    StreamId id,
    ApplicationErrorCode errorCode) {
  if (!conn_->transportSettings.advertisedReliableResetStreamSupport ||
      !conn_->peerAdvertisedReliableStreamResetSupport) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  return resetStreamInternal(id, errorCode, true /* reliable */);
}

void QuicTransportBaseLite::cancelDeliveryCallbacksForStream(StreamId id) {
  cancelByteEventCallbacksForStream(ByteEvent::Type::ACK, id);
}

void QuicTransportBaseLite::cancelDeliveryCallbacksForStream(
    StreamId id,
    uint64_t offset) {
  cancelByteEventCallbacksForStream(ByteEvent::Type::ACK, id, offset);
}

void QuicTransportBaseLite::cancelByteEventCallbacksForStream(
    const StreamId id,
    const Optional<uint64_t>& offsetUpperBound) {
  invokeForEachByteEventType(
      ([this, id, &offsetUpperBound](const ByteEvent::Type type) {
        cancelByteEventCallbacksForStream(type, id, offsetUpperBound);
      }));
}

void QuicTransportBaseLite::cancelByteEventCallbacksForStream(
    const ByteEvent::Type type,
    const StreamId id,
    const Optional<uint64_t>& offsetUpperBound) {
  cancelByteEventCallbacksForStreamInternal(
      type, id, [&offsetUpperBound](uint64_t cbOffset) {
        return !offsetUpperBound || cbOffset < *offsetUpperBound;
      });
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::notifyPendingWriteOnStream(
    StreamId id,
    StreamWriteCallback* wcb) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = conn_->streamManager->getStream(id).value_or(nullptr);
  CHECK(stream) << "Invalid stream in " << __func__ << ": " << id;
  if (!stream->writable()) {
    return quic::make_unexpected(LocalErrorCode::STREAM_CLOSED);
  }

  if (wcb == nullptr) {
    return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_CALLBACK);
  }
  // Add the callback to the pending write callbacks so that if we are closed
  // while we are scheduled in the loop, the close will error out the
  // callbacks.
  auto wcbEmplaceResult = pendingWriteCallbacks_.emplace(id, wcb);
  if (!wcbEmplaceResult.second) {
    if ((wcbEmplaceResult.first)->second != wcb) {
      return quic::make_unexpected(LocalErrorCode::INVALID_WRITE_CALLBACK);
    } else {
      return quic::make_unexpected(LocalErrorCode::CALLBACK_ALREADY_INSTALLED);
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
    auto stream = CHECK_NOTNULL(
        self->conn_->streamManager->getStream(id).value_or(nullptr));
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
  return {};
}

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::registerByteEventCallback(
    const ByteEvent::Type type,
    const StreamId id,
    const uint64_t offset,
    ByteEventCallback* cb) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  if (!cb) {
    return {};
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
        return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
      }
    }
    byteEventMapIt->second.emplace(pos, offset, cb);
  }
  auto stream = conn_->streamManager->getStream(id).value_or(nullptr);
  CHECK(stream) << "Invalid stream in " << __func__ << ": " << id;

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
  return {};
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
  if (connCallback_) {
    runOnEvbAsync([](auto self) { self->processCallbacksAfterNetworkData(); });
  }
}

void QuicTransportBaseLite::setConnectionCallbackFromCtor(
    folly::MaybeManagedPtr<ConnectionCallback> callback) {
  connCallback_ = callback;
}

Optional<LocalErrorCode> QuicTransportBaseLite::setControlStream(StreamId id) {
  if (!conn_->streamManager->streamExists(id)) {
    return LocalErrorCode::STREAM_NOT_EXISTS;
  }
  auto stream = conn_->streamManager->getStream(id).value_or(nullptr);
  CHECK(stream) << "Invalid stream in " << __func__ << ": " << id;
  conn_->streamManager->setStreamAsControl(*stream);
  return std::nullopt;
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setReadCallback(
    StreamId id,
    ReadCallback* cb,
    Optional<ApplicationErrorCode> err) {
  if (isSendingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (cb != nullptr && closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  return setReadCallbackInternal(id, cb, err);
}

quic::Expected<std::pair<BufPtr, bool>, LocalErrorCode>
QuicTransportBaseLite::read(StreamId id, size_t maxLen) {
  if (isSendingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  [[maybe_unused]] auto self = sharedGuard();
  SCOPE_EXIT {
    updateReadLooper();
    updatePeekLooper(); // read can affect "peek" API
    updateWriteLooper(true);
  };
  try {
    if (!conn_->streamManager->streamExists(id)) {
      return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    auto stream = conn_->streamManager->getStream(id).value_or(nullptr);
    CHECK(stream) << "Invalid stream in " << __func__ << ": " << id;
    auto readResult = readDataFromQuicStream(*stream, maxLen);
    if (!readResult.has_value()) {
      VLOG(4) << "read() error " << readResult.error().message << " " << *this;
      exceptionCloseWhat_ = readResult.error().message;
      closeImpl(QuicError(
          QuicErrorCode(readResult.error().code), std::string("read() error")));
      return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
    }
    auto result = std::move(readResult.value());
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
    return quic::Expected<std::pair<BufPtr, bool>, LocalErrorCode>(
        std::move(result));
  } catch (const QuicTransportException& ex) {
    VLOG(4) << "read() error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(
        QuicError(QuicErrorCode(ex.errorCode()), std::string("read() error")));
    return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(
        QuicError(QuicErrorCode(ex.errorCode()), std::string("read() error")));
    return quic::make_unexpected(ex.errorCode());
  } catch (const std::exception& ex) {
    VLOG(4) << "read()  error " << ex.what() << " " << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("read() error")));
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }
}

void QuicTransportBaseLite::setQLogger(std::shared_ptr<QLogger> qLogger) {
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

const std::shared_ptr<QLogger> QuicTransportBaseLite::getQLogger() const {
  return conn_->qLogger;
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setPriorityQueue(
    std::unique_ptr<PriorityQueue> queue) {
  if (conn_) {
    return conn_->streamManager->setPriorityQueue(std::move(queue));
  }
  return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setStreamPriority(
    StreamId id,
    PriorityQueue::Priority priority) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (!conn_->streamManager->streamExists(id)) {
    // It's not an error to try to prioritize a non-existent stream.
    return {};
  }
  // It's not an error to prioritize a stream after it's sent its FIN - this
  // can reprioritize retransmissions.
  conn_->streamManager->setStreamPriority(
      id,
      priority,
      getSendConnFlowControlBytesWire(*conn_) > 0,
      conn_->qLogger);
  return {};
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setMaxPacingRate(
    uint64_t maxRateBytesPerSec) {
  if (conn_->pacer) {
    conn_->pacer->setMaxPacingRate(maxRateBytesPerSec);
    return {};
  } else {
    LOG(WARNING)
        << "Cannot set max pacing rate without a pacer. Pacing Enabled = "
        << conn_->transportSettings.pacingEnabled;
    return quic::make_unexpected(LocalErrorCode::PACER_NOT_AVAILABLE);
  }
}

void QuicTransportBaseLite::setThrottlingSignalProvider(
    std::shared_ptr<ThrottlingSignalProvider> throttlingSignalProvider) {
  DCHECK(conn_);
  conn_->throttlingSignalProvider = throttlingSignalProvider;
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

  if (processCancelCode(cancelCode)) {
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

quic::Expected<QuicSocketLite::StreamTransportInfo, LocalErrorCode>
QuicTransportBaseLite::getStreamTransportInfo(StreamId id) const {
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = conn_->streamManager->getStream(id).value_or(nullptr);
  CHECK(stream) << "Invalid stream in " << __func__ << ": " << id;
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

const folly::SocketAddress& QuicTransportBaseLite::getOriginalPeerAddress()
    const {
  return conn_->originalPeerAddress;
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

quic::Expected<QuicSocketLite::FlowControlState, LocalErrorCode>
QuicTransportBaseLite::getStreamFlowControl(StreamId id) const {
  if (!conn_->streamManager->streamExists(id)) {
    return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = conn_->streamManager->getStream(id).value_or(nullptr);
  CHECK(stream) << "Invalid stream in " << __func__ << ": " << id;
  return QuicSocketLite::FlowControlState(
      getSendStreamFlowControlBytesAPI(*stream),
      stream->flowControlState.peerAdvertisedMaxOffset,
      getRecvStreamFlowControlBytes(*stream),
      stream->flowControlState.advertisedMaxOffset);
}

void QuicTransportBaseLite::runOnEvbAsync(
    std::function<void(std::shared_ptr<QuicTransportBaseLite>)> func) {
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

void QuicTransportBaseLite::updateWriteLooper(bool thisIteration) {
  if (conn_->version == QuicVersion::MVFST_PRIMING) {
    writeLooper_->stop();
    return;
  }
  if (closeState_ == CloseState::CLOSED) {
    VLOG(10) << nodeToString(conn_->nodeType)
             << " stopping write looper because conn closed " << *this;
    writeLooper_->stop();
    return;
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

void QuicTransportBaseLite::updateReadLooper() {
  if (closeState_ != CloseState::OPEN) {
    VLOG(10) << "Stopping read looper " << *this;
    readLooper_->stop();
    return;
  }
  auto matcherFn = [&readCallbacks = readCallbacks_](StreamId s) {
    auto readCb = readCallbacks.find(s);
    if (readCb == readCallbacks.end()) {
      return false;
    }
    // TODO: if the stream has an error and it is also paused we should
    // still return an error
    return readCb->second.readCb && readCb->second.resumed;
  };
  auto iter = std::find_if(
      conn_->streamManager->readableStreams().begin(),
      conn_->streamManager->readableStreams().end(),
      matcherFn);
  auto unidirIter = std::find_if(
      conn_->streamManager->readableUnidirectionalStreams().begin(),
      conn_->streamManager->readableUnidirectionalStreams().end(),
      matcherFn);
  if (iter != conn_->streamManager->readableStreams().end() ||
      unidirIter !=
          conn_->streamManager->readableUnidirectionalStreams().end() ||
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
      auto resumeResult = socket_->resumeWrite(this);
      if (!resumeResult.has_value()) {
        exceptionCloseWhat_ = resumeResult.error().message;
        closeImpl(QuicError(
            resumeResult.error().code,
            std::string(
                "maybeStopWriteLooperAndArmSocketWritableEvent() error")));
        return;
      }
      writeLooper_->stop();
    }
  }
}

void QuicTransportBaseLite::checkForClosedStream() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  auto itr = conn_->streamManager->closedStreams().begin();
  while (itr != conn_->streamManager->closedStreams().end()) {
    const auto& streamId = *itr;

    if (getSocketObserverContainer() &&
        getSocketObserverContainer()
            ->hasObserversForEvent<
                SocketObserverInterface::Events::streamEvents>()) {
      getSocketObserverContainer()
          ->invokeInterfaceMethod<
              SocketObserverInterface::Events::streamEvents>(
              [event = SocketObserverInterface::StreamCloseEvent(
                   streamId,
                   getStreamInitiator(streamId),
                   getStreamDirectionality(streamId))](
                  auto observer, auto observed) {
                observer->streamClosed(observed, event);
              });
    }

    // We may be in an active read cb when we close the stream
    auto readCbIt = readCallbacks_.find(*itr);
    // We use the read callback as a way to defer destruction of the stream.
    if (readCbIt != readCallbacks_.end() &&
        readCbIt->second.readCb != nullptr) {
      if (conn_->transportSettings.removeStreamAfterEomCallbackUnset ||
          !readCbIt->second.deliveredEOM) {
        VLOG(10) << "Not closing stream=" << *itr
                 << " because it has active read callback";
        ++itr;
        continue;
      }
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
          getClosingStream(fmt::format("{}", *itr)));
    }
    if (connCallback_) {
      connCallback_->onStreamPreReaped(*itr);
    }
    auto result = conn_->streamManager->removeClosedStream(*itr);
    if (!result.has_value()) {
      exceptionCloseWhat_ = result.error().message;
      closeImpl(QuicError(
          result.error().code, std::string("checkForClosedStream() error")));
      return;
    }
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
    closeImpl(std::nullopt);
  }
}

void QuicTransportBaseLite::writeSocketDataAndCatch() {
  [[maybe_unused]] auto self = sharedGuard();
  try {
    auto result = writeSocketData();
    if (!result.has_value()) {
      VLOG(4) << __func__ << " " << result.error().message << " " << *this;
      exceptionCloseWhat_ = result.error().message;
      closeImpl(result.error());
      return;
    }
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

quic::Expected<void, QuicError> QuicTransportBaseLite::writeSocketData() {
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
    auto result = writeData();
    if (!result.has_value()) {
      return result;
    }
    if (conn_->transportSettings.isPriming && conn_->primingData.size() > 0) {
      auto primingData = std::move(conn_->primingData);
      connSetupCallback_->onPrimingDataAvailable(std::move(primingData));
    }
    if (closeState_ != CloseState::CLOSED) {
      if (conn_->pendingEvents.closeTransport == true) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "Max packet number reached"));
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
  return {};
}

// TODO: t64691045 change the closeImpl API to include both the sanitized and
// unsanited error message, remove exceptionCloseWhat_.
void QuicTransportBaseLite::closeImpl(
    Optional<QuicError> errorCode,
    bool drainConnection,
    bool sendCloseImmediately) {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }

  if (getSocketObserverContainer()) {
    SocketObserverInterface::CloseStartedEvent event;
    event.maybeCloseReason = errorCode;
    getSocketObserverContainer()->invokeInterfaceMethodAllObservers(
        [&event](auto observer, auto observed) {
          observer->closeStarted(observed, event);
        });
  }

  drainConnection = drainConnection & conn_->transportSettings.shouldDrain;

  uint64_t totalCryptoDataWritten = 0;
  uint64_t totalCryptoDataRecvd = 0;
  auto timeUntilLastInitialCryptoFrameReceived = std::chrono::milliseconds(0);
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
    timeUntilLastInitialCryptoFrameReceived =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            conn_->cryptoState->lastInitialCryptoFrameReceivedTimePoint -
            conn_->connectionTime);
  }

  if (conn_->qLogger) {
    auto tlsSummary = conn_->handshakeLayer->getTLSSummary();
    conn_->qLogger->addTransportSummary(
        {conn_->lossState.totalBytesSent,
         conn_->lossState.totalBytesRecvd,
         conn_->flowControlState.sumCurWriteOffset,
         conn_->flowControlState.sumMaxObservedOffset,
         conn_->flowControlState.sumCurStreamBufferLen,
         conn_->lossState.totalBytesRetransmitted,
         conn_->lossState.totalStreamBytesCloned,
         conn_->lossState.totalBytesCloned,
         totalCryptoDataWritten,
         totalCryptoDataRecvd,
         conn_->congestionController
             ? conn_->congestionController->getWritableBytes()
             : std::numeric_limits<uint64_t>::max(),
         getSendConnFlowControlBytesWire(*conn_),
         conn_->lossState.totalPacketsSpuriouslyMarkedLost,
         conn_->lossState.reorderingThreshold,
         uint64_t(conn_->transportSettings.timeReorderingThreshDividend),
         conn_->usedZeroRtt,
         conn_->version.value_or(QuicVersion::MVFST_INVALID),
         conn_->dsrPacketCount,
         conn_->initialPacketsReceived,
         conn_->uniqueInitialCryptoFramesReceived,
         timeUntilLastInitialCryptoFrameReceived,
         tlsSummary.alpn,
         tlsSummary.namedGroup,
         tlsSummary.pskType,
         tlsSummary.echStatus});
  }

  // TODO: truncate the error code string to be 1MSS only.
  closeState_ = CloseState::CLOSED;
  updatePacingOnClose(*conn_);
  auto cancelCode = QuicError(
      QuicErrorCode(LocalErrorCode::NO_ERROR),
      toString(LocalErrorCode::NO_ERROR).str());
  if (conn_->peerConnectionError) {
    cancelCode = *conn_->peerConnectionError;
  } else if (errorCode) {
    cancelCode = *errorCode;
  }
  // cancelCode is used for communicating error message to local app layer.
  // errorCode will be used for localConnectionError, and sent in close frames.
  // It's safe to include the unsanitized error message in cancelCode
  if (exceptionCloseWhat_) {
    cancelCode.message = exceptionCloseWhat_.value();
  }

  bool isReset = false;
  bool isAbandon = false;
  bool isInvalidMigration = false;
  LocalErrorCode* localError = cancelCode.code.asLocalErrorCode();
  TransportErrorCode* transportError = cancelCode.code.asTransportErrorCode();
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
    if (conn_->qLogger) {
      conn_->qLogger->addConnectionClose(
          conn_->localConnectionError->message,
          errorCode->message,
          drainConnection,
          sendCloseImmediately);
    }
  } else if (conn_->qLogger) {
    auto reason = fmt::format(
        "Server: {}, Peer: isReset: {}, Peer: isAbandon: {}",
        kNoError,
        isReset,
        isAbandon);
    conn_->qLogger->addConnectionClose(
        kNoError, std::move(reason), drainConnection, sendCloseImmediately);
  }
  cancelLossTimeout();
  cancelTimeout(&ackTimeout_);
  cancelTimeout(&pathValidationTimeout_);
  cancelTimeout(&idleTimeout_);
  cancelTimeout(&keepaliveTimeout_);
  cancelTimeout(&pingTimeout_);
  cancelTimeout(&excessWriteTimeout_);

  VLOG(10) << "Stopping read looper due to immediate close " << *this;
  readLooper_->stop();
  peekLooper_->stop();
  writeLooper_->stop();

  // Drop any alternate paths
  conn_->pathManager->dropAllSockets();

  cancelAllAppCallbacks(cancelCode);

  // Clear out all the pending events, we don't need them any more.
  closeTransport();

  // Clear out all the streams, we don't need them any more. When the peer
  // receives the conn close they will implicitly reset all the streams.
  conn_->streamManager->clearOpenStreams();

  // Clear out all the buffered datagrams
  conn_->datagramState.readBuffer.clear();
  conn_->datagramState.writeBuffer.clear();

  // Clear out all the pending events.
  conn_->pendingEvents = QuicConnectionStateBase::PendingEvents();
  conn_->streamManager->clearActionable();
  conn_->streamManager->clearWritable();
  if (conn_->ackStates.initialAckState) {
    conn_->ackStates.initialAckState->acks.clear();
  }
  if (conn_->ackStates.handshakeAckState) {
    conn_->ackStates.handshakeAckState->acks.clear();
  }
  conn_->ackStates.appDataAckState.acks.clear();

  if (transportReadyNotified_) {
    // This connection was open, update the stats for close.
    QUIC_STATS(conn_->statsCallback, onConnectionClose, cancelCode.code);

    processConnectionCallbacks(std::move(cancelCode));
  } else {
    processConnectionSetupCallbacks(std::move(cancelCode));
  }

  // can't invoke connection callbacks any more.
  resetConnectionCallbacks();

  // Don't need outstanding packets.
  conn_->outstandings.reset();

  // We don't need no congestion control.
  conn_->congestionController = nullptr;
  sendCloseImmediately = sendCloseImmediately && !isReset && !isAbandon;
  if (sendCloseImmediately) {
    // We might be invoked from the destructor, so just send the connection
    // close directly.
    auto result = writeData();
    if (!result.has_value()) {
      LOG(ERROR) << "close failed with error: " << result.error().message << " "
                 << *this;
    }
  }
  drainConnection =
      drainConnection && !isReset && !isAbandon && !isInvalidMigration;
  if (drainConnection) {
    // We ever drain once, and the object ever gets created once.
    DCHECK(!isTimeoutScheduled(&drainTimeout_));
    scheduleTimeout(
        &drainTimeout_,
        folly::chrono::ceil<std::chrono::milliseconds>(
            kDrainFactor * calculatePTO(*conn_)));
  } else {
    drainTimeoutExpired();
  }
}

void QuicTransportBaseLite::processCallbacksAfterNetworkData() {
  if (closeState_ != CloseState::OPEN) {
    return;
  }
  if (!connCallback_ || !conn_->streamManager) {
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

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::resetStreamInternal(
    StreamId id,
    ApplicationErrorCode errorCode,
    bool reliable) {
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
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
      return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    auto stream = conn_->streamManager->getStream(id).value_or(nullptr);
    CHECK(stream) << "Invalid stream in " << __func__ << ": " << id;
    if (stream->appErrorCodeToPeer &&
        *stream->appErrorCodeToPeer != errorCode) {
      // We can't change the error code across resets for a stream
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    Optional<uint64_t> maybeReliableSize = std::nullopt;
    if (reliable) {
      maybeReliableSize = stream->reliableResetCheckpoint;
    }
    if (stream->reliableSizeToPeer && maybeReliableSize &&
        *maybeReliableSize > *stream->reliableSizeToPeer) {
      // We can't increase the reliable size in a reset
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    if (maybeReliableSize && *maybeReliableSize > 0 &&
        (stream->sendState == StreamSendState::ResetSent)) {
      // We can't send a reliable reset with a non-zero reliable size if
      // we've already sent a non-reliable reset
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    // Invoke state machine
    auto result = sendRstSMHandler(*stream, errorCode, maybeReliableSize);
    if (!result.has_value()) {
      VLOG(4) << __func__ << " streamId=" << id << " " << result.error().message
              << " " << *this;
      exceptionCloseWhat_ = result.error().message;
      closeImpl(
          QuicError(result.error().code, std::string("resetStream() error")));
      return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
    }

    // Cancel all byte events for this stream which have offsets that don't
    // need to be reliably delivered.
    invokeForEachByteEventType(
        ([this, id, &maybeReliableSize](const ByteEvent::Type type) {
          cancelByteEventCallbacksForStreamInternal(
              type, id, [&maybeReliableSize](uint64_t offset) {
                return !maybeReliableSize || offset >= *maybeReliableSize;
              });
        }));

    pendingWriteCallbacks_.erase(id);
    QUIC_STATS(conn_->statsCallback, onQuicStreamReset, errorCode);
  } catch (const QuicTransportException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("resetStream() error")));
    return quic::make_unexpected(LocalErrorCode::TRANSPORT_ERROR);
  } catch (const QuicInternalException& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(ex.errorCode()), std::string("resetStream() error")));
    return quic::make_unexpected(ex.errorCode());
  } catch (const std::exception& ex) {
    VLOG(4) << __func__ << " streamId=" << id << " " << ex.what() << " "
            << *this;
    exceptionCloseWhat_ = ex.what();
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string("resetStream() error")));
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }
  return {};
}

void QuicTransportBaseLite::cancelByteEventCallbacksForStreamInternal(
    const ByteEvent::Type type,
    const StreamId id,
    const std::function<bool(uint64_t)>& offsetFilter) {
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
    if (offsetFilter(cbOffset)) {
      streamByteEvents.pop_front();
      ByteEventCancellation cancellation{id, cbOffset, type};
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
    // The callback could have changed the map so erase by id.
    byteEventMap.erase(id);
  }
}

void QuicTransportBaseLite::onSocketWritable() noexcept {
  // Remove the writable callback.
  socket_->pauseWrite();

  // Try to write.
  // If write fails again, pacedWriteDataToSocket() will re-arm the write event
  // and stop the write looper.
  writeLooper_->run(true /* thisIteration */);
}

void QuicTransportBaseLite::invokeStreamsAvailableCallbacks() {
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

void QuicTransportBaseLite::handlePingCallbacks() {
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

void QuicTransportBaseLite::handleKnobCallbacks() {
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

void QuicTransportBaseLite::handleAckEventCallbacks() {
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

void QuicTransportBaseLite::handleCancelByteEventCallbacks() {
  for (auto pendingResetIt = conn_->pendingEvents.resets.begin();
       pendingResetIt != conn_->pendingEvents.resets.end();
       pendingResetIt++) {
    cancelByteEventCallbacksForStream(pendingResetIt->first);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }
}

void QuicTransportBaseLite::handleNewStreamCallbacks(
    std::vector<StreamId>& streamStorage) {
  streamStorage = conn_->streamManager->consumeNewPeerStreams();
  handleNewStreams(streamStorage);
}

void QuicTransportBaseLite::handleNewGroupedStreamCallbacks(
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

void QuicTransportBaseLite::handleDeliveryCallbacks() {
  auto deliverableStreamId = conn_->streamManager->popDeliverable();
  while (deliverableStreamId.has_value()) {
    auto streamId = *deliverableStreamId;
    auto stream = CHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
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

void QuicTransportBaseLite::handleStreamFlowControlUpdatedCallbacks(
    std::vector<StreamId>& streamStorage) {
  // Iterate over streams that changed their flow control window and give
  // their registered listeners their updates.
  // We don't really need flow control notifications when we are closed.
  streamStorage = conn_->streamManager->consumeFlowControlUpdated();
  const auto& flowControlUpdated = streamStorage;
  for (auto streamId : flowControlUpdated) {
    auto stream = CHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
    if (!stream->writable()) {
      pendingWriteCallbacks_.erase(streamId);
      continue;
    }
    connCallback_->onFlowControlUpdate(streamId);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
    // In case the callback modified the stream map, get it again.
    stream = CHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
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

void QuicTransportBaseLite::handleStreamStopSendingCallbacks() {
  const auto stopSendingStreamsCopy =
      conn_->streamManager->consumeStopSending();
  for (const auto& itr : stopSendingStreamsCopy) {
    connCallback_->onStopSending(itr.first, itr.second);
    if (closeState_ != CloseState::OPEN) {
      return;
    }
  }
}

void QuicTransportBaseLite::handleConnWritable() {
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
      auto stream = CHECK_NOTNULL(
          conn_->streamManager->getStream(streamId).value_or(nullptr));
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

void QuicTransportBaseLite::cleanupAckEventState() {
  // if there's no bytes in flight, clear any memory allocated for AckEvents
  if (conn_->outstandings.packets.empty()) {
    std::vector<AckEvent> empty;
    conn_->lastProcessedAckEvents.swap(empty);
  } // memory allocated for vector will be freed
}

quic::Expected<WriteQuicDataResult, QuicError>
QuicTransportBaseLite::handleInitialWriteDataCommon(
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

quic::Expected<WriteQuicDataResult, QuicError>
QuicTransportBaseLite::handleHandshakeWriteDataCommon(
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

void QuicTransportBaseLite::closeUdpSocket() {
  if (!socket_) {
    return;
  }
  if (getSocketObserverContainer()) {
    SocketObserverInterface::ClosingEvent event; // empty for now
    getSocketObserverContainer()->invokeInterfaceMethodAllObservers(
        [&event](auto observer, auto observed) {
          observer->closing(observed, event);
        });
  }
  auto sock = std::move(socket_);
  socket_ = nullptr;
  sock->pauseRead();
  auto closeResult = sock->close();
  LOG_IF(ERROR, !closeResult.has_value())
      << "close hit an error: " << closeResult.error().message;
}

quic::Expected<StreamId, LocalErrorCode>
QuicTransportBaseLite::createStreamInternal(
    bool bidirectional,
    const OptionalIntegral<StreamGroupId>& streamGroupId) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  quic::Expected<QuicStreamState*, LocalErrorCode> streamResult;
  if (bidirectional) {
    streamResult =
        conn_->streamManager->createNextBidirectionalStream(streamGroupId);
  } else {
    streamResult =
        conn_->streamManager->createNextUnidirectionalStream(streamGroupId);
  }
  if (!streamResult.has_value()) {
    return quic::make_unexpected(streamResult.error());
  }

  auto* streamState = *streamResult;
  if (!streamState) {
    return quic::make_unexpected(LocalErrorCode::INTERNAL_ERROR);
  }

  const StreamId streamId = streamState->id;
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

  return streamId;
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
    auto result = onLossDetectionAlarm(*conn_, markPacketLoss);
    if (!result.has_value()) {
      closeImpl(QuicError(
          result.error().code, std::string("lossTimeoutExpired() error")));
      return;
    }

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
  auto localError =
      drain ? LocalErrorCode::IDLE_TIMEOUT : LocalErrorCode::SHUTTING_DOWN;
  auto sendCloseImmediately =
      conn_->transportSettings.alwaysSendConnectionCloseOnIdleTimeout ? true
                                                                      : !drain;

  auto localIdleTimeout = conn_->transportSettings.idleTimeout;
  auto peerIdleTimeout =
      conn_->peerIdleTimeout > 0ms ? conn_->peerIdleTimeout : localIdleTimeout;
  auto idleTimeout = timeMin(localIdleTimeout, peerIdleTimeout);
  auto idleTimeoutCount = idleTimeout.count();
  closeImpl(
      quic::QuicError(
          QuicErrorCode(localError),
          fmt::format(
              "{}: {} seconds", toString(localError), idleTimeoutCount / 1000)),
      drain /* drainConnection */,
      sendCloseImmediately);
}

void QuicTransportBaseLite::keepaliveTimeoutExpired() noexcept {
  [[maybe_unused]] auto self = sharedGuard();
  conn_->pendingEvents.sendPing = true;
  updateWriteLooper(true);
}

void QuicTransportBaseLite::ackTimeoutExpired() noexcept {
  CHECK_NE(closeState_, CloseState::CLOSED);
  VLOG(10) << __func__ << " " << *this;
  [[maybe_unused]] auto self = sharedGuard();
  updateAckStateOnAckTimeout(*conn_);
  pacedWriteDataToSocket();
}

void QuicTransportBaseLite::pathValidationTimeoutExpired() noexcept {
  // Pass the signal to the path manager. Responding to the result of the path
  // validation is handled in the path validation callback in the client/server
  // transport.
  [[maybe_unused]] auto self = sharedGuard();
  conn_->pathManager->onPathValidationTimeoutExpired();
}

void QuicTransportBaseLite::drainTimeoutExpired() noexcept {
  closeUdpSocket();
  unbindConnection();
}

void QuicTransportBaseLite::pingTimeoutExpired() noexcept {
  // If timeout expired just call the  call back Provided
  if (pingCallback_ != nullptr) {
    pingCallback_->pingTimeout();
  }
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

void QuicTransportBaseLite::cancelAllAppCallbacks(
    const QuicError& err) noexcept {
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
  auto readCallbacksCopy = readCallbacks_;
  for (auto& cb : readCallbacksCopy) {
    auto streamId = cb.first;
    auto it = readCallbacks_.find(streamId);
    if (it == readCallbacks_.end()) {
      // An earlier call to readError removed the stream from readCallbacks
      // May not be possible?
      continue;
    }
    if (it->second.readCb) {
      auto stream = CHECK_NOTNULL(
          conn_->streamManager->getStream(streamId).value_or(nullptr));
      if (!stream->groupId) {
        it->second.readCb->readError(streamId, err);
      } else {
        it->second.readCb->readErrorWithGroup(streamId, *stream->groupId, err);
      }
    }
    readCallbacks_.erase(it);
  }
  // TODO: what if a call to readError installs a new read callback?
  LOG_IF(ERROR, !readCallbacks_.empty())
      << readCallbacks_.size() << " read callbacks remaining to be cleared";

  VLOG(4) << "Clearing datagram callback";
  datagramCallback_ = nullptr;

  VLOG(4) << "Clearing ping callback";
  pingCallback_ = nullptr;

  VLOG(4) << "Clearing " << peekCallbacks_.size() << " peek callbacks";
  auto peekCallbacksCopy = peekCallbacks_;
  for (auto& cb : peekCallbacksCopy) {
    peekCallbacks_.erase(cb.first);
    if (cb.second.peekCb) {
      cb.second.peekCb->peekError(cb.first, err);
    }
  }

  if (connWriteCallback_) {
    auto connWriteCallback = connWriteCallback_;
    connWriteCallback_ = nullptr;
    connWriteCallback->onConnectionWriteError(err);
  }
  auto pendingWriteCallbacksCopy = pendingWriteCallbacks_;
  for (auto& wcb : pendingWriteCallbacksCopy) {
    pendingWriteCallbacks_.erase(wcb.first);
    wcb.second->onStreamWriteError(wcb.first, err);
  }
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

size_t QuicTransportBaseLite::getNumByteEventCallbacksForStream(
    const StreamId id) const {
  size_t total = 0;
  invokeForEachByteEventTypeConst(
      ([this, id, &total](const ByteEvent::Type type) {
        total += getNumByteEventCallbacksForStream(type, id);
      }));
  return total;
}

size_t QuicTransportBaseLite::getNumByteEventCallbacksForStream(
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

void QuicTransportBaseLite::cancelAllByteEventCallbacks() {
  invokeForEachByteEventType(
      ([this](const ByteEvent::Type type) { cancelByteEventCallbacks(type); }));
}

void QuicTransportBaseLite::cancelByteEventCallbacks(
    const ByteEvent::Type type) {
  ByteEventMap byteEventMap = std::move(getByteEventMap(type));
  for (const auto& [streamId, cbMap] : byteEventMap) {
    for (const auto& [offset, cb] : cbMap) {
      ByteEventCancellation cancellation{streamId, offset, type};
      cb->onByteEventCanceled(cancellation);
    }
  }
}

StreamInitiator QuicTransportBaseLite::getStreamInitiator(
    StreamId stream) noexcept {
  return quic::getStreamInitiator(conn_->nodeType, stream);
}

QuicConnectionStats QuicTransportBaseLite::getConnectionsStats() const {
  QuicConnectionStats connStats;
  if (!conn_) {
    return connStats;
  }
  connStats.peerAddress = conn_->peerAddress;
  connStats.duration = Clock::now() - conn_->connectionTime;
  if (conn_->congestionController) {
    connStats.cwnd_bytes = conn_->congestionController->getCongestionWindow();
    connStats.congestionController = conn_->congestionController->type();
    conn_->congestionController->getStats(connStats.congestionControllerStats);
  }
  connStats.ptoCount = conn_->lossState.ptoCount;
  connStats.srtt = conn_->lossState.srtt;
  connStats.mrtt = conn_->lossState.mrtt;
  connStats.lrtt = conn_->lossState.lrtt;
  connStats.rttvar = conn_->lossState.rttvar;
  connStats.peerAckDelayExponent = conn_->peerAckDelayExponent;
  connStats.udpSendPacketLen = conn_->udpSendPacketLen;
  if (conn_->streamManager) {
    connStats.numStreams = conn_->streamManager->streams().size();
  }

  if (conn_->clientChosenDestConnectionId.has_value()) {
    connStats.clientChosenDestConnectionId =
        conn_->clientChosenDestConnectionId->hex();
  }
  if (conn_->clientConnectionId.has_value()) {
    connStats.clientConnectionId = conn_->clientConnectionId->hex();
  }
  if (conn_->serverConnectionId.has_value()) {
    connStats.serverConnectionId = conn_->serverConnectionId->hex();
  }

  connStats.totalBytesSent = conn_->lossState.totalBytesSent;
  connStats.totalBytesReceived = conn_->lossState.totalBytesRecvd;
  connStats.totalBytesRetransmitted = conn_->lossState.totalBytesRetransmitted;
  if (conn_->version.has_value()) {
    connStats.version = static_cast<uint32_t>(*conn_->version);
  }
  return connStats;
}

const TransportSettings& QuicTransportBaseLite::getTransportSettings() const {
  return conn_->transportSettings;
}

bool QuicTransportBaseLite::isTimeoutScheduled(
    QuicTimerCallback* callback) const {
  return callback->isTimerCallbackScheduled();
}

void QuicTransportBaseLite::invokeReadDataAndCallbacks(
    bool updateLoopersAndCheckForClosedStream) {
  auto self = sharedGuard();
  SCOPE_EXIT {
    if (updateLoopersAndCheckForClosedStream) {
      self->checkForClosedStream();
      self->updateReadLooper();
      self->updateWriteLooper(true);
    }
  };
  // Need a copy since the set can change during callbacks.
  std::vector<StreamId> readableStreamsCopy;

  const auto& readableStreams = self->conn_->streamManager->readableStreams();
  const auto& readableUnidirectionalStreams =
      self->conn_->streamManager->readableUnidirectionalStreams();

  readableStreamsCopy.reserve(
      readableStreams.size() + readableUnidirectionalStreams.size());

  if (self->conn_->transportSettings.unidirectionalStreamsReadCallbacksFirst) {
    std::copy(
        readableUnidirectionalStreams.begin(),
        readableUnidirectionalStreams.end(),
        std::back_inserter(readableStreamsCopy));
  }

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
    auto stream = CHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
    if (readCb && stream->streamReadError &&
        (!stream->reliableSizeFromPeer ||
         *stream->reliableSizeFromPeer <= stream->currentReadOffset)) {
      // If we got a reliable reset from the peer, we don't fire the readError
      // callback and remove it until we've read all of the reliable data.
      if (self->conn_->transportSettings
              .unidirectionalStreamsReadCallbacksFirst &&
          isUnidirectionalStream(streamId)) {
        self->conn_->streamManager->readableUnidirectionalStreams().erase(
            streamId);
      } else {
        self->conn_->streamManager->readableStreams().erase(streamId);
      }
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
    auto stream = CHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
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

quic::Expected<void, LocalErrorCode>
QuicTransportBaseLite::setReadCallbackInternal(
    StreamId id,
    ReadCallback* cb,
    Optional<ApplicationErrorCode> err) noexcept {
  VLOG(4) << "Setting setReadCallback for stream=" << id << " cb=" << cb << " "
          << *this;
  auto readCbIt = readCallbacks_.find(id);
  if (readCbIt == readCallbacks_.end()) {
    // Don't allow initial setting of a nullptr callback.
    if (!cb) {
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    readCbIt = readCallbacks_.emplace(id, ReadCallbackData(cb)).first;
  }
  auto& readCb = readCbIt->second.readCb;
  if (readCb == nullptr && cb != nullptr) {
    // It's already been set to nullptr we do not allow unsetting it.
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  } else {
    readCb = cb;
    if (readCb == nullptr && err) {
      return stopSending(id, err.value());
    }
  }
  updateReadLooper();
  return {};
}

Optional<folly::SocketCmsgMap>
QuicTransportBaseLite::getAdditionalCmsgsForAsyncUDPSocket() {
  if (conn_->socketCmsgsState.additionalCmsgs) {
    // This callback should be happening for the target write
    DCHECK(conn_->writeCount == conn_->socketCmsgsState.targetWriteCount);
    return conn_->socketCmsgsState.additionalCmsgs;
  }
  return std::nullopt;
}

void QuicTransportBaseLite::notifyStartWritingFromAppRateLimited() {
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
                             : std::nullopt)
                     .setWritableBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getWritableBytes())
                             : std::nullopt)
                     .build()](auto observer, auto observed) {
              observer->startWritingFromAppLimited(observed, event);
            });
  }
}

void QuicTransportBaseLite::notifyPacketsWritten(
    const uint64_t numPacketsWritten,
    const uint64_t numAckElicitingPacketsWritten,
    const uint64_t numBytesWritten) {
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
                             : std::nullopt)
                     .setWritableBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getWritableBytes())
                             : std::nullopt)
                     .setNumPacketsWritten(numPacketsWritten)
                     .setNumAckElicitingPacketsWritten(
                         numAckElicitingPacketsWritten)
                     .setNumBytesWritten(numBytesWritten)
                     .build()](auto observer, auto observed) {
              observer->packetsWritten(observed, event);
            });
  }
}

void QuicTransportBaseLite::notifyAppRateLimited() {
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
                             : std::nullopt)
                     .setWritableBytes(
                         conn_->congestionController
                             ? Optional<uint64_t>(conn_->congestionController
                                                      ->getWritableBytes())
                             : std::nullopt)
                     .build()](auto observer, auto observed) {
              observer->appRateLimited(observed, event);
            });
  }
}

void QuicTransportBaseLite::onTransportKnobs(BufPtr knobBlob) {
  // Not yet implemented,
  VLOG(4) << "Received transport knobs: "
          << std::string(
                 reinterpret_cast<const char*>(knobBlob->data()),
                 knobBlob->length());
}

void QuicTransportBaseLite::processCallbacksAfterWriteData() {
  if (closeState_ != CloseState::OPEN) {
    return;
  }

  auto txStreamId = conn_->streamManager->popTx();
  while (txStreamId.has_value()) {
    auto streamId = *txStreamId;
    auto stream = CHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
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
        return std::nullopt;
      }

      auto& txCallbacksForStream = txCallbacksForStreamIt->second;
      if (txCallbacksForStream.front().offset > *largestOffsetTxed) {
        return std::nullopt;
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

  scheduleTimeout(&idleTimeout_, idleTimeout);
  auto idleTimeoutCount = idleTimeout.count();
  if (conn_->transportSettings.enableKeepalive) {
    std::chrono::milliseconds keepaliveTimeout = std::chrono::milliseconds(
        idleTimeoutCount - static_cast<int64_t>(idleTimeoutCount * .15));
    scheduleTimeout(&keepaliveTimeout_, keepaliveTimeout);
  }
}

void QuicTransportBaseLite::setTransportSettings(
    TransportSettings transportSettings) {
  if (conn_->nodeType == QuicNodeType::Client) {
    if (useSinglePacketInplaceBatchWriter(
            transportSettings.maxBatchSize, transportSettings.dataPathType)) {
      createBufAccessor(conn_->udpSendPacketLen);
    } else if (
        transportSettings.dataPathType ==
        quic::DataPathType::ContinuousMemory) {
      // Create generic buf for in-place batch writer.
      createBufAccessor(
          conn_->udpSendPacketLen * transportSettings.maxBatchSize);
    }
  }

  // If transport parameters are encoded, we can only update congestion
  // control related params. Setting other transport settings again would be
  // buggy.
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
    auto result = conn_->streamManager->refreshTransportSettings(
        conn_->transportSettings);
    LOG_IF(FATAL, !result.has_value()) << result.error().message;
    if (conn_->nodeType == QuicNodeType::Client &&
        conn_->transportSettings.isPriming) {
      setSupportedVersions({QuicVersion::MVFST_PRIMING});
      // always use the smaller packet size to ensure priming packets work
      // both with IPv4 and IPv6
      conn_->udpSendPacketLen = kDefaultUDPSendPacketLen;
    }
  }

  // A few values cannot be overridden to be lower than default:
  // TODO refactor transport settings to avoid having to update params twice.
  if (conn_->transportSettings.defaultCongestionController !=
      CongestionControlType::None) {
    conn_->transportSettings.initCwndInMss =
        std::max(conn_->transportSettings.initCwndInMss, kInitCwndInMss);
    conn_->transportSettings.minCwndInMss =
        std::max(conn_->transportSettings.minCwndInMss, kMinCwndInMss);
    conn_->transportSettings.initCwndInMss = std::max(
        conn_->transportSettings.minCwndInMss,
        conn_->transportSettings.initCwndInMss);
  }

  validateCongestionAndPacing(
      conn_->transportSettings.defaultCongestionController);
  if (conn_->transportSettings.pacingEnabled) {
    writeLooper_->setPacingFunction([this]() -> auto {
      if (isConnectionPaced(*conn_)) {
        return conn_->pacer->getTimeUntilNextWrite();
      }
      return 0us;
    });
    bool usingBbr =
        (conn_->transportSettings.defaultCongestionController ==
             CongestionControlType::BBR ||
         conn_->transportSettings.defaultCongestionController ==
             CongestionControlType::BBRTesting ||
         conn_->transportSettings.defaultCongestionController ==
             CongestionControlType::BBR2);
    auto minCwnd =
        usingBbr ? kMinCwndInMssForBbr : conn_->transportSettings.minCwndInMss;
    conn_->pacer = std::make_unique<TokenlessPacer>(*conn_, minCwnd);
    conn_->pacer->setExperimental(conn_->transportSettings.experimentalPacer);
    conn_->canBePaced = conn_->transportSettings.pacingEnabledFirstFlight;
  }
  setCongestionControl(conn_->transportSettings.defaultCongestionController);
  if (conn_->transportSettings.datagramConfig.enabled) {
    conn_->datagramState.maxReadFrameSize = kMaxDatagramFrameSize;
    conn_->datagramState.maxReadBufferSize =
        conn_->transportSettings.datagramConfig.readBufSize;
    conn_->datagramState.maxWriteBufferSize =
        conn_->transportSettings.datagramConfig.writeBufSize;
  }

  updateSocketTosSettings(conn_->transportSettings.dscpValue);

  if (conn_->readCodec) {
    // Update the codec parameters. In case of the client, the codec was
    // initialized in the constructor and did not have the transport settings.
    conn_->readCodec->setCodecParameters(CodecParameters(
        conn_->peerAckDelayExponent,
        conn_->originalVersion.value(),
        conn_->transportSettings.maybeAckReceiveTimestampsConfigSentToPeer,
        conn_->transportSettings.advertisedExtendedAckFeatures));
  }
}

void QuicTransportBaseLite::setCongestionControl(CongestionControlType type) {
  DCHECK(conn_);
  if (!conn_->congestionController ||
      type != conn_->congestionController->type()) {
    CHECK(conn_->congestionControllerFactory);
    validateCongestionAndPacing(type);
    conn_->congestionController =
        conn_->congestionControllerFactory->makeCongestionController(
            *conn_, type);
    if (conn_->qLogger) {
      std::stringstream s;
      s << "CCA set to " << congestionControlTypeToString(type);
      conn_->qLogger->addTransportStateUpdate(s.str());
    }
  }
}

void QuicTransportBaseLite::setSupportedVersions(
    const std::vector<QuicVersion>& versions) {
  conn_->originalVersion = versions.at(0);
  conn_->supportedVersions = versions;
}

void QuicTransportBaseLite::setCongestionControllerFactory(
    std::shared_ptr<CongestionControllerFactory> ccFactory) {
  CHECK(ccFactory);
  CHECK(conn_);
  conn_->congestionControllerFactory = ccFactory;
  conn_->congestionController.reset();
}

void QuicTransportBaseLite::addPacketProcessor(
    std::shared_ptr<PacketProcessor> packetProcessor) {
  DCHECK(conn_);
  conn_->packetProcessors.push_back(std::move(packetProcessor));
}

quic::Expected<void, LocalErrorCode> QuicTransportBaseLite::setKnob(
    uint64_t knobSpace,
    uint64_t knobId,
    BufPtr knobBlob) {
  if (isKnobSupported()) {
    sendSimpleFrame(*conn_, KnobFrame(knobSpace, knobId, std::move(knobBlob)));
    return {};
  }
  LOG(ERROR) << "Cannot set knob. Peer does not support the knob frame";
  return quic::make_unexpected(LocalErrorCode::KNOB_FRAME_UNSUPPORTED);
}

bool QuicTransportBaseLite::isKnobSupported() const {
  return conn_->peerAdvertisedKnobFrameSupport;
}

void QuicTransportBaseLite::validateCongestionAndPacing(
    CongestionControlType& type) {
  // Fallback to Cubic if Pacing isn't enabled with BBR together
  if ((type == CongestionControlType::BBR ||
       type == CongestionControlType::BBRTesting ||
       type == CongestionControlType::BBR2) &&
      !conn_->transportSettings.pacingEnabled) {
    LOG(ERROR) << "Unpaced BBR isn't supported";
    type = CongestionControlType::Cubic;
  }

  if (type == CongestionControlType::BBR2 ||
      type == CongestionControlType::BBRTesting) {
    // We need to have the pacer rate be as accurate as possible for BBR2 and
    // BBRTesting.
    // The current BBR behavior is dependent on the existing pacing
    // behavior so the override is only for BBR2/BBRTesting.
    // TODO: This should be removed once the pacer changes are adopted as
    // the defaults or the pacer is fixed in another way.
    conn_->transportSettings.experimentalPacer = true;
    conn_->transportSettings.defaultRttFactor = {1, 1};
    if (type == CongestionControlType::BBRTesting) {
      // Force-disable startup pace scaling only for BBRTesting
      conn_->transportSettings.startupRttFactor = {1, 1};
    }
    if (conn_->pacer) {
      conn_->pacer->setExperimental(conn_->transportSettings.experimentalPacer);
      conn_->pacer->setRttFactor(
          conn_->transportSettings.defaultRttFactor.first,
          conn_->transportSettings.defaultRttFactor.second);
    }
  }
}

void QuicTransportBaseLite::updateSocketTosSettings(uint8_t dscpValue) {
  const auto initialTosValue = conn_->socketTos.value;
  conn_->socketTos.fields.dscp = dscpValue;
  if (conn_->transportSettings.enableEcnOnEgress) {
    if (conn_->transportSettings.useL4sEcn) {
      conn_->socketTos.fields.ecn = kEcnECT1;
      conn_->ecnState = ECNState::AttemptingL4S;
    } else {
      conn_->socketTos.fields.ecn = kEcnECT0;
      conn_->ecnState = ECNState::AttemptingECN;
    }
  } else {
    conn_->socketTos.fields.ecn = 0;
    conn_->ecnState = ECNState::NotAttempted;
  }

  if (socket_ && socket_->isBound() &&
      conn_->socketTos.value != initialTosValue) {
    auto tosResult = socket_->setTosOrTrafficClass(conn_->socketTos.value);
    if (!tosResult.has_value()) {
      exceptionCloseWhat_ = tosResult.error().message;
      return closeImpl(tosResult.error());
    }
  }
}

quic::Expected<void, QuicError> QuicTransportBaseLite::validateECNState() {
  if (conn_->ecnState == ECNState::NotAttempted ||
      conn_->ecnState == ECNState::FailedValidation) {
    // Verification not needed
    return {};
  }
  const auto& minExpectedMarkedPacketsCount =
      conn_->ackStates.appDataAckState.minimumExpectedEcnMarksEchoed;
  if (minExpectedMarkedPacketsCount < 10) {
    // We wait for 10 ack-eliciting app data packets to be marked before trying
    // to validate ECN.
    return {};
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
    auto result = socket_->setTosOrTrafficClass(conn_->socketTos.value);
    if (!result.has_value()) {
      return result;
    }

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
  return {};
}

void QuicTransportBaseLite::scheduleAckTimeout() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  if (conn_->pendingEvents.scheduleAckTimeout) {
    if (!isTimeoutScheduled(&ackTimeout_)) {
      auto factoredRtt = std::chrono::duration_cast<std::chrono::microseconds>(
          conn_->transportSettings.ackTimerFactor * conn_->lossState.srtt);
      // If we are using ACK_FREQUENCY, disable the factored RTT heuristic
      // and only use the update max ACK delay.
      if (conn_->ackStates.appDataAckState.ackFrequencySequenceNumber) {
        factoredRtt = conn_->ackStates.maxAckDelay;
      }
      auto timeout = timeMax(
          std::chrono::duration_cast<std::chrono::microseconds>(
              evb_->getTimerTickInterval()),
          timeMin(conn_->ackStates.maxAckDelay, factoredRtt));
      auto timeoutMs = folly::chrono::ceil<std::chrono::milliseconds>(timeout);
      VLOG(10) << __func__ << " timeout=" << timeoutMs.count() << "ms"
               << " factoredRtt=" << factoredRtt.count() << "us" << " "
               << *this;
      scheduleTimeout(&ackTimeout_, timeoutMs);
    }
  } else {
    if (isTimeoutScheduled(&ackTimeout_)) {
      VLOG(10) << __func__ << " cancel timeout " << *this;
      cancelTimeout(&ackTimeout_);
    }
  }
}

void QuicTransportBaseLite::schedulePathValidationTimeout() {
  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  if (!conn_->pendingEvents.schedulePathValidationTimeout) {
    if (isTimeoutScheduled(&pathValidationTimeout_)) {
      VLOG(10) << __func__ << " cancel timeout " << *this;
      // This means path validation succeeded, and we should have updated to
      // correct state
      cancelTimeout(&pathValidationTimeout_);
    }
  } else if (!isTimeoutScheduled(&pathValidationTimeout_)) {
    auto nextTimeout = conn_->pathManager->getEarliestChallengeTimeout();
    if (nextTimeout.has_value()) {
      auto timeoutMs = *nextTimeout > Clock::now()
          ? std::chrono::ceil<std::chrono::milliseconds>(
                *nextTimeout - Clock::now())
          : 0ms;
      VLOG(10) << __func__ << " timeout=" << timeoutMs.count() << "ms "
               << *this;
      scheduleTimeout(&pathValidationTimeout_, timeoutMs);
    }
  }
}

/**
 * Getters for details from the transport/security layers such as
 * RTT, rxmit, cwnd, mss, app protocol, handshake latency,
 * client proposed ciphers, etc.
 */

QuicSocketLite::TransportInfo QuicTransportBaseLite::getTransportInfo() const {
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

const folly::SocketAddress& QuicTransportBaseLite::getLocalAddress() const {
  return socket_ && socket_->isBound() ? socket_->addressRef()
                                       : localFallbackAddress;
}

void QuicTransportBaseLite::handleNewStreams(
    std::vector<StreamId>& streamStorage) {
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

void QuicTransportBaseLite::handleNewGroupedStreams(
    std::vector<StreamId>& streamStorage) {
  const auto& newPeerStreamIds = streamStorage;
  for (const auto& streamId : newPeerStreamIds) {
    CHECK_NOTNULL(connCallback_.get());
    auto stream = CHECK_NOTNULL(
        conn_->streamManager->getStream(streamId).value_or(nullptr));
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

void QuicTransportBaseLite::logStreamOpenEvent(StreamId streamId) {
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

bool QuicTransportBaseLite::hasDeliveryCallbacksToCall(
    StreamId streamId,
    uint64_t maxOffsetToDeliver) const {
  auto callbacksIt = deliveryCallbacks_.find(streamId);
  if (callbacksIt == deliveryCallbacks_.end() || callbacksIt->second.empty()) {
    return false;
  }

  return (callbacksIt->second.front().offset <= maxOffsetToDeliver);
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

void QuicTransportBaseLite::updateCongestionControlSettings(
    const TransportSettings& transportSettings) {
  conn_->transportSettings.defaultCongestionController =
      transportSettings.defaultCongestionController;
  conn_->transportSettings.initCwndInMss = transportSettings.initCwndInMss;
  conn_->transportSettings.minCwndInMss = transportSettings.minCwndInMss;
  conn_->transportSettings.maxCwndInMss = transportSettings.maxCwndInMss;
  conn_->transportSettings.limitedCwndInMss =
      transportSettings.limitedCwndInMss;
  conn_->transportSettings.pacingEnabled = transportSettings.pacingEnabled;
  conn_->transportSettings.pacingTickInterval =
      transportSettings.pacingTickInterval;
  conn_->transportSettings.pacingTimerResolution =
      transportSettings.pacingTimerResolution;
  conn_->transportSettings.minBurstPackets = transportSettings.minBurstPackets;
  conn_->transportSettings.copaDeltaParam = transportSettings.copaDeltaParam;
  conn_->transportSettings.copaUseRttStanding =
      transportSettings.copaUseRttStanding;
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
