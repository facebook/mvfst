/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Bbr.h>
#include <quic/congestion_control/ServerCongestionControllerFactory.h>
#include <quic/dsr/frontend/WriteFunctions.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/handshake/AppToken.h>
#include <quic/server/handshake/DefaultAppTokenValidator.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/TransportSettingsFunctions.h>

#include <quic/common/Optional.h>
#include <quic/common/TransportKnobs.h>
#include <chrono>
#include <memory>

namespace quic {

QuicServerTransport::QuicServerTransport(
    std::shared_ptr<QuicEventBase> evb,
    std::unique_ptr<QuicAsyncUDPSocket> sock,
    folly::MaybeManagedPtr<ConnectionSetupCallback> connSetupCb,
    folly::MaybeManagedPtr<ConnectionCallback> connStreamsCb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx,
    std::unique_ptr<CryptoFactory> cryptoFactory,
    PacketNum startingPacketNum)
    : QuicServerTransport(
          std::move(evb),
          std::move(sock),
          connSetupCb,
          connStreamsCb,
          std::move(ctx),
          std::move(cryptoFactory)) {
  conn_->ackStates = AckStates(startingPacketNum);
}

QuicServerTransport::QuicServerTransport(
    std::shared_ptr<QuicEventBase> evb,
    std::unique_ptr<QuicAsyncUDPSocket> sock,
    folly::MaybeManagedPtr<ConnectionSetupCallback> connSetupCb,
    folly::MaybeManagedPtr<ConnectionCallback> connStreamsCb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx,
    std::unique_ptr<CryptoFactory> cryptoFactory,
    bool useConnectionEndWithErrorCallback)
    : QuicTransportBaseLite(
          evb,
          std::move(sock),
          useConnectionEndWithErrorCallback),
      QuicTransportBase(
          std::move(evb),
          nullptr /* Initialized through the QuicTransportBaseLite constructor
                   */
          ,
          useConnectionEndWithErrorCallback),
      ctx_(std::move(ctx)),
      wrappedObserverContainer_(this) {
  auto tempConn = std::make_unique<QuicServerConnectionState>(
      FizzServerQuicHandshakeContext::Builder()
          .setFizzServerContext(ctx_)
          .setCryptoFactory(std::move(cryptoFactory))
          .build());
  auto addrResult = socket_->address();
  CHECK(addrResult.has_value());
  tempConn->serverAddr = addrResult.value();
  serverConn_ = tempConn.get();
  conn_.reset(tempConn.release());
  conn_->observerContainer = wrappedObserverContainer_.getWeakPtr();
  setConnectionSetupCallback(connSetupCb);
  setConnectionCallbackFromCtor(connStreamsCb);
  conn_->pathManager->setPathValidationCallback(this);
}

QuicServerTransport::~QuicServerTransport() {
  VLOG(10) << "Destroyed connection to client=" << *this;
  // The caller probably doesn't need the conn callback after destroying the
  // transport.
  resetConnectionCallbacks();
  closeImpl(
      QuicError(
          QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
          std::string("Closing from server destructor")),
      false /* drainConnection */);
  // closeImpl may have been called earlier with drain = true, so force close.
  closeUdpSocket();
}

QuicServerTransport::Ptr QuicServerTransport::make(
    folly::EventBase* evb,
    std::unique_ptr<FollyAsyncUDPSocketAlias> sock,
    const folly::MaybeManagedPtr<ConnectionSetupCallback>& connSetupCb,
    const folly::MaybeManagedPtr<ConnectionCallback>& connStreamsCb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx,
    bool useConnectionEndWithErrorCallback) {
  auto qEvb = std::make_shared<FollyQuicEventBase>(evb);
  auto qSock = std::make_unique<FollyQuicAsyncUDPSocket>(qEvb, std::move(sock));
  return std::make_shared<QuicServerTransport>(
      std::move(qEvb),
      std::move(qSock),
      connSetupCb,
      connStreamsCb,
      ctx,
      nullptr /* cryptoFactory */,
      useConnectionEndWithErrorCallback);
}

void QuicServerTransport::setRoutingCallback(
    RoutingCallback* callback) noexcept {
  routingCb_ = callback;
}

void QuicServerTransport::setHandshakeFinishedCallback(
    HandshakeFinishedCallback* callback) noexcept {
  handshakeFinishedCb_ = callback;
}

void QuicServerTransport::setOriginalPeerAddress(
    const folly::SocketAddress& addr) {
  conn_->originalPeerAddress = addr;
}

void QuicServerTransport::setServerConnectionIdParams(
    ServerConnectionIdParams params) noexcept {
  serverConn_->serverConnIdParams = std::move(params);
}

void QuicServerTransport::setTransportStatsCallback(
    QuicTransportStatsCallback* statsCallback) noexcept {
  if (conn_) {
    conn_->statsCallback = statsCallback;
    if (conn_->readCodec) {
      conn_->readCodec->setConnectionStatsCallback(statsCallback);
    }
  }
}

void QuicServerTransport::setConnectionIdAlgo(
    ConnectionIdAlgo* connIdAlgo) noexcept {
  CHECK(connIdAlgo);
  if (serverConn_) {
    serverConn_->connIdAlgo = connIdAlgo;
  }
}

void QuicServerTransport::setServerConnectionIdRejector(
    ServerConnectionIdRejector* connIdRejector) noexcept {
  CHECK(connIdRejector);
  if (serverConn_) {
    serverConn_->connIdRejector = connIdRejector;
  }
}

quic::Expected<void, QuicError> QuicServerTransport::onReadData(
    const folly::SocketAddress& localAddress,
    ReceivedUdpPacket&& udpPacket,
    const folly::SocketAddress& peerAddress) {
  ServerEvents::ReadData readData;
  readData.peerAddress = peerAddress;
  readData.localAddress = localAddress;
  readData.udpPacket = std::move(udpPacket);
  bool waitingForFirstPacket = !hasReceivedUdpPackets(*conn_);
  uint64_t prevWritableBytes = serverConn_->writableBytesLimit
      ? *serverConn_->writableBytesLimit
      : std::numeric_limits<uint64_t>::max();
  auto readDataResult = onServerReadData(*serverConn_, readData);
  if (readDataResult.hasError()) {
    return quic::make_unexpected(readDataResult.error());
  }
  processPendingData(true);

  if (closeState_ == CloseState::CLOSED) {
    return {};
  }
  if (!notifiedRouting_ && routingCb_ && conn_->serverConnectionId) {
    notifiedRouting_ = true;
    routingCb_->onConnectionIdAvailable(
        shared_from_this(), *conn_->serverConnectionId);
  }
  if (connSetupCallback_ && waitingForFirstPacket &&
      hasReceivedUdpPackets(*conn_)) {
    connSetupCallback_->onFirstPeerPacketProcessed();
  }

  uint64_t curWritableBytes = serverConn_->writableBytesLimit
      ? *serverConn_->writableBytesLimit
      : std::numeric_limits<uint64_t>::max();

  // If we've increased our writable bytes limit after processing incoming data
  // and we were previously blocked from writing probes, fire the PTO alarm
  if (serverConn_->transportSettings.enableWritableBytesLimit &&
      serverConn_->numProbesWritableBytesLimited &&
      prevWritableBytes < curWritableBytes) {
    auto ptoAlarmResult = onPTOAlarm(*serverConn_);
    if (ptoAlarmResult.hasError()) {
      return ptoAlarmResult;
    }
    serverConn_->numProbesWritableBytesLimited = 0;
  }

  auto sessionTicketResult = maybeWriteNewSessionTicket();
  if (sessionTicketResult.hasError()) {
    return sessionTicketResult;
  }
  maybeNotifyConnectionIdBound();
  maybeNotifyHandshakeFinished();
  maybeNotifyConnectionIdRetired();
  maybeIssueConnectionIds();
  maybeNotifyTransportReady();
  conn_->pathManager->maybeReapUnusedPaths();
  return {};
}

void QuicServerTransport::accept(folly::Optional<QuicVersion> quicVersion) {
  registerAllTransportKnobParamHandlers();
  setIdleTimer();
  updateFlowControlStateWithSettings(
      conn_->flowControlState, conn_->transportSettings);
  // Override zeroRttSourceTokenMatchingPolicy for MVFST_PRIMING
  if (quicVersion && *quicVersion == QuicVersion::MVFST_PRIMING) {
    serverConn_->transportSettings.zeroRttSourceTokenMatchingPolicy =
        ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
  }
  serverConn_->serverHandshakeLayer->initialize(
      getFollyEventbase(),
      this,
      std::move(quicVersion),
      std::make_unique<DefaultAppTokenValidator>(serverConn_));
}

quic::Expected<void, QuicError> QuicServerTransport::writeData() {
  if (!conn_->clientConnectionId || !conn_->serverConnectionId) {
    return {};
  }
  auto version = conn_->version.value_or(*(conn_->originalVersion));
  const ConnectionId& srcConnId = *conn_->serverConnectionId;
  const ConnectionId& destConnId = *conn_->clientConnectionId;
  if (closeState_ == CloseState::CLOSED) {
    if (conn_->peerConnectionError &&
        hasReceivedUdpPacketsAtLastCloseSent(*conn_)) {
      // The peer sent us an error, we are in draining state now.
      return {};
    }
    if (hasReceivedUdpPacketsAtLastCloseSent(*conn_) &&
        hasNotReceivedNewPacketsSinceLastCloseSent(*conn_)) {
      // We did not receive any new packets, do not sent a new close frame.
      return {};
    }
    updateLargestReceivedUdpPacketsAtLastCloseSent(*conn_);
    if (conn_->oneRttWriteCipher) {
      CHECK(conn_->oneRttWriteHeaderCipher);
      writeShortClose(
          *socket_,
          *conn_,
          destConnId,
          conn_->localConnectionError,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher);
    }
    if (conn_->handshakeWriteCipher) {
      CHECK(conn_->handshakeWriteHeaderCipher);
      writeLongClose(
          *socket_,
          *conn_,
          srcConnId,
          destConnId,
          LongHeader::Types::Handshake,
          conn_->localConnectionError,
          *conn_->handshakeWriteCipher,
          *conn_->handshakeWriteHeaderCipher,
          version);
    }
    if (conn_->initialWriteCipher) {
      CHECK(conn_->initialHeaderCipher);
      writeLongClose(
          *socket_,
          *conn_,
          srcConnId,
          destConnId,
          LongHeader::Types::Initial,
          conn_->localConnectionError,
          *conn_->initialWriteCipher,
          *conn_->initialHeaderCipher,
          version);
    }
    return {};
  }
  uint64_t packetLimit =
      (isConnectionPaced(*conn_)
           ? conn_->pacer->updateAndGetWriteBatchSize(Clock::now())
           : conn_->transportSettings.writeConnectionDataPacketsLimit);
  // At the end of this function, clear out any probe packets credit we didn't
  // use.
  SCOPE_EXIT {
    conn_->pendingEvents.numProbePackets = {};
  };
  if (conn_->initialWriteCipher) {
    auto res = handleInitialWriteDataCommon(srcConnId, destConnId, packetLimit);
    if (res.hasError()) {
      return quic::make_unexpected(res.error());
    }
    packetLimit -= res->packetsWritten;
    serverConn_->numHandshakeBytesSent += res->bytesWritten;
    if (!packetLimit && !conn_->pendingEvents.anyProbePackets()) {
      return {};
    }
  }
  if (conn_->handshakeWriteCipher) {
    auto res =
        handleHandshakeWriteDataCommon(srcConnId, destConnId, packetLimit);
    if (res.hasError()) {
      return quic::make_unexpected(res.error());
    }
    packetLimit -= res->packetsWritten;
    serverConn_->numHandshakeBytesSent += res->bytesWritten;
    if (!packetLimit && !conn_->pendingEvents.anyProbePackets()) {
      return {};
    }
  }
  if (conn_->oneRttWriteCipher) {
    CHECK(conn_->oneRttWriteHeaderCipher);
    auto writeLoopBeginTime = Clock::now();
    auto nonDsrPath =
        [&](auto limit) -> quic::Expected<WriteQuicDataResult, QuicError> {
      auto result = writeQuicDataToSocket(
          *socket_,
          *conn_,
          srcConnId /* src */,
          destConnId /* dst */,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher,
          version,
          limit,
          writeLoopBeginTime);
      if (result.hasError()) {
        return quic::make_unexpected(result.error());
      }
      return result.value();
    };
    auto dsrPath =
        [&](auto limit) -> quic::Expected<WriteQuicDataResult, QuicError> {
      auto bytesBefore = conn_->lossState.totalBytesSent;
      // The DSR path can't write probes.
      // This is packetsWritte, probesWritten, bytesWritten.
      auto dsrResult = writePacketizationRequest(
          *serverConn_,
          destConnId,
          limit,
          *conn_->oneRttWriteCipher,
          writeLoopBeginTime);
      if (dsrResult.hasError()) {
        return quic::make_unexpected(dsrResult.error());
      }
      auto result = WriteQuicDataResult{
          dsrResult.value(), 0, conn_->lossState.totalBytesSent - bytesBefore};
      return result;
    };
    auto pathValidationWrites =
        [&](auto limit) -> quic::Expected<WriteQuicDataResult, QuicError> {
      auto result = writePathValidationDataForAlternatePaths(
          *socket_,
          *conn_,
          srcConnId /* src */,
          destConnId /* dst */,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher,
          version,
          limit,
          writeLoopBeginTime);
      if (result.hasError()) {
        return quic::make_unexpected(result.error());
      }
      return result.value();
    };
    // We need a while loop because both paths write streams from the same
    // queue, which can result in empty writes.
    while (packetLimit) {
      auto totalSentBefore = conn_->lossState.totalBytesSent;
      // Give the non-DSR path a chance first for things like ACKs and flow
      // control.
      auto written = nonDsrPath(packetLimit);
      if (written.hasError()) {
        return quic::make_unexpected(written.error());
      }
      // For both paths we only consider full packets against the packet
      // limit. While this is slightly more aggressive than the intended
      // packet limit it also helps ensure that small packets don't cause
      // us to underutilize the link when mixing between DSR and non-DSR.
      packetLimit -= written->bytesWritten / conn_->udpSendPacketLen;
      if (packetLimit && congestionControlWritableBytes(*serverConn_)) {
        auto dsrWritten = dsrPath(packetLimit);
        if (dsrWritten.hasError()) {
          return quic::make_unexpected(dsrWritten.error());
        }
        packetLimit -= dsrWritten->bytesWritten / conn_->udpSendPacketLen;
      }
      if (totalSentBefore == conn_->lossState.totalBytesSent) {
        // We haven't written anything with either path, so we're done.
        break;
      }
    }
    auto written = pathValidationWrites(packetLimit);
    if (written.hasError()) {
      return quic::make_unexpected(written.error());
    }
  }

  return maybeInitiateKeyUpdate(*conn_);
}

void QuicServerTransport::closeTransport() {
  if (!serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    QUIC_STATS(conn_->statsCallback, onServerUnfinishedHandshake);
    if (handshakeFinishedCb_) {
      handshakeFinishedCb_->onHandshakeUnfinished();
      handshakeFinishedCb_ = nullptr;
    }
  }
  serverConn_->serverHandshakeLayer->cancel();
  // Clear out pending data.
  serverConn_->pendingZeroRttData.reset();
  serverConn_->pendingOneRttData.reset();
  onServerClose(*serverConn_);
}

void QuicServerTransport::unbindConnection() {
  if (routingCb_) {
    auto routingCb = routingCb_;
    routingCb_ = nullptr;
    CHECK(conn_->clientChosenDestConnectionId);
    if (conn_->serverConnectionId) {
      auto connectionIds =
          conn_->selfConnectionIds; // We pass a copy as this transport might be
                                    // deleted.
      routingCb->onConnectionUnbound(
          this,
          std::make_pair(
              getOriginalPeerAddress(), *conn_->clientChosenDestConnectionId),
          connectionIds);
    }
  }
}

bool QuicServerTransport::hasWriteCipher() const {
  return conn_->oneRttWriteCipher != nullptr;
}

bool QuicServerTransport::hasReadCipher() const {
  return conn_->readCodec != nullptr &&
      conn_->readCodec->getOneRttReadCipher() != nullptr;
}

std::shared_ptr<QuicTransportBaseLite> QuicServerTransport::sharedGuard() {
  return shared_from_this();
}

void QuicServerTransport::setClientConnectionId(
    const ConnectionId& clientConnectionId) {
  conn_->clientConnectionId = clientConnectionId;
  auto& cid = conn_->peerConnectionIds.emplace_back(
      clientConnectionId, kInitialConnectionIdSequenceNumber);
  cid.inUse = true;
}

void QuicServerTransport::setClientChosenDestConnectionId(
    const ConnectionId& clientChosenDestConnectionId) {
  conn_->clientChosenDestConnectionId = clientChosenDestConnectionId;
}

void QuicServerTransport::onCryptoEventAvailable() noexcept {
  try {
    VLOG(10) << "onCryptoEventAvailable " << *this;
    if (closeState_ != CloseState::OPEN) {
      VLOG(10) << "Got crypto event after connection closed " << *this;
      return;
    }
    [[maybe_unused]] auto self = sharedGuard();
    auto handshakeResult = updateHandshakeState(*serverConn_);
    if (handshakeResult.hasError()) {
      closeImpl(handshakeResult.error());
      return;
    }
    processPendingData(false);
    // pending data may contain connection close
    if (closeState_ == CloseState::CLOSED) {
      return;
    }
    auto sessionTicketResult = maybeWriteNewSessionTicket();
    if (sessionTicketResult.hasError()) {
      closeImpl(sessionTicketResult.error());
      return;
    }
    maybeNotifyConnectionIdBound();
    maybeNotifyHandshakeFinished();
    maybeIssueConnectionIds();
    auto writeResult = writeSocketData();
    if (writeResult.hasError()) {
      closeImpl(writeResult.error());
      return;
    }
    maybeNotifyTransportReady();
  } catch (const QuicTransportException& ex) {
    VLOG(4) << "onCryptoEventAvailable() error " << ex.what() << " " << *this;
    closeImpl(QuicError(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << "onCryptoEventAvailable() error " << ex.what() << " " << *this;
    closeImpl(QuicError(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const std::exception& ex) {
    LOG(ERROR) << "read() error " << ex.what() << " " << *this;
    closeImpl(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string(ex.what())));
  }
}

void QuicServerTransport::handleTransportKnobParams(
    const TransportKnobParams& params) {
  for (const auto& param : params) {
    auto maybeParamHandler = transportKnobParamHandlers_.find(param.id);
    TransportKnobParamId knobParamId = TransportKnobParamId::UNKNOWN;
    if (TransportKnobParamId::_is_valid(param.id)) {
      knobParamId = TransportKnobParamId::_from_integral(param.id);
    }
    if (maybeParamHandler != transportKnobParamHandlers_.end()) {
      auto result = (maybeParamHandler->second)(*this, param.val);
      if (result.has_value()) {
        QUIC_STATS(conn_->statsCallback, onTransportKnobApplied, knobParamId);
      } else {
        QUIC_STATS(conn_->statsCallback, onTransportKnobError, knobParamId);
      }
    } else {
      QUIC_STATS(conn_->statsCallback, onTransportKnobError, knobParamId);
    }
  }
}

void QuicServerTransport::processPendingData(bool async) {
  // The case when both 0-rtt and 1-rtt pending data are ready to be processed
  // but neither had been shouldn't happen.
  // This is shared pointer because the lamda below (auto func) does a copy
  // for std::function for a reason not understood.
  std::shared_ptr<std::vector<ServerEvents::ReadData>> pendingData;
  if (conn_->readCodec && conn_->readCodec->getOneRttReadCipher()) {
    pendingData = std::move(serverConn_->pendingOneRttData);
    // It's possible that 0-rtt packets are received after CFIN, we are not
    // dealing with that much level of reordering.
    serverConn_->pendingZeroRttData.reset();
  } else if (conn_->readCodec && conn_->readCodec->getZeroRttReadCipher()) {
    pendingData = std::move(serverConn_->pendingZeroRttData);
  }
  if (pendingData) {
    // Move the pending data out so that we don't ever add new data to the
    // pending data.
    VLOG_IF(10, !pendingData->empty())
        << "Processing pending data size=" << pendingData->size() << " "
        << *this;
    auto func = [pendingData = std::move(pendingData), this](auto) {
      for (auto& pendingPacket : *pendingData) {
        onNetworkData(
            pendingPacket.localAddress,
            NetworkData(std::move(pendingPacket.udpPacket)),
            pendingPacket.peerAddress);
        if (closeState_ == CloseState::CLOSED) {
          // The pending data could potentially contain a connection close, or
          // the app could have triggered a connection close with an error. It
          // is not useful to continue the handshake.
          return;
        }
        // The app could have triggered a graceful close from the callbacks,
        // in which case we should continue with the handshake and processing
        // the remaining data because it could potentially have a FIN which
        // could end the graceful close.
      }
    };
    if (async) {
      runOnEvbAsync(std::move(func));
    } else {
      func(shared_from_this());
    }
  }
}

bool QuicServerTransport::shouldWriteNewSessionTicket() {
  if (!newSessionTicketWrittenTimestamp_) {
    // No session ticket has been written yet, we should write one.
    return true;
  }
  // Conditions for writing more session tickets after the first one:
  // 1. includeCwndHintsInSessionTicket transport setting is set
  // 2. The current BDP is either smaller than or more than twice
  // the last one we sent in a session ticket
  // 3. We haven't sent any session ticket in the last
  // kMinIntervalBetweenSessionTickets

  if (conn_->transportSettings.includeCwndHintsInSessionTicket &&
      conn_->congestionController &&
      Clock::now() - newSessionTicketWrittenTimestamp_.value() >
          kMinIntervalBetweenSessionTickets) {
    const auto& targetBDP = conn_->congestionController->getBDP();
    bool bdpChangedSinceLastHint =
        !newSessionTicketWrittenCwndHint_.has_value() ||
        targetBDP / 2 > *newSessionTicketWrittenCwndHint_ ||
        targetBDP < *newSessionTicketWrittenCwndHint_;
    if (bdpChangedSinceLastHint) {
      return true;
    }
  }
  return false;
}

quic::Expected<void, QuicError>
QuicServerTransport::maybeWriteNewSessionTicket() {
  if (shouldWriteNewSessionTicket() &&
      serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    if (conn_->qLogger) {
      conn_->qLogger->addTransportStateUpdate(kWriteNst);
    }
    newSessionTicketWrittenTimestamp_ = Clock::now();
    Optional<uint64_t> cwndHint = std::nullopt;
    if (conn_->transportSettings.includeCwndHintsInSessionTicket &&
        conn_->congestionController) {
      const auto& bdp = conn_->congestionController->getBDP();
      VLOG(7) << "Writing a new session ticket with cwnd hint=" << bdp;
      cwndHint = bdp;
      newSessionTicketWrittenCwndHint_ = cwndHint;
    }
    AppToken appToken;
    auto transportParamsResult = createTicketTransportParameters(
        conn_->transportSettings.idleTimeout.count(),
        conn_->transportSettings.maxRecvPacketSize,
        conn_->transportSettings.advertisedInitialConnectionFlowControlWindow,
        conn_->transportSettings
            .advertisedInitialBidiLocalStreamFlowControlWindow,
        conn_->transportSettings
            .advertisedInitialBidiRemoteStreamFlowControlWindow,
        conn_->transportSettings.advertisedInitialUniStreamFlowControlWindow,
        conn_->transportSettings.advertisedInitialMaxStreamsBidi,
        conn_->transportSettings.advertisedInitialMaxStreamsUni,
        conn_->transportSettings.advertisedExtendedAckFeatures,
        cwndHint);
    if (transportParamsResult.hasError()) {
      return quic::make_unexpected(transportParamsResult.error());
    }
    appToken.transportParams = std::move(transportParamsResult.value());
    appToken.sourceAddresses = serverConn_->tokenSourceAddresses;
    appToken.version = conn_->version.value();
    // If a client connects to server for the first time and doesn't attempt
    // early data, tokenSourceAddresses will not be set because
    // validateAndUpdateSourceAddressToken is not called in this case.
    // So checking if source address token is empty here and adding peerAddr
    // if so.
    // TODO accumulate recent source tokens
    if (appToken.sourceAddresses.empty()) {
      appToken.sourceAddresses.push_back(conn_->peerAddress.getIPAddress());
    }
    if (conn_->earlyDataAppParamsGetter) {
      appToken.appParams = conn_->earlyDataAppParamsGetter();
    }
    auto result =
        serverConn_->serverHandshakeLayer->writeNewSessionTicket(appToken);
    if (result.hasError()) {
      return quic::make_unexpected(result.error());
    }
  }
  return {};
}

void QuicServerTransport::maybeNotifyConnectionIdRetired() {
  if (!conn_->transportSettings.disableMigration && routingCb_ &&
      !conn_->connIdsRetiringSoon->empty() &&
      serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    for (const auto& connId : *conn_->connIdsRetiringSoon) {
      routingCb_->onConnectionIdRetired(*this, connId);
    }
    conn_->connIdsRetiringSoon->clear();
  }
}

void QuicServerTransport::maybeNotifyConnectionIdBound() {
  // make this connId bound only when the keys are available
  if (!notifiedConnIdBound_ && routingCb_ &&
      conn_->serverConnectionId.has_value() &&
      serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    notifiedConnIdBound_ = true;
    routingCb_->onConnectionIdBound(shared_from_this());
  }
}

void QuicServerTransport::maybeNotifyHandshakeFinished() {
  if (serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    if (handshakeFinishedCb_) {
      handshakeFinishedCb_->onHandshakeFinished();
      handshakeFinishedCb_ = nullptr;
    }
    if (connSetupCallback_ && !handshakeDoneNotified_) {
      connSetupCallback_->onFullHandshakeDone();
      handshakeDoneNotified_ = true;
    }
  }
}

void QuicServerTransport::maybeIssueConnectionIds() {
  // If the peer specifies that they have a limit of 1,000,000 connection
  // ids then only issue a small number at first, since the server still
  // needs to be able to search through all issued ids for routing.
  const uint64_t maximumIdsToIssue = maximumConnectionIdsToIssue(*conn_);
  if (!conn_->transportSettings.disableMigration &&
      (conn_->selfConnectionIds.size() < maximumIdsToIssue) &&
      serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    CHECK(conn_->transportSettings.statelessResetTokenSecret.has_value());

    // Make sure size of selfConnectionIds is not larger than maximumIdsToIssue
    for (size_t i = conn_->selfConnectionIds.size(); i < maximumIdsToIssue;
         ++i) {
      auto newConnIdData = serverConn_->createAndAddNewSelfConnId();
      if (!newConnIdData.has_value()) {
        return;
      }

      CHECK(routingCb_);
      routingCb_->onConnectionIdAvailable(
          shared_from_this(), newConnIdData->connId);

      NewConnectionIdFrame frame(
          newConnIdData->sequenceNumber,
          0,
          newConnIdData->connId,
          *newConnIdData->token);
      sendSimpleFrame(*conn_, std::move(frame));
    }
  }
}

void QuicServerTransport::maybeNotifyTransportReady() {
  if (!transportReadyNotified_ && connSetupCallback_ && hasWriteCipher()) {
    if (conn_->qLogger) {
      conn_->qLogger->addTransportStateUpdate(kTransportReady);
    }
    transportReadyNotified_ = true;
    connSetupCallback_->onTransportReady();

    // This is a new connection. Update QUIC Stats
    QUIC_STATS(conn_->statsCallback, onNewConnection);
  }
}

void QuicServerTransport::setShouldRegisterKnobParamHandlerFn(
    ShouldRegisterKnobParamHandlerFn fn) {
  shouldRegisterKnobParamHandlerFn_ = std::move(fn);
}

void QuicServerTransport::registerTransportKnobParamHandler(
    uint64_t paramId,
    std::function<quic::Expected<void, QuicError>(
        QuicServerTransport&,
        TransportKnobParam::Val)>&& handler) {
  // No validation callback, allow all parameters
  if (!shouldRegisterKnobParamHandlerFn_) {
    transportKnobParamHandlers_.emplace(paramId, std::move(handler));
    return;
  }
  // Register based on validation callback
  if (TransportKnobParamId::_is_valid(paramId) &&
      shouldRegisterKnobParamHandlerFn_(
          TransportKnobParamId::_from_integral(paramId))) {
    transportKnobParamHandlers_.emplace(paramId, std::move(handler));
  }
}

void QuicServerTransport::setBufAccessor(BufAccessor* bufAccessor) {
  CHECK(bufAccessor);
  conn_->bufAccessor = bufAccessor;
}

const std::shared_ptr<const folly::AsyncTransportCertificate>
QuicServerTransport::getPeerCertificate() const {
  const auto handshakeLayer = serverConn_->serverHandshakeLayer;
  if (handshakeLayer) {
    return handshakeLayer->getState().clientCert();
  }
  return nullptr;
}

const std::shared_ptr<const folly::AsyncTransportCertificate>
QuicServerTransport::getSelfCertificate() const {
  const auto handshakeLayer = serverConn_->serverHandshakeLayer;
  if (handshakeLayer) {
    return handshakeLayer->getState().serverCert();
  }
  return nullptr;
}

void QuicServerTransport::onTransportKnobs(BufPtr knobBlob) {
  if (knobBlob->length() > 0) {
    std::string serializedKnobs = std::string(
        reinterpret_cast<const char*>(knobBlob->data()), knobBlob->length());
    VLOG(4) << "Received transport knobs: " << serializedKnobs;
    auto params = parseTransportKnobs(serializedKnobs);
    if (params.has_value()) {
      handleTransportKnobParams(*params);
    } else {
      QUIC_STATS(
          conn_->statsCallback,
          onTransportKnobError,
          TransportKnobParamId::UNKNOWN);
    }
  }
}

void QuicServerTransport::verifiedClientAddress() {
  if (serverConn_) {
    serverConn_->isClientAddrVerified = true;
    conn_->writableBytesLimit.reset();
  }
}

void QuicServerTransport::registerAllTransportKnobParamHandlers() {
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val val) -> quic::Expected<void, QuicError> {
        auto server_conn = serverTransport.serverConn_;
        if (static_cast<bool>(std::get<uint64_t>(val))) {
          server_conn->udpSendPacketLen = server_conn->peerMaxUdpPayloadSize;
          VLOG(3)
              << "Knob param received, udpSendPacketLen is forcibly set to max UDP payload size advertised by peer";
        }
        return {};
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CC_ALGORITHM_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val val) -> quic::Expected<void, QuicError> {
        auto server_conn = serverTransport.serverConn_;
        auto cctype =
            static_cast<CongestionControlType>(std::get<uint64_t>(val));
        VLOG(3) << "Knob param received, set congestion control type to "
                << congestionControlTypeToString(cctype);
        if (cctype == server_conn->congestionController->type()) {
          return {};
        }
        serverTransport.setCongestionControl(cctype);
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto server_conn = serverTransport.serverConn_;
        auto val = std::get<uint64_t>(value);
        uint8_t numerator = (val / 100);
        uint8_t denominator = (val - (numerator * 100));
        VLOG(3) << "Knob param received, set STARTUP rtt factor to ("
                << unsigned(numerator) << "," << unsigned(denominator) << ")";
        server_conn->transportSettings.startupRttFactor =
            std::make_pair(numerator, denominator);
        return {};
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::DEFAULT_RTT_FACTOR_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto server_conn = serverTransport.serverConn_;
        auto val = std::get<uint64_t>(value);
        auto numerator = (uint8_t)(val / 100);
        auto denominator = (uint8_t)(val - (numerator * 100));
        VLOG(3) << "Knob param received, set DEFAULT rtt factor to ("
                << unsigned(numerator) << "," << unsigned(denominator) << ")";
        server_conn->transportSettings.defaultRttFactor =
            std::make_pair(numerator, denominator);
        return {};
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        // Safely check if value is a uint64_t
        const uint64_t* valPtr = std::get_if<uint64_t>(&value);
        if (!valPtr) {
          auto errMsg =
              "Received invalid type for MAX_PACING_RATE_KNOB KnobParam: expected uint64_t";
          VLOG(3) << errMsg;
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, errMsg));
        }

        const uint64_t val = *valPtr;

        auto& maxPacingRateKnobState =
            serverTransport.serverConn_->maxPacingRateKnobState;
        if (maxPacingRateKnobState.frameOutOfOrderDetected) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "MAX_PACING_RATE_KNOB frame out of order detected"));
        }

        if (maxPacingRateKnobState.lastMaxRateBytesPerSec ==
                std::numeric_limits<uint64_t>::max() &&
            maxPacingRateKnobState.lastMaxRateBytesPerSec == val) {
          maxPacingRateKnobState.frameOutOfOrderDetected = true;
          QUIC_STATS(
              serverTransport.serverConn_->statsCallback,
              onTransportKnobOutOfOrder,
              TransportKnobParamId::MAX_PACING_RATE_KNOB);
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "MAX_PACING_RATE_KNOB frame out of order detected"));
        }

        VLOG(3) << "Knob param received, set max pacing rate to ("
                << unsigned(val) << " bytes per second)";
        (void)serverTransport.setMaxPacingRate(val);
        maxPacingRateKnobState.lastMaxRateBytesPerSec = val;
        return {};
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        // Safely check if value is a string
        const std::string* valPtr = std::get_if<std::string>(&value);
        if (!valPtr) {
          auto errMsg =
              "Received invalid type for MAX_PACING_RATE_KNOB_SEQUENCED KnobParam: expected string";
          VLOG(3) << errMsg;
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, errMsg));
        }

        const std::string& val = *valPtr;
        std::string rateBytesPerSecStr, seqNumStr;
        if (!folly::split(',', val, rateBytesPerSecStr, seqNumStr)) {
          std::string errMsg = fmt::format(
              "MAX_PACING_RATE_KNOB_SEQUENCED frame value {} is not in expected format: "
              "{{rate}},{{sequenceNumber}}",
              val);
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }

        auto maybeRateBytesPerSec = folly::tryTo<uint64_t>(rateBytesPerSecStr);
        if (maybeRateBytesPerSec.hasError()) {
          std::string errMsg = fmt::format(
              "MAX_PACING_RATE_KNOB_SEQUENCED frame received with invalid rate {}",
              rateBytesPerSecStr);
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }

        auto expectedSeqNum = folly::tryTo<uint64_t>(seqNumStr);
        if (expectedSeqNum.hasError()) {
          std::string errMsg = fmt::format(
              "MAX_PACING_RATE_KNOB_SEQUENCED frame received with invalid sequence number {}",
              seqNumStr);
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }

        if (serverTransport.serverConn_->maybeLastMaxPacingRateKnobSeqNum >=
            make_optional(expectedSeqNum.value())) {
          QUIC_STATS(
              serverTransport.serverConn_->statsCallback,
              onTransportKnobOutOfOrder,
              TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED);
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "MAX_PACING_RATE_KNOB_SEQUENCED frame received out of order"));
        }

        VLOG(3) << fmt::format(
            "MAX_PACING_RATE_KNOB_SEQUENCED frame received with rate {} bytes/sec "
            "and sequence number {}",
            maybeRateBytesPerSec.value(),
            expectedSeqNum.value());
        (void)serverTransport.setMaxPacingRate(maybeRateBytesPerSec.value());
        serverTransport.serverConn_->maybeLastMaxPacingRateKnobSeqNum =
            expectedSeqNum.value();
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CC_EXPERIMENTAL),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val val) -> quic::Expected<void, QuicError> {
        auto server_conn = serverTransport.serverConn_;
        if (server_conn->congestionController) {
          auto enableExperimental = static_cast<bool>(std::get<uint64_t>(val));
          server_conn->congestionController->setExperimental(
              enableExperimental);
          VLOG(3) << fmt::format(
              "CC_EXPERIMENTAL KnobParam received, setting experimental={} "
              "settings for congestion controller. Current congestion controller={}",
              enableExperimental,
              congestionControlTypeToString(
                  server_conn->congestionController->type()));
        }
        return {};
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::SHORT_HEADER_PADDING_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        serverTransport.serverConn_->transportSettings.paddingModulo = val;
        VLOG(3) << fmt::format(
            "SHORT_HEADER_PADDING_KNOB KnobParam received, setting paddingModulo={}",
            val);
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::FIXED_SHORT_HEADER_PADDING_KNOB),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        serverTransport.serverConn_->transportSettings.fixedShortHeaderPadding =
            val;
        VLOG(3) << fmt::format(
            "FIXED_SHORT_HEADER_PADDING_KNOB KnobParam received, setting fixedShortHeaderPadding={}",
            val);
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::PACER_EXPERIMENTAL),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val val) -> quic::Expected<void, QuicError> {
        auto server_conn = serverTransport.serverConn_;
        if (server_conn->pacer) {
          auto enableExperimental = static_cast<bool>(std::get<uint64_t>(val));
          server_conn->pacer->setExperimental(enableExperimental);
          VLOG(3) << fmt::format(
              "PACER_EXPERIMENTAL KnobParam received, "
              "setting experimental={} for pacer",
              enableExperimental);
        }
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::KEEPALIVE_ENABLED),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        VLOG(3) << "KEEPALIVE_ENABLED KnobParam received: " << val;
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.enableKeepalive = static_cast<bool>(val);
        if (val >= 5000) {
          server_conn->transportSettings.keepAliveTimeout =
              std::chrono::milliseconds(val);
        }
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        const std::string* valPtr = std::get_if<std::string>(&value);
        if (!valPtr) {
          auto errMsg =
              "Received invalid type for ACK_FREQUENCY_POLICY KnobParam: expected string";
          VLOG(3) << errMsg;
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, errMsg));
        }

        const std::string& val = *valPtr;
        CongestionControlConfig::AckFrequencyConfig ackFrequencyConfig;
        bool parseSuccess = false;
        try {
          parseSuccess = folly::split(
              ',',
              val,
              ackFrequencyConfig.ackElicitingThreshold,
              ackFrequencyConfig.reorderingThreshold,
              ackFrequencyConfig.minRttDivisor,
              ackFrequencyConfig.useSmallThresholdDuringStartup);
          // Sanity check the values.
          parseSuccess = parseSuccess &&
              ackFrequencyConfig.ackElicitingThreshold > 1 &&
              ackFrequencyConfig.reorderingThreshold > 1 &&
              ackFrequencyConfig.minRttDivisor > 0;
        } catch (std::exception&) {
          parseSuccess = false;
        }
        if (parseSuccess) {
          VLOG(3) << fmt::format(
              "ACK_FREQUENCY_POLICY KnobParam received, "
              "ackElicitingThreshold={}, "
              "reorderingThreshold={}, "
              "minRttDivisor={}, "
              "useSmallThresholdDuringStartup={}, "
              "raw knob={}",
              ackFrequencyConfig.ackElicitingThreshold,
              ackFrequencyConfig.reorderingThreshold,
              ackFrequencyConfig.minRttDivisor,
              ackFrequencyConfig.useSmallThresholdDuringStartup,
              val);
          serverTransport.conn_->transportSettings.ccaConfig
              .ackFrequencyConfig = ackFrequencyConfig;
        } else {
          auto errMsg = fmt::format(
              "Received invalid KnobParam for ACK_FREQUENCY_POLICY: {}", val);
          VLOG(3) << errMsg;
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::PACING_TIMER_TICK),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.pacingTickInterval =
            std::chrono::microseconds(val);
        VLOG(3) << "PACING_TIMER_TICK KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::DEFAULT_STREAM_PRIORITY),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<std::string>(value);
        auto serverConn = serverTransport.serverConn_;
        uint8_t level;
        bool incremental;
        bool parseSuccess = false;
        try {
          parseSuccess = folly::split(',', val, level, incremental);
        } catch (std::exception&) {
          parseSuccess = false;
        }
        if (!parseSuccess || level > 7) {
          auto errMsg = fmt::format(
              "Received invalid KnobParam for DEFAULT_STREAM_PRIORITY: {}",
              val);
          VLOG(3) << errMsg;
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }
        serverConn->transportSettings.defaultPriority =
            HTTPPriorityQueue::Priority(level, incremental);
        VLOG(3) << "DEFAULT_STREAM_PRIORITY KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CC_CONFIG),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<std::string>(value);
        try {
          serverTransport.conn_->transportSettings.ccaConfig =
              parseCongestionControlConfig(val);
          VLOG(3) << "CC_CONFIG KnobParam received: " << val;
          return {};
        } catch (const std::exception& ex) {
          std::string errorMsg = fmt::format(
              "Failed to parse congestion control config: {}", ex.what());
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR, std::move(errorMsg)));
        }
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CONNECTION_MIGRATION),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.disableMigration =
            !static_cast<bool>(val);
        VLOG(3) << "CONNECTION_MIGRATION KnobParam received: "
                << static_cast<bool>(val);
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::KEY_UPDATE_INTERVAL),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        if (val < 1000 || val > 8ul * 1000 * 1000) {
          std::string errMsg = fmt::format(
              "KEY_UPDATE_INTERVAL KnobParam received with invalid value: {}",
              val);
          return quic::make_unexpected(
              QuicError(TransportErrorCode::INTERNAL_ERROR, std::move(errMsg)));
        }
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.initiateKeyUpdate = val > 0;
        server_conn->transportSettings.keyUpdatePacketCountInterval = val;
        VLOG(3) << "KEY_UPDATE_INTERVAL KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::AUTOTUNE_RECV_STREAM_FLOW_CONTROL),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        bool autotuneReceiveStreamFlowControl =
            static_cast<bool>(std::get<uint64_t>(value));
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.autotuneReceiveStreamFlowControl =
            autotuneReceiveStreamFlowControl;
        VLOG(3) << "AUTOTUNE_RECV_STREAM_FLOW_CONTROL KnobParam received: "
                << autotuneReceiveStreamFlowControl;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::INFLIGHT_REORDERING_THRESHOLD),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        bool inflightReorderingThreshold =
            static_cast<bool>(std::get<uint64_t>(value));
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.useInflightReorderingThreshold =
            inflightReorderingThreshold;
        VLOG(3) << "INFLIGHT_REORDERING_THRESHOLD KnobParam received: "
                << inflightReorderingThreshold;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::PACER_MIN_BURST_PACKETS),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.minBurstPackets =
            val <= kMinBurstPacketsLimit ? val : kMinBurstPacketsLimit;
        VLOG(3) << "PACER_MIN_BURST_PACKETS KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::MAX_WRITE_CONN_DATA_PKT_LIM),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = std::get<uint64_t>(value);
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.writeConnectionDataPacketsLimit =
            val <= kMaxWriteConnectionDataPacketLimit
            ? val
            : kMaxWriteConnectionDataPacketLimit;
        VLOG(3) << "MAX_WRITE_CONN_DATA_PKT_LIM KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::USE_NEW_PRIORITY_QUEUE),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        bool useNewPriorityQueue = static_cast<bool>(std::get<uint64_t>(value));
        auto serverConn = serverTransport.serverConn_;
        VLOG(3) << "USE_NEW_PRIORITY_QUEUE KnobParam received: "
                << useNewPriorityQueue;
        auto refreshResult = serverConn->streamManager->updatePriorityQueueImpl(
            useNewPriorityQueue);
        if (refreshResult.hasError()) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "Refresh transport settings failed"));
        } else {
          std::swap(
              useNewPriorityQueue,
              serverConn->transportSettings.useNewPriorityQueue);
        }
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::MIN_STREAM_BUF_THRESH),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = static_cast<uint16_t>(std::get<uint64_t>(value));
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.minStreamBufThresh =
            val <= kMinStreamBufThreshLimit ? val : kMinStreamBufThreshLimit;
        VLOG(3) << "MIN_STREAM_BUF_THRESH KnobParam received: " << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::EXCESS_CWND_PCT_FOR_IMMINENT_STREAMS),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto val = static_cast<uint16_t>(std::get<uint64_t>(value));
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.excessCwndPctForImminentStreams =
            val <= kMaxExcessCwndPctForImminentStreams
            ? val
            : kMaxExcessCwndPctForImminentStreams;
        VLOG(3) << "EXCESS_CWND_PCT_FOR_IMMINENT_STREAMS KnobParam received: "
                << val;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::ALLOW_DUPLICATE_PROBES),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        bool allowDuplicateProbesInSameWrite =
            static_cast<bool>(std::get<uint64_t>(value));
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.allowDuplicateProbesInSameWrite =
            allowDuplicateProbesInSameWrite;
        VLOG(3) << "ALLOW_DUPLICATE_CLONES KnobParam received: "
                << allowDuplicateProbesInSameWrite;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::SEND_CLOSE_ON_IDLE_TIMEOUT),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        bool sendCloseOnIdleTimeout =
            static_cast<bool>(std::get<uint64_t>(value));
        auto server_conn = serverTransport.serverConn_;
        server_conn->transportSettings.alwaysSendConnectionCloseOnIdleTimeout =
            sendCloseOnIdleTimeout;
        VLOG(3) << "SEND_CLOSE_ON_IDLE_TIMEOUT KnobParam received: "
                << sendCloseOnIdleTimeout;
        return {};
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::MAX_PTO),
      [](QuicServerTransport& serverTransport,
         TransportKnobParam::Val value) -> quic::Expected<void, QuicError> {
        auto maxPTOCount = std::get<uint64_t>(value);
        if (maxPTOCount < 3 || maxPTOCount > 15) {
          return quic::make_unexpected(QuicError(
              TransportErrorCode::INTERNAL_ERROR,
              "MAX_PTO KnobParam value out of bounds"));
        }
        auto serverConn = serverTransport.serverConn_;
        serverConn->transportSettings.maxNumPTOs = maxPTOCount;
        VLOG(3) << "MAX_PTO KnobParam received: " << maxPTOCount;
        return {};
      });
}

QuicConnectionStats QuicServerTransport::getConnectionsStats() const {
  QuicConnectionStats connStats = QuicTransportBase::getConnectionsStats();
  if (serverConn_) {
    connStats.localAddress = serverConn_->serverAddr;
  }
  return connStats;
}

QuicSocket::WriteResult QuicServerTransport::writeBufMeta(
    StreamId id,
    const BufferMeta& data,
    bool eof,
    ByteEventCallback* cb) {
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
    auto stream =
        CHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));
    if (!stream->writable()) {
      return quic::make_unexpected(LocalErrorCode::STREAM_CLOSED);
    }
    if (!stream->dsrSender) {
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    if (stream->currentWriteOffset == 0 && stream->pendingWrites.empty()) {
      // If nothing has been written ever, meta writing isn't allowed.
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    // Register DeliveryCallback for the data + eof offset.
    if (cb) {
      auto dataLength = data.length + (eof ? 1 : 0);
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
    auto writeResult = writeBufMetaToQuicStream(*stream, data, eof);
    if (!writeResult.has_value()) {
      VLOG(4) << __func__ << " streamId=" << id << " "
              << writeResult.error().message << " " << *this;
      exceptionCloseWhat_ = writeResult.error().message;
      closeImpl(QuicError(
          QuicErrorCode(*writeResult.error().code.asTransportErrorCode()),
          std::string("writeChain() error")));
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

QuicSocket::WriteResult QuicServerTransport::setDSRPacketizationRequestSender(
    StreamId id,
    std::unique_ptr<DSRPacketizationRequestSender> sender) {
  if (closeState_ != CloseState::OPEN) {
    return quic::make_unexpected(LocalErrorCode::CONNECTION_CLOSED);
  }
  if (isReceivingStream(conn_->nodeType, id)) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  [[maybe_unused]] auto self = sharedGuard();
  try {
    // Check whether stream exists before calling getStream to avoid
    // creating a peer stream if it does not exist yet.
    if (!conn_->streamManager->streamExists(id)) {
      return quic::make_unexpected(LocalErrorCode::STREAM_NOT_EXISTS);
    }
    auto stream =
        CHECK_NOTNULL(conn_->streamManager->getStream(id).value_or(nullptr));
    // Only allow resetting it back to nullptr once set.
    if (stream->dsrSender && sender != nullptr) {
      return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
    }
    if (stream->dsrSender != nullptr) {
      // If any of these aren't true then we are abandoning stream data.
      CHECK_EQ(stream->writeBufMeta.length, 0) << stream;
      CHECK_EQ(stream->lossBufMetas.size(), 0) << stream;
      CHECK_EQ(stream->retransmissionBufMetas.size(), 0) << stream;
      stream->dsrSender->release();
      stream->dsrSender = nullptr;
      return {};
    }
    if (!stream->writable()) {
      return quic::make_unexpected(LocalErrorCode::STREAM_CLOSED);
    }
    stream->dsrSender = std::move(sender);
    // Default to disabling opportunistic ACKing for DSR since it causes extra
    // writes and spurious losses.
    conn_->transportSettings.opportunisticAcking = false;
    // Also turn on the default of 5 nexts per stream which has empirically
    // shown good results.
    if (conn_->transportSettings.priorityQueueWritesPerStream == 1) {
      conn_->transportSettings.priorityQueueWritesPerStream = 5;
      conn_->streamManager->setWriteQueueMaxNextsPerStream(5);
    }

    // Fow now, no appLimited or appIdle update here since we are not writing
    // either BufferMetas yet. The first BufferMeta write will update it.
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

CipherInfo QuicServerTransport::getOneRttCipherInfo() const {
  return {
      *conn_->oneRttWriteCipher->getKey(),
      *serverConn_->serverHandshakeLayer->getState().cipher(),
      conn_->oneRttWriteHeaderCipher->getKey()->clone()};
}

Optional<std::string> QuicServerTransport::getSni() {
  auto logging =
      serverConn_->serverHandshakeLayer->getState().handshakeLogging();
  if (!logging || !logging->clientSni.has_value()) {
    return std::nullopt;
  }

  return logging->clientSni.value();
}

void QuicServerTransport::logTimeBasedStats() const {
  if (!conn_ || !conn_->statsCallback) {
    return;
  }
  // Ignore 0 inflight bytes samples for now to not affect sampling.
  if (conn_->lossState.inflightBytes > 0) {
    QUIC_STATS(
        conn_->statsCallback,
        onInflightBytesSample,
        conn_->lossState.inflightBytes);
  }
  // Only consider RTT sample if handshake is done.
  if (serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    QUIC_STATS(
        conn_->statsCallback,
        onRttSample,
        std::chrono::duration_cast<std::chrono::milliseconds>(
            conn_->lossState.srtt)
            .count());
  }
  if (conn_->congestionController) {
    // We only log the bandwidth if it's available and the units are bytes/s.
    auto bandwidth = conn_->congestionController->getBandwidth();
    if (bandwidth.has_value() &&
        bandwidth->unitType == Bandwidth::UnitType::BYTES) {
      uint64_t bitsPerSecSample = bandwidth->normalize() * 8;
      QUIC_STATS(conn_->statsCallback, onBandwidthSample, bitsPerSecSample);
    }
  }
}

Optional<std::vector<TransportParameter>>
QuicServerTransport::getPeerTransportParams() const {
  if (serverConn_ && serverConn_->serverHandshakeLayer) {
    auto maybeParams =
        serverConn_->serverHandshakeLayer->getClientTransportParams();
    if (maybeParams) {
      return maybeParams->parameters;
    }
  }
  return std::nullopt;
}

void QuicServerTransport::setCongestionControl(CongestionControlType type) {
  if (!conn_->congestionControllerFactory) {
    // If you are hitting this, update your application to call
    // setCongestionControllerFactory() on the transport to share one factory
    // for all transports.
    conn_->congestionControllerFactory =
        std::make_shared<ServerCongestionControllerFactory>();
    LOG(WARNING)
        << "A congestion controller factory is not set. Using a default per-transport instance.";
  }
  QuicTransportBase::setCongestionControl(type);
}

void QuicServerTransport::onPathValidationResult(const PathInfo& pathInfo) {
  if (pathInfo.id == conn_->currentPathId) {
    if (pathInfo.status == PathStatus::NotValid) {
      // We should fallback to the previously validated path or close the
      // connection if we don't have one.

      // This will reverse what ServerStateMachine::onConnectionMigration()
      // did. The reason it's here is that we want to be able to close the
      // connection, which is only possible from the transport.
      auto migrationReverted = false;
      if (conn_->fallbackPathId) {
        auto fallbackPath = conn_->pathManager->getPath(*conn_->fallbackPathId);
        if (fallbackPath) {
          conn_->currentPathId = fallbackPath->id;
          conn_->peerAddress = fallbackPath->peerAddress;
          auto ccaRestored =
              conn_->pathManager
                  ->maybeRestoreCongestionControlAndRttStateForCurrentPath();
          if (!ccaRestored) {
            conn_->congestionController =
                conn_->congestionControllerFactory->makeCongestionController(
                    *conn_,
                    conn_->transportSettings.defaultCongestionController);
          }
          conn_->fallbackPathId.reset();
          migrationReverted = true;
        }
      }

      if (!migrationReverted) {
        closeImpl(QuicError(
            QuicErrorCode(TransportErrorCode::INVALID_MIGRATION),
            std::string(
                "Path validation timed out. No fallback path available")));
      }
    } else if (pathInfo.status == PathStatus::Validated) {
      // We're on a validated path. We don't need a fallback anymore.
      conn_->fallbackPathId.reset();
    }
  }
}

} // namespace quic
