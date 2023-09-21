/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/Bbr.h>
#include <quic/dsr/frontend/WriteFunctions.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/handshake/AppToken.h>
#include <quic/server/handshake/DefaultAppTokenValidator.h>
#include <quic/server/handshake/StatelessResetGenerator.h>
#include <quic/state/TransportSettingsFunctions.h>

#include <folly/Optional.h>
#include <quic/common/TransportKnobs.h>
#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace quic {

QuicServerTransport::QuicServerTransport(
    folly::EventBase* evb,
    std::unique_ptr<QuicAsyncUDPSocketWrapper> sock,
    ConnectionSetupCallback* connSetupCb,
    ConnectionCallback* connStreamsCb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx,
    std::unique_ptr<CryptoFactory> cryptoFactory,
    PacketNum startingPacketNum)
    : QuicServerTransport(
          evb,
          std::move(sock),
          connSetupCb,
          connStreamsCb,
          std::move(ctx),
          std::move(cryptoFactory)) {
  conn_->ackStates = AckStates(startingPacketNum);
}

QuicServerTransport::QuicServerTransport(
    folly::EventBase* evb,
    std::unique_ptr<QuicAsyncUDPSocketWrapper> sock,
    ConnectionSetupCallback* connSetupCb,
    ConnectionCallback* connStreamsCb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx,
    std::unique_ptr<CryptoFactory> cryptoFactory,
    bool useConnectionEndWithErrorCallback)
    : QuicTransportBase(
          evb,
          std::move(sock),
          useConnectionEndWithErrorCallback),
      ctx_(std::move(ctx)),
      wrappedObserverContainer_(this) {
  auto tempConn = std::make_unique<QuicServerConnectionState>(
      FizzServerQuicHandshakeContext::Builder()
          .setFizzServerContext(ctx_)
          .setCryptoFactory(std::move(cryptoFactory))
          .build());
  tempConn->serverAddr = socket_->address();
  serverConn_ = tempConn.get();
  conn_.reset(tempConn.release());
  conn_->observerContainer = wrappedObserverContainer_.getWeakPtr();
  setConnectionSetupCallback(connSetupCb);
  setConnectionCallback(connStreamsCb);
  registerAllTransportKnobParamHandlers();
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
    std::unique_ptr<QuicAsyncUDPSocketWrapper> sock,
    ConnectionSetupCallback* connSetupCb,
    ConnectionCallback* connStreamsCb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx,
    bool useConnectionEndWithErrorCallback) {
  return std::make_shared<QuicServerTransport>(
      evb,
      std::move(sock),
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
  serverConn_->serverConnIdParams.assign(std::move(params));
}

void QuicServerTransport::setTransportStatsCallback(
    QuicTransportStatsCallback* statsCallback) noexcept {
  if (conn_) {
    conn_->statsCallback = statsCallback;
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

void QuicServerTransport::onReadData(
    const folly::SocketAddress& peer,
    NetworkDataSingle&& networkData) {
  ServerEvents::ReadData readData;
  readData.peer = peer;
  readData.networkData = std::move(networkData);
  bool waitingForFirstPacket = !hasReceivedPackets(*conn_);
  uint64_t prevWritableBytes = serverConn_->writableBytesLimit
      ? *serverConn_->writableBytesLimit
      : std::numeric_limits<uint64_t>::max();
  onServerReadData(*serverConn_, readData);
  processPendingData(true);

  if (closeState_ == CloseState::CLOSED) {
    return;
  }
  if (!notifiedRouting_ && routingCb_ && conn_->serverConnectionId) {
    notifiedRouting_ = true;
    routingCb_->onConnectionIdAvailable(
        shared_from_this(), *conn_->serverConnectionId);
  }
  if (connSetupCallback_ && waitingForFirstPacket &&
      hasReceivedPackets(*conn_)) {
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
    onPTOAlarm(*serverConn_);
    serverConn_->numProbesWritableBytesLimited = 0;
  }

  maybeWriteNewSessionTicket();
  maybeNotifyConnectionIdBound();
  maybeNotifyHandshakeFinished();
  maybeNotifyConnectionIdRetired();
  maybeIssueConnectionIds();
  maybeNotifyTransportReady();
}

void QuicServerTransport::accept() {
  setIdleTimer();
  updateFlowControlStateWithSettings(
      conn_->flowControlState, conn_->transportSettings);
  serverConn_->serverHandshakeLayer->initialize(
      qEvbPtr_.load()->getBackingEventBase(),
      this,
      std::make_unique<DefaultAppTokenValidator>(serverConn_));
}

void QuicServerTransport::writeData() {
  if (!conn_->clientConnectionId || !conn_->serverConnectionId) {
    return;
  }
  auto version = conn_->version.value_or(*(conn_->originalVersion));
  const ConnectionId& srcConnId = *conn_->serverConnectionId;
  const ConnectionId& destConnId = *conn_->clientConnectionId;
  if (closeState_ == CloseState::CLOSED) {
    if (conn_->peerConnectionError &&
        hasReceivedPacketsAtLastCloseSent(*conn_)) {
      // The peer sent us an error, we are in draining state now.
      return;
    }
    if (hasReceivedPacketsAtLastCloseSent(*conn_) &&
        hasNotReceivedNewPacketsSinceLastCloseSent(*conn_)) {
      // We did not receive any new packets, do not sent a new close frame.
      return;
    }
    updateLargestReceivedPacketsAtLastCloseSent(*conn_);
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
    return;
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
    auto& initialCryptoStream =
        *getCryptoStream(*conn_->cryptoState, EncryptionLevel::Initial);
    CryptoStreamScheduler initialScheduler(*conn_, initialCryptoStream);
    auto& numProbePackets =
        conn_->pendingEvents.numProbePackets[PacketNumberSpace::Initial];
    if ((numProbePackets && initialCryptoStream.retransmissionBuffer.size() &&
         conn_->outstandings.packetCount[PacketNumberSpace::Initial]) ||
        initialScheduler.hasData() || toWriteInitialAcks(*conn_)) {
      CHECK(conn_->initialWriteCipher);
      CHECK(conn_->initialHeaderCipher);

      auto res = writeCryptoAndAckDataToSocket(
          *socket_,
          *conn_,
          srcConnId /* src */,
          destConnId /* dst */,
          LongHeader::Types::Initial,
          *conn_->initialWriteCipher,
          *conn_->initialHeaderCipher,
          version,
          packetLimit);

      packetLimit -= res.packetsWritten;
      serverConn_->numHandshakeBytesSent += res.bytesWritten;
    }
    if (!packetLimit && !conn_->pendingEvents.anyProbePackets()) {
      return;
    }
  }
  if (conn_->handshakeWriteCipher) {
    auto& handshakeCryptoStream =
        *getCryptoStream(*conn_->cryptoState, EncryptionLevel::Handshake);
    CryptoStreamScheduler handshakeScheduler(*conn_, handshakeCryptoStream);
    auto& numProbePackets =
        conn_->pendingEvents.numProbePackets[PacketNumberSpace::Handshake];
    if ((conn_->outstandings.packetCount[PacketNumberSpace::Handshake] &&
         handshakeCryptoStream.retransmissionBuffer.size() &&
         numProbePackets) ||
        handshakeScheduler.hasData() || toWriteHandshakeAcks(*conn_)) {
      CHECK(conn_->handshakeWriteCipher);
      CHECK(conn_->handshakeWriteHeaderCipher);
      auto res = writeCryptoAndAckDataToSocket(
          *socket_,
          *conn_,
          srcConnId /* src */,
          destConnId /* dst */,
          LongHeader::Types::Handshake,
          *conn_->handshakeWriteCipher,
          *conn_->handshakeWriteHeaderCipher,
          version,
          packetLimit);

      packetLimit -= res.packetsWritten;
      serverConn_->numHandshakeBytesSent += res.bytesWritten;
    }
    if (!packetLimit && !conn_->pendingEvents.anyProbePackets()) {
      return;
    }
  }
  if (conn_->oneRttWriteCipher) {
    CHECK(conn_->oneRttWriteHeaderCipher);
    auto writeLoopBeginTime = Clock::now();
    auto nonDsrPath = [&](auto limit) {
      return writeQuicDataToSocket(
          *socket_,
          *conn_,
          srcConnId /* src */,
          destConnId /* dst */,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher,
          version,
          limit,
          writeLoopBeginTime);
    };
    auto dsrPath = [&](auto limit) {
      auto bytesBefore = conn_->lossState.totalBytesSent;
      // The DSR path can't write probes.
      // This is packetsWritte, probesWritten, bytesWritten.
      return WriteQuicDataResult{
          writePacketizationRequest(
              *serverConn_,
              destConnId,
              limit,
              *conn_->oneRttWriteCipher,
              writeLoopBeginTime),
          0,
          conn_->lossState.totalBytesSent - bytesBefore};
    };
    // We need a while loop because both paths write streams from the same
    // queue, which can result in empty writes.
    while (packetLimit) {
      auto totalSentBefore = conn_->lossState.totalBytesSent;
      // Give the non-DSR path a chance first for things like ACKs and flow
      // control.
      auto written = nonDsrPath(packetLimit);
      // For both paths we only consider full packets against the packet
      // limit. While this is slightly more aggressive than the intended
      // packet limit it also helps ensure that small packets don't cause
      // us to underutilize the link when mixing between DSR and non-DSR.
      packetLimit -= written.bytesWritten / conn_->udpSendPacketLen;
      if (packetLimit && congestionControlWritableBytes(*serverConn_)) {
        written = dsrPath(packetLimit);
        packetLimit -= written.bytesWritten / conn_->udpSendPacketLen;
      }
      if (totalSentBefore == conn_->lossState.totalBytesSent) {
        // We haven't written anything with either path, so we're done.
        break;
      }
    }
  }
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
      routingCb->onConnectionUnbound(
          this,
          std::make_pair(
              getOriginalPeerAddress(), *conn_->clientChosenDestConnectionId),
          conn_->selfConnectionIds);
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

std::shared_ptr<QuicTransportBase> QuicServerTransport::sharedGuard() {
  return shared_from_this();
}

void QuicServerTransport::setClientConnectionId(
    const ConnectionId& clientConnectionId) {
  conn_->clientConnectionId.assign(clientConnectionId);
  conn_->peerConnectionIds.emplace_back(
      clientConnectionId, kInitialSequenceNumber);
}

void QuicServerTransport::setClientChosenDestConnectionId(
    const ConnectionId& clientChosenDestConnectionId) {
  conn_->clientChosenDestConnectionId.assign(clientChosenDestConnectionId);
}

void QuicServerTransport::onCryptoEventAvailable() noexcept {
  try {
    VLOG(10) << "onCryptoEventAvailable " << *this;
    if (closeState_ != CloseState::OPEN) {
      VLOG(10) << "Got crypto event after connection closed " << *this;
      return;
    }
    FOLLY_MAYBE_UNUSED auto self = sharedGuard();
    updateHandshakeState(*serverConn_);
    processPendingData(false);
    // pending data may contain connection close
    if (closeState_ == CloseState::CLOSED) {
      return;
    }
    maybeWriteNewSessionTicket();
    maybeNotifyConnectionIdBound();
    maybeNotifyHandshakeFinished();
    maybeIssueConnectionIds();
    writeSocketData();
    maybeNotifyTransportReady();
  } catch (const QuicTransportException& ex) {
    VLOG(4) << "onCryptoEventAvailable() error " << ex.what() << " " << *this;
    closeImpl(QuicError(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << "onCryptoEventAvailable() error " << ex.what() << " " << *this;
    closeImpl(QuicError(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const std::exception& ex) {
    VLOG(4) << "read() error " << ex.what() << " " << *this;
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
      try {
        (maybeParamHandler->second)(this, param.val);
        QUIC_STATS(conn_->statsCallback, onTransportKnobApplied, knobParamId);
      } catch (const std::exception& /* ex */) {
        QUIC_STATS(conn_->statsCallback, onTransportKnobError, knobParamId);
      }
    } else {
      QUIC_STATS(conn_->statsCallback, onTransportKnobError, knobParamId);
    }
  }
}

void QuicServerTransport::processPendingData(bool async) {
  // The case when both 0-rtt and 1-rtt pending data are ready to be processed
  // but neither had been shouldn't happen
  std::unique_ptr<std::vector<ServerEvents::ReadData>> pendingData;
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
    auto func = [pendingData = std::move(pendingData)](auto self) {
      auto serverPtr = static_cast<QuicServerTransport*>(self.get());
      for (auto& pendingPacket : *pendingData) {
        serverPtr->onNetworkData(
            pendingPacket.peer,
            NetworkData(
                std::move(pendingPacket.networkData.packet.buf),
                pendingPacket.networkData.receiveTimePoint));
        if (serverPtr->closeState_ == CloseState::CLOSED) {
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

void QuicServerTransport::maybeWriteNewSessionTicket() {
  if (!newSessionTicketWritten_ && !ctx_->getSendNewSessionTicket() &&
      serverConn_->serverHandshakeLayer->isHandshakeDone()) {
    if (conn_->qLogger) {
      conn_->qLogger->addTransportStateUpdate(kWriteNst);
    }
    newSessionTicketWritten_ = true;
    AppToken appToken;
    appToken.transportParams = createTicketTransportParameters(
        conn_->transportSettings.idleTimeout.count(),
        conn_->transportSettings.maxRecvPacketSize,
        conn_->transportSettings.advertisedInitialConnectionFlowControlWindow,
        conn_->transportSettings
            .advertisedInitialBidiLocalStreamFlowControlWindow,
        conn_->transportSettings
            .advertisedInitialBidiRemoteStreamFlowControlWindow,
        conn_->transportSettings.advertisedInitialUniStreamFlowControlWindow,
        conn_->transportSettings.advertisedInitialMaxStreamsBidi,
        conn_->transportSettings.advertisedInitialMaxStreamsUni);
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
    serverConn_->serverHandshakeLayer->writeNewSessionTicket(appToken);
  }
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
  if (!notifiedConnIdBound_ && routingCb_ && conn_->serverConnectionId &&
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
  }
}

void QuicServerTransport::registerTransportKnobParamHandler(
    uint64_t paramId,
    std::function<void(QuicServerTransport*, TransportKnobParam::Val)>&&
        handler) {
  transportKnobParamHandlers_.emplace(paramId, std::move(handler));
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

void QuicServerTransport::onTransportKnobs(Buf knobBlob) {
  if (knobBlob->length() > 0) {
    std::string serializedKnobs = std::string(
        reinterpret_cast<const char*>(knobBlob->data()), knobBlob->length());
    VLOG(4) << "Received transport knobs: " << serializedKnobs;
    auto params = parseTransportKnobs(serializedKnobs);
    if (params.hasValue()) {
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
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val val) {
        CHECK(serverTransport);
        auto server_conn = serverTransport->serverConn_;
        if (static_cast<bool>(std::get<uint64_t>(val))) {
          server_conn->udpSendPacketLen = server_conn->peerMaxUdpPayloadSize;
          VLOG(3)
              << "Knob param received, udpSendPacketLen is forcibly set to max UDP payload size advertised by peer";
        }
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CC_ALGORITHM_KNOB),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val val) {
        CHECK(serverTransport);
        auto server_conn = serverTransport->serverConn_;
        auto cctype =
            static_cast<CongestionControlType>(std::get<uint64_t>(val));
        VLOG(3) << "Knob param received, set congestion control type to "
                << congestionControlTypeToString(cctype);
        if (cctype == server_conn->congestionController->type()) {
          return;
        }
        serverTransport->setCongestionControl(cctype);
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto server_conn = serverTransport->serverConn_;
        auto val = std::get<uint64_t>(value);
        uint8_t numerator = (val / 100);
        uint8_t denominator = (val - (numerator * 100));
        VLOG(3) << "Knob param received, set STARTUP rtt factor to ("
                << unsigned(numerator) << "," << unsigned(denominator) << ")";
        server_conn->transportSettings.startupRttFactor =
            std::make_pair(numerator, denominator);
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::DEFAULT_RTT_FACTOR_KNOB),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto server_conn = serverTransport->serverConn_;
        auto val = std::get<uint64_t>(value);
        auto numerator = (uint8_t)(val / 100);
        auto denominator = (uint8_t)(val - (numerator * 100));
        VLOG(3) << "Knob param received, set DEFAULT rtt factor to ("
                << unsigned(numerator) << "," << unsigned(denominator) << ")";
        server_conn->transportSettings.defaultRttFactor =
            std::make_pair(numerator, denominator);
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::MAX_PACING_RATE_KNOB),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<uint64_t>(value);

        // Check if the server should process this knob, i.e should set the max
        // pacing rate to the given value. Currently there is a possibility that
        // MAX_PACING_RATE_KNOB frames arrive out of order, causing incorrect
        // max pacing rate to be set on the transport, i.e. the rate is set to a
        // low value when it should be set to max value (i.e. disabled pacing).
        //
        // To address this issue while a new knob ID is introduced (where
        // sequence number is included alongside the max pacing rate value),
        // this handler will not call setMaxPacingRate(val) after it has
        // received two consecutive frames where pacing is disabled, so that it
        // can prevent the abovementioned scenario where the frames should be:
        //
        //   NO_PACING --> PACING --> NO_PACING
        //
        // due to out-of-order, becomes:
        //
        //   NO_PACING --> NO_PACING --> PACING
        auto& maxPacingRateKnobState =
            serverTransport->serverConn_->maxPacingRateKnobState;
        if (maxPacingRateKnobState.frameOutOfOrderDetected) {
          throw std::runtime_error(
              "MAX_PACING_RATE_KNOB frame out of order detected");
        }

        // if pacing is already disabled and the new value is disabling it,
        // assume there has been an out of order frame and stop processing
        // pacing frames
        if (maxPacingRateKnobState.lastMaxRateBytesPerSec ==
                std::numeric_limits<uint64_t>::max() &&
            maxPacingRateKnobState.lastMaxRateBytesPerSec == val) {
          maxPacingRateKnobState.frameOutOfOrderDetected = true;
          QUIC_STATS(
              serverTransport->serverConn_->statsCallback,
              onTransportKnobOutOfOrder,
              TransportKnobParamId::MAX_PACING_RATE_KNOB);
          throw std::runtime_error(
              "MAX_PACING_RATE_KNOB frame out of order detected");
        }

        VLOG(3) << "Knob param received, set max pacing rate to ("
                << unsigned(val) << " bytes per second)";
        serverTransport->setMaxPacingRate(val);
        maxPacingRateKnobState.lastMaxRateBytesPerSec = val;
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(
          TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<std::string>(value);
        std::string rateBytesPerSecStr, seqNumStr;
        if (!folly::split(',', val, rateBytesPerSecStr, seqNumStr)) {
          std::string errMsg = fmt::format(
              "MAX_PACING_RATE_KNOB_SEQUENCED frame value {} is not in expected format: "
              "{{rate}},{{sequenceNumber}}",
              val);
          throw std::runtime_error(errMsg);
        }

        auto maybeRateBytesPerSec = folly::tryTo<uint64_t>(rateBytesPerSecStr);
        if (maybeRateBytesPerSec.hasError()) {
          std::string errMsg = fmt::format(
              "MAX_PACING_RATE_KNOB_SEQUENCED frame received with invalid rate {}",
              rateBytesPerSecStr);
          throw std::runtime_error(errMsg);
        }

        auto expectedSeqNum = folly::tryTo<uint64_t>(seqNumStr);
        if (expectedSeqNum.hasError()) {
          std::string errMsg = fmt::format(
              "MAX_PACING_RATE_KNOB_SEQUENCED frame received with invalid sequence number {}",
              seqNumStr);
          throw std::runtime_error(errMsg);
        }

        if (serverTransport->serverConn_->maybeLastMaxPacingRateKnobSeqNum >=
            folly::make_optional(expectedSeqNum.value())) {
          QUIC_STATS(
              serverTransport->serverConn_->statsCallback,
              onTransportKnobOutOfOrder,
              TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED);
          throw std::runtime_error(
              "MAX_PACING_RATE_KNOB_SEQUENCED frame received out of order");
        }

        VLOG(3) << fmt::format(
            "MAX_PACING_RATE_KNOB_SEQUENCED frame received with rate {} bytes/sec "
            "and sequence number {}",
            maybeRateBytesPerSec.value(),
            expectedSeqNum.value());
        serverTransport->setMaxPacingRate(maybeRateBytesPerSec.value());
        serverTransport->serverConn_->maybeLastMaxPacingRateKnobSeqNum =
            expectedSeqNum.value();
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CC_EXPERIMENTAL),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val val) {
        CHECK(serverTransport);
        auto server_conn = serverTransport->serverConn_;
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
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::SHORT_HEADER_PADDING_KNOB),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<uint64_t>(value);
        serverTransport->serverConn_->transportSettings.paddingModulo = val;
        VLOG(3) << fmt::format(
            "SHORT_HEADER_PADDING_KNOB KnobParam received, setting paddingModulo={}",
            val);
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::ADAPTIVE_LOSS_DETECTION),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val val) {
        CHECK(serverTransport);
        auto server_conn = serverTransport->serverConn_;
        auto useAdaptiveLossReorderingThresholds =
            static_cast<bool>(std::get<uint64_t>(val));
        server_conn->transportSettings.useAdaptiveLossReorderingThresholds =
            useAdaptiveLossReorderingThresholds;
        VLOG(3) << fmt::format(
            "ADAPTIVE_LOSS_DETECTION KnobParam received, UseAdaptiveLossReorderingThresholds is now set to {}",
            useAdaptiveLossReorderingThresholds);
      });

  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::PACER_EXPERIMENTAL),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val val) {
        CHECK(serverTransport);
        auto server_conn = serverTransport->serverConn_;
        if (server_conn->pacer) {
          auto enableExperimental = static_cast<bool>(std::get<uint64_t>(val));
          server_conn->pacer->setExperimental(enableExperimental);
          VLOG(3) << fmt::format(
              "PACER_EXPERIMENTAL KnobParam received, "
              "setting experimental={} for pacer",
              enableExperimental);
        }
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::KEEPALIVE_ENABLED),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<uint64_t>(value);
        auto server_conn = serverTransport->serverConn_;
        server_conn->transportSettings.enableKeepalive = static_cast<bool>(val);
        VLOG(3) << "KEEPALIVE_ENABLED KnobParam received: "
                << static_cast<bool>(val);
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::REMOVE_FROM_LOSS_BUFFER),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<uint64_t>(value);
        // Temporarily disabled while we investigate some related bugs.
        VLOG(3) << "REMOVE_FROM_LOSS_BUFFER KnobParam received: "
                << static_cast<bool>(val);
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::ACK_FREQUENCY_POLICY),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<std::string>(value);
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
          serverTransport->conn_->transportSettings.ccaConfig
              .ackFrequencyConfig = ackFrequencyConfig;
        } else {
          auto errMsg = fmt::format(
              "Received invalid KnobParam for ACK_FREQUENCY_POLICY: {}", val);
          VLOG(3) << errMsg;
          throw std::runtime_error(errMsg);
        }
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::FIRE_LOOP_EARLY),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<uint64_t>(value);
        serverTransport->writeLooper_->setFireLoopEarly(static_cast<bool>(val));
        VLOG(3) << "FIRE_LOOP_EARLY KnobParam received: "
                << static_cast<bool>(val);
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::PACING_TIMER_TICK),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<uint64_t>(value);
        auto serverConn = serverTransport->serverConn_;
        serverConn->transportSettings.pacingTickInterval =
            std::chrono::microseconds(val);
        VLOG(3) << "PACING_TIMER_TICK KnobParam received: " << val;
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::DEFAULT_STREAM_PRIORITY),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<std::string>(value);
        auto serverConn = serverTransport->serverConn_;
        uint8_t level;
        bool incremental;
        bool parseSuccess = false;
        try {
          parseSuccess = folly::split(',', val, level, incremental);
        } catch (std::exception&) {
          parseSuccess = false;
        }
        if (!parseSuccess) {
          auto errMsg = fmt::format(
              "Received invalid KnobParam for DEFAULT_STREAM_PRIORITY: {}",
              val);
          VLOG(3) << errMsg;
          throw std::runtime_error(errMsg);
        }
        serverConn->transportSettings.defaultPriority =
            Priority(level, incremental);
        VLOG(3) << "DEFAULT_STREAM_PRIORITY KnobParam received: " << val;
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::WRITE_LOOP_TIME_FRACTION),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<uint64_t>(value);
        auto serverConn = serverTransport->serverConn_;
        serverConn->transportSettings.writeLimitRttFraction = val;
        VLOG(3) << "WRITE_LOOP_TIME_FRACTION KnobParam received: " << val;
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::WRITES_PER_STREAM),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<uint64_t>(value);
        auto serverConn = serverTransport->serverConn_;
        serverConn->transportSettings.priorityQueueWritesPerStream = val;
        serverConn->streamManager->writeQueue().setMaxNextsPerStream(val);
        VLOG(3) << "WRITES_PER_STREAM KnobParam received: " << val;
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CC_CONFIG),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<std::string>(value);
        serverTransport->conn_->transportSettings.ccaConfig =
            parseCongestionControlConfig(val);
        VLOG(3) << "CC_CONFIG KnobParam received: " << val;
      });
  registerTransportKnobParamHandler(
      static_cast<uint64_t>(TransportKnobParamId::CONNECTION_MIGRATION),
      [](QuicServerTransport* serverTransport, TransportKnobParam::Val value) {
        CHECK(serverTransport);
        auto val = std::get<uint64_t>(value);
        auto server_conn = serverTransport->serverConn_;
        server_conn->transportSettings.disableMigration =
            !static_cast<bool>(val);
        VLOG(3) << "CONNECTION_MIGRATION KnobParam received: "
                << static_cast<bool>(val);
      });
}

QuicConnectionStats QuicServerTransport::getConnectionsStats() const {
  QuicConnectionStats connStats = QuicTransportBase::getConnectionsStats();
  if (serverConn_) {
    connStats.localAddress = serverConn_->serverAddr;
  }
  return connStats;
}

CipherInfo QuicServerTransport::getOneRttCipherInfo() const {
  return {
      *conn_->oneRttWriteCipher->getKey(),
      *serverConn_->serverHandshakeLayer->getState().cipher(),
      conn_->oneRttWriteHeaderCipher->getKey()->clone()};
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

} // namespace quic
