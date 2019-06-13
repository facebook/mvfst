/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/QuicServerTransport.h>

#include <quic/server/handshake/AppToken.h>
#include <quic/server/handshake/DefaultAppTokenValidator.h>
#include <quic/server/handshake/StatelessResetGenerator.h>

namespace quic {

QuicServerTransport::QuicServerTransport(
    folly::EventBase* evb,
    std::unique_ptr<folly::AsyncUDPSocket> sock,
    ConnectionCallback& cb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx)
    : QuicTransportBase(evb, std::move(sock)), ctx_(std::move(ctx)) {
  auto tempConn = std::make_unique<QuicServerConnectionState>();
  tempConn->serverAddr = socket_->address();
  serverConn_ = tempConn.get();
  conn_ = std::move(tempConn);
  // TODO: generate this when we can encode the packet sequence number
  // correctly.
  // conn_->nextSequenceNum = folly::Random::secureRandom<PacketNum>();
  setConnectionCallback(&cb);
}

QuicServerTransport::~QuicServerTransport() {
  VLOG(10) << "Destroyed connection to client=" << *this;
  // The caller probably doesn't need the conn callback after destroying the
  // transport.
  connCallback_ = nullptr;
  closeImpl(
      std::make_pair(
          QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
          std::string("Closing from server destructor")),
      false);
}

// TODO: refactor this API so that the factory does not have to create an
// owning reference.
QuicServerTransport::Ptr QuicServerTransport::make(
    folly::EventBase* evb,
    std::unique_ptr<folly::AsyncUDPSocket> sock,
    ConnectionCallback& cb,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx) {
  return std::make_shared<QuicServerTransport>(evb, std::move(sock), cb, ctx);
}

void QuicServerTransport::setRoutingCallback(
    RoutingCallback* callback) noexcept {
  routingCb_ = callback;
}

void QuicServerTransport::setOriginalPeerAddress(
    const folly::SocketAddress& addr) {
  conn_->originalPeerAddress = addr;
  conn_->udpSendPacketLen = addr.getFamily() == AF_INET6
      ? kDefaultV6UDPSendPacketLen
      : kDefaultV4UDPSendPacketLen;
}

void QuicServerTransport::setServerConnectionIdParams(
    ServerConnectionIdParams params) noexcept {
  serverConn_->serverConnIdParams.assign(std::move(params));
}

void QuicServerTransport::setTransportInfoCallback(
    QuicTransportStatsCallback* infoCallback) noexcept {
  if (conn_) {
    conn_->infoCallback = infoCallback;
  }
}

void QuicServerTransport::setConnectionIdAlgo(
    ConnectionIdAlgo* connIdAlgo) noexcept {
  CHECK(connIdAlgo);
  if (conn_) {
    conn_->connIdAlgo = connIdAlgo;
  }
}

void QuicServerTransport::setCongestionControllerFactory(
    std::shared_ptr<CongestionControllerFactory> ccFactory) {
  CHECK(ccFactory);
  ccFactory_ = ccFactory;
  if (conn_) {
    conn_->congestionControllerFactory = ccFactory_;
  }
}

void QuicServerTransport::onReadData(
    const folly::SocketAddress& peer,
    NetworkData&& networkData) {
  ServerEvents::ReadData readData;
  readData.peer = peer;
  readData.networkData = std::move(networkData);
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
  maybeWriteNewSessionTicket();
  maybeNotifyConnectionIdBound();
  maybeNotifyTransportReady();
}

void QuicServerTransport::accept() {
  setIdleTimer();
  updateFlowControlStateWithSettings(
      conn_->flowControlState, conn_->transportSettings);
  serverConn_->serverHandshakeLayer->initialize(
      evb_,
      ctx_,
      this,
      std::make_unique<DefaultAppTokenValidator>(serverConn_));
}

void QuicServerTransport::writeData() {
  if (!conn_->clientConnectionId && !conn_->serverConnectionId) {
    // It is possible for the server to invoke writeData() after receiving a
    // packet that could not per parsed successfully.
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
    if (conn_->oneRttWriteCipher && conn_->readCodec->getOneRttReadCipher()) {
      CHECK(conn_->oneRttWriteHeaderCipher);
      // We do not process handshake data after we are closed. It is
      // possible that we closed the transport while handshake data was
      // pending in which case we would not derive the 1-RTT keys. We
      // shouldn't send a long header at this point, because the client may
      // have already dropped its handshake keys.
      writeShortClose(
          *socket_,
          *conn_,
          destConnId /* dst */,
          conn_->localConnectionError,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher);
    } else if (conn_->initialWriteCipher) {
      CHECK(conn_->initialHeaderCipher);
      writeLongClose(
          *socket_,
          *conn_,
          srcConnId /* src */,
          destConnId /* dst */,
          LongHeader::Types::Initial,
          conn_->localConnectionError,
          *conn_->initialWriteCipher,
          *conn_->initialHeaderCipher,
          version);
    }
    return;
  }

  if (UNLIKELY(!conn_->initialWriteCipher)) {
    // This would be possible if we read a packet from the network which
    // could not be parsed later.
    return;
  }

  uint64_t packetLimit =
      (isConnectionPaced(*conn_)
           ? conn_->congestionController->getPacingRate(Clock::now())
           : conn_->transportSettings.writeConnectionDataPacketsLimit);
  CryptoStreamScheduler initialScheduler(
      *conn_,
      *getCryptoStream(*conn_->cryptoState, fizz::EncryptionLevel::Plaintext));
  CryptoStreamScheduler handshakeScheduler(
      *conn_,
      *getCryptoStream(*conn_->cryptoState, fizz::EncryptionLevel::Handshake));
  if (initialScheduler.hasData() ||
      (conn_->ackStates.initialAckState.needsToSendAckImmediately &&
       hasAcksToSchedule(conn_->ackStates.initialAckState))) {
    CHECK(conn_->initialWriteCipher);
    CHECK(conn_->initialHeaderCipher);
    packetLimit -= writeCryptoAndAckDataToSocket(
        *socket_,
        *conn_,
        srcConnId /* src */,
        destConnId /* dst */,
        LongHeader::Types::Initial,
        *conn_->initialWriteCipher,
        *conn_->initialHeaderCipher,
        version,
        packetLimit);
  }
  if (!packetLimit) {
    return;
  }
  if (handshakeScheduler.hasData() ||
      (conn_->ackStates.handshakeAckState.needsToSendAckImmediately &&
       hasAcksToSchedule(conn_->ackStates.handshakeAckState))) {
    CHECK(conn_->handshakeWriteCipher);
    CHECK(conn_->handshakeWriteHeaderCipher);
    packetLimit -= writeCryptoAndAckDataToSocket(
        *socket_,
        *conn_,
        srcConnId /* src */,
        destConnId /* dst */,
        LongHeader::Types::Handshake,
        *conn_->handshakeWriteCipher,
        *conn_->handshakeWriteHeaderCipher,
        version,
        packetLimit);
  }
  if (!packetLimit) {
    return;
  }
  if (conn_->oneRttWriteCipher) {
    CHECK(conn_->oneRttWriteHeaderCipher);
    writeQuicDataToSocket(
        *socket_,
        *conn_,
        srcConnId /* src */,
        destConnId /* dst */,
        *conn_->oneRttWriteCipher,
        *conn_->oneRttWriteHeaderCipher,
        version,
        packetLimit);
  }
}

void QuicServerTransport::closeTransport() {
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
    // TODO: we need a better way to solve the case that a QuicServerTransport
    // is created and added to the map, but conn.ClientConnectionId doesn't get
    // a legit value.
    const ConnectionId* connId =
        &(*serverConn_->serverConnIdParams->clientConnId);
    if (conn_->clientConnectionId) {
      connId = &(*conn_->clientConnectionId);
    }
    routingCb->onConnectionUnbound(
        std::make_pair(getOriginalPeerAddress(), *connId),
        conn_->serverConnectionId);
  }
}

bool QuicServerTransport::hasWriteCipher() const {
  return conn_->oneRttWriteCipher != nullptr;
}

std::shared_ptr<QuicTransportBase> QuicServerTransport::sharedGuard() {
  return shared_from_this();
}

void QuicServerTransport::onCryptoEventAvailable() noexcept {
  try {
    VLOG(10) << "onCryptoEventAvailable " << *this;
    if (closeState_ != CloseState::OPEN) {
      VLOG(10) << "Got crypto event after connection closed " << *this;
      return;
    }
    updateHandshakeState(*serverConn_);
    processPendingData(false);
    // pending data may contain connection close
    if (closeState_ == CloseState::CLOSED) {
      return;
    }
    maybeWriteNewSessionTicket();
    maybeNotifyConnectionIdBound();
    writeSocketData();
    maybeNotifyTransportReady();
  } catch (const QuicTransportException& ex) {
    VLOG(4) << "onCryptoEventAvailable() error " << ex.what() << " " << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const QuicInternalException& ex) {
    VLOG(4) << "onCryptoEventAvailable() error " << ex.what() << " " << *this;
    closeImpl(
        std::make_pair(QuicErrorCode(ex.errorCode()), std::string(ex.what())));
  } catch (const std::exception& ex) {
    VLOG(4) << "read() error " << ex.what() << " " << *this;
    closeImpl(std::make_pair(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::string(ex.what())));
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
            pendingPacket.peer, std::move(pendingPacket.networkData));
        if (serverPtr->closeState_ == CloseState::CLOSED) {
          // The pending data could potentially contain a connection close, or
          // the app could have triggered a connection close with an error. It
          // is not useful to continue the handshake.
          return;
        }
        // The app could have triggered a graceful close from the callbacks,
        // in which case we should continue with the handshake and processing
        // the reamining data because it could potentially have a FIN which
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
    QUIC_TRACE(fst_trace, *conn_, "write nst");
    newSessionTicketWritten_ = true;
    AppToken appToken;
    appToken.transportParams = createTicketTransportParameters(
        *conn_->version,
        conn_->transportSettings.idleTimeout.count(),
        conn_->transportSettings.maxRecvPacketSize,
        conn_->transportSettings.advertisedInitialConnectionWindowSize,
        conn_->transportSettings.advertisedInitialBidiLocalStreamWindowSize,
        conn_->transportSettings.advertisedInitialBidiRemoteStreamWindowSize,
        conn_->transportSettings.advertisedInitialUniStreamWindowSize,
        std::numeric_limits<uint32_t>::max(),
        std::numeric_limits<uint32_t>::max());
    appToken.sourceAddresses = serverConn_->tokenSourceAddresses;
    // If a client connects to server for the first time and doesn't attempt
    // early data, tokenSourceAddresses will not be set because
    // validateAndUpdateSourceAddressToken is not called in this case.
    // So checking if source address token is empty here and adding peerAddr
    // if so.
    // TODO accumulate recent source tokens
    if (appToken.sourceAddresses.empty()) {
      appToken.sourceAddresses.push_back(conn_->peerAddress.getIPAddress());
    }
    appToken.appParams = connCallback_->serializeEarlyDataAppParams();
    serverConn_->serverHandshakeLayer->writeNewSessionTicket(appToken);
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

void QuicServerTransport::maybeNotifyTransportReady() {
  if (!transportReadyNotified_ && connCallback_ && hasWriteCipher()) {
    QUIC_TRACE(fst_trace, *conn_, "transport ready");
    transportReadyNotified_ = true;
    connCallback_->onTransportReady();
  }
}

} // namespace quic
