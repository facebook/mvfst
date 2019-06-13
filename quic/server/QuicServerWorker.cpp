/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/io/Cursor.h>
#include <folly/system/ThreadId.h>
#include <quic/QuicConstants.h>
#include <quic/common/Timers.h>

#include <quic/server/QuicServerWorker.h>
#include <quic/server/handshake/StatelessResetGenerator.h>

namespace quic {

QuicServerWorker::QuicServerWorker(
    std::shared_ptr<QuicServerWorker::WorkerCallback> callback)
    : callback_(callback), takeoverPktHandler_(this) {}

folly::EventBase* QuicServerWorker::getEventBase() const {
  return evb_;
}

void QuicServerWorker::setSocket(
    std::unique_ptr<folly::AsyncUDPSocket> socket) {
  socket_ = std::move(socket);
  evb_ = socket_->getEventBase();
}

void QuicServerWorker::bind(const folly::SocketAddress& address) {
  DCHECK(!supportedVersions_.empty());
  CHECK(socket_);
  socket_->bind(address);
  socket_->dontFragment(true);
}

void QuicServerWorker::setTransportInfoCallback(
    std::unique_ptr<QuicTransportStatsCallback> infoCallback) noexcept {
  CHECK(infoCallback);
  infoCallback_ = std::move(infoCallback);
}

QuicTransportStatsCallback* QuicServerWorker::getTransportInfoCallback() const
    noexcept {
  return infoCallback_.get();
}

void QuicServerWorker::setConnectionIdAlgo(
    std::unique_ptr<ConnectionIdAlgo> connIdAlgo) noexcept {
  CHECK(connIdAlgo);
  connIdAlgo_ = std::move(connIdAlgo);
}

void QuicServerWorker::setCongestionControllerFactory(
    std::shared_ptr<CongestionControllerFactory> ccFactory) {
  CHECK(ccFactory);
  ccFactory_ = ccFactory;
}

void QuicServerWorker::start() {
  CHECK(socket_);
  if (transportSettings_.pacingEnabled && !pacingTimer_) {
    pacingTimer_ = TimerHighRes::newTimer(
        evb_, transportSettings_.pacingTimerTickInterval);
  }
  socket_->resumeRead(this);
  VLOG(10) << "Registered read on worker=" << this
           << " thread=" << folly::getCurrentThreadID()
           << " processId=" << (int)processId_;
}

void QuicServerWorker::pauseRead() {
  CHECK(socket_);
  socket_->pauseRead();
}

int QuicServerWorker::getFD() {
  CHECK(socket_);
  return socket_->getNetworkSocket().toFd();
}

const folly::SocketAddress& QuicServerWorker::getAddress() const {
  CHECK(socket_);
  return socket_->address();
}

void QuicServerWorker::getReadBuffer(void** buf, size_t* len) noexcept {
  readBuffer_ = folly::IOBuf::create(transportSettings_.maxRecvPacketSize);
  *buf = readBuffer_->writableData();
  *len = transportSettings_.maxRecvPacketSize;
}

void QuicServerWorker::onDataAvailable(
    const folly::SocketAddress& client,
    size_t len,
    bool truncated) noexcept {
  // TODO: we can get better receive time accuracy than this, with
  // SO_TIMESTAMP or SIOCGSTAMP.
  auto packetReceiveTime = Clock::now();
  VLOG(10) << "Worker=" << this
           << " Received data on thread=" << folly::getCurrentThreadID()
           << " processId=" << (int)processId_;
  // Move readBuffer_ first so that we can get rid
  // of it immediately so that if we return early,
  // we've flushed it.
  Buf data = std::move(readBuffer_);
  if (truncated) {
    // This is an error, drop the packet.
    return;
  }
  data->append(len);
  QUIC_STATS(infoCallback_, onPacketReceived);
  QUIC_STATS(infoCallback_, onRead, len);
  handleNetworkData(client, std::move(data), packetReceiveTime);
}

void QuicServerWorker::handleNetworkData(
    const folly::SocketAddress& client,
    Buf data,
    const TimePoint& packetReceiveTime) noexcept {
  try {
    if (shutdown_) {
      VLOG(4) << "Packet received after shutdown, dropping";
      QUIC_STATS(
          infoCallback_, onPacketDropped, PacketDropReason::SERVER_SHUTDOWN);
      return;
    }

    if (!callback_) {
      VLOG(0) << "Worker callback is null.  Dropping packet.";
      QUIC_STATS(
          infoCallback_,
          onPacketDropped,
          PacketDropReason::WORKER_NOT_INITIALIZED);
      return;
    }
    folly::io::Cursor cursor(data.get());
    if (!cursor.canAdvance(sizeof(uint8_t))) {
      VLOG(4) << "Dropping packet too small";
      QUIC_STATS(
          infoCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET);
      return;
    }
    uint8_t initialByte = cursor.readBE<uint8_t>();
    HeaderForm headerForm = getHeaderForm(initialByte);

    if (headerForm == HeaderForm::Short) {
      folly::Expected<ShortHeaderInvariant, TransportErrorCode>
          parsedShortHeader = parseShortHeaderInvariants(initialByte, cursor);
      if (!parsedShortHeader) {
        return tryHandlingAsHealthCheck(client, *data);
      }
      RoutingData routingData(
          headerForm,
          false,
          false,
          std::move(parsedShortHeader->destinationConnId),
          folly::none);
      return forwardNetworkData(
          client,
          std::move(routingData),
          NetworkData(std::move(data), packetReceiveTime));
    }

    folly::Expected<ParsedLongHeaderInvariant, TransportErrorCode>
        parsedLongHeader = parseLongHeaderInvariant(initialByte, cursor);
    if (!parsedLongHeader) {
      return tryHandlingAsHealthCheck(client, *data);
    }

    // TODO: check version before looking at type
    LongHeader::Types longHeaderType = parseLongHeaderType(initialByte);
    bool isInitial = longHeaderType == LongHeader::Types::Initial;
    bool isUsingClientConnId =
        isInitial || longHeaderType == LongHeader::Types::ZeroRtt;

    folly::Optional<std::pair<VersionNegotiationPacket, Buf>>
        versionNegotiationPacket;
    if (rejectNewConnections_ && isInitial) {
      VersionNegotiationPacketBuilder builder(
          parsedLongHeader->invariant.dstConnId,
          parsedLongHeader->invariant.srcConnId,
          std::vector<QuicVersion>{QuicVersion::MVFST_INVALID});
      versionNegotiationPacket =
          folly::make_optional(std::move(builder).buildPacket());
    }
    if (!versionNegotiationPacket) {
      bool negotiationNeeded =
          std::find(
              supportedVersions_.begin(),
              supportedVersions_.end(),
              parsedLongHeader->invariant.version) == supportedVersions_.end();
      if (negotiationNeeded && !isInitial) {
        VLOG(3) << "Dropping non-initial packet due to invalid version";
        QUIC_STATS(
            infoCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET);
        return;
      }
      if (negotiationNeeded) {
        VersionNegotiationPacketBuilder builder(
            parsedLongHeader->invariant.dstConnId,
            parsedLongHeader->invariant.srcConnId,
            supportedVersions_);
        versionNegotiationPacket =
            folly::make_optional(std::move(builder).buildPacket());
      }
    }
    if (versionNegotiationPacket) {
      VLOG(4) << "Version negotiation sent to client=" << client;
      auto len = versionNegotiationPacket->second->computeChainDataLength();
      QUIC_STATS(infoCallback_, onWrite, len);
      QUIC_STATS(infoCallback_, onPacketProcessed);
      QUIC_STATS(infoCallback_, onPacketSent);
      socket_->write(client, std::move(versionNegotiationPacket->second));
      return;
    }

    if (parsedLongHeader->invariant.dstConnId.size() < kMinConnectionIdSize) {
      // drop packet if connId is present but is not valid.
      VLOG(3) << "Dropping packet due to invalid connectionId";
      QUIC_STATS(
          infoCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET);
      return;
    }
    RoutingData routingData(
        headerForm,
        isInitial,
        isUsingClientConnId,
        std::move(parsedLongHeader->invariant.dstConnId),
        std::move(parsedLongHeader->invariant.srcConnId));
    return forwardNetworkData(
        client,
        std::move(routingData),
        NetworkData(std::move(data), packetReceiveTime));
  } catch (const std::exception& ex) {
    // Drop the packet.
    QUIC_STATS(infoCallback_, onPacketDropped, PacketDropReason::PARSE_ERROR);
    VLOG(6) << "Failed to parse packet header " << ex.what();
  }
}

void QuicServerWorker::tryHandlingAsHealthCheck(
    const folly::SocketAddress& client,
    const folly::IOBuf& data) {
  // If we cannot parse the long header then it is not a QUIC invariant
  // packet, so just drop it after checking whether it could be a health
  // check.
  if (!healthCheckToken_) {
    VLOG(4) << "Dropping packet, cannot parse header client=" << client;
    QUIC_STATS(
        infoCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET);
    return;
  }

  folly::IOBufEqualTo eq;
  // TODO: make this constant time, the token might be secret, but we're
  // current assuming it's not.
  if (eq(*healthCheckToken_.value(), data)) {
    // say that we are OK. The response is much smaller than the
    // request, so we are not creating an amplification vector. Also
    // ignore the error code.
    VLOG(4) << "Health check request, response=OK";
    socket_->write(client, folly::IOBuf::copyBuffer("OK"));
  }
}

void QuicServerWorker::forwardNetworkData(
    const folly::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData) {
  // if it's not Client initial or ZeroRtt, AND if the connectionId version
  // mismatches: foward if pktForwarding is enabled else dropPacket
  if (!routingData.isUsingClientConnId &&
      !connIdAlgo_->canParse(routingData.destinationConnId)) {
    if (packetForwardingEnabled_) {
      VLOG(3) << "Forwarding packet with unknown connId version from client="
              << client << " to another process";
      takeoverPktHandler_.forwardPacketToAnotherServer(
          client, std::move(networkData.data), networkData.receiveTimePoint);
      QUIC_STATS(infoCallback_, onPacketForwarded);
      return;
    } else {
      VLOG(3) << "Dropping packet due to unknown connectionId version connId="
              << routingData.destinationConnId.hex();
      QUIC_STATS(
          infoCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET);
    }
    return;
  }
  callback_->routeDataToWorker(
      client, std::move(routingData), std::move(networkData));
}

void QuicServerWorker::setPacingTimer(
    TimerHighRes::SharedPtr pacingTimer) noexcept {
  pacingTimer_ = std::move(pacingTimer);
}

void QuicServerWorker::dispatchPacketData(
    const folly::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData) noexcept {
  DCHECK(socket_);
  QuicServerTransport::Ptr transport;
  bool dropPacket = false;
  auto cit = connectionIdMap_.find(routingData.destinationConnId);
  if (cit != connectionIdMap_.end()) {
    transport = cit->second;
    VLOG(10) << "Found existing connection for CID="
             << routingData.destinationConnId.hex() << " " << *transport;
  } else if (routingData.headerForm != HeaderForm::Long) {
    // Drop the packet if the header form is not long
    VLOG(3) << "Dropping non-long header packet with no connid match CID="
            << routingData.destinationConnId << " headerForm="
            << static_cast<typename std::underlying_type<HeaderForm>::type>(
                   routingData.headerForm)
            << ", workerId=" << (uint32_t)workerId_
            << ", thread=" << folly::getCurrentThreadID();
    // Try forwarding the packet to the old server (if it is enabled)
    dropPacket = true;
  }

  if (!dropPacket && !transport && routingData.sourceConnId) {
    // For LongHeader packets without existing associated connection, try to
    // route with sourceConnId chosen by the peer and IP address of the peer.
    CHECK(transportFactory_);
    // can only route by address.
    auto source = std::make_pair(client, *routingData.sourceConnId);
    auto sit = sourceAddressMap_.find(source);
    if (sit == sourceAddressMap_.end()) {
      // TODO for O-RTT types we need to create new connections to handle
      // the case, where the new server gets packets sent to the old one due
      // to network reordering
      if (!routingData.isInitial) {
        VLOG(3) << "Dropping packet from client=" << client
                << ", workerId=" << (uint32_t)workerId_
                << ", thread=" << folly::getCurrentThreadID();
        dropPacket = true;
      } else {
        VLOG(4) << "Creating new connection for client=" << client
                << ", workerId=" << (uint32_t)workerId_
                << ", thread=" << folly::getCurrentThreadID();

        // This could be a new connection, add it in the map
        // verify that the initial packet is at least min initial bytes
        // to avoid amplification attacks.
        if (networkData.data->computeChainDataLength() <
            kMinInitialPacketSize) {
          // Don't even attempt to forward the packet, just drop it.
          VLOG(3) << "Dropping small initial packet from client=" << client;
          QUIC_STATS(
              infoCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET);
          return;
        }
        // create 'accepting' transport
        auto sock = makeSocket(getEventBase());
        auto trans = transportFactory_->make(
            getEventBase(), std::move(sock), client, ctx_);
        trans->setPacingTimer(pacingTimer_);
        trans->setRoutingCallback(this);
        trans->setSupportedVersions(supportedVersions_);
        trans->setOriginalPeerAddress(client);
        trans->setCongestionControllerFactory(ccFactory_);
        trans->setTransportSettings(transportSettings_);
        trans->setConnectionIdAlgo(connIdAlgo_.get());
        // parameters to create server chosen connection id
        ServerConnectionIdParams serverConnIdParams(
            hostId_, static_cast<uint8_t>(processId_), workerId_);
        serverConnIdParams.clientConnId = *routingData.sourceConnId;
        trans->setServerConnectionIdParams(std::move(serverConnIdParams));
        if (infoCallback_) {
          trans->setTransportInfoCallback(infoCallback_.get());
        }
        trans->accept();
        auto result = sourceAddressMap_.emplace(std::make_pair(
            std::make_pair(client, *routingData.sourceConnId), trans));
        if (!result.second) {
          LOG(ERROR) << "Routing entry already exists for client=" << client
                     << ", client CID=" << routingData.sourceConnId->hex();
          dropPacket = true;
        }
        transport = trans;
      }
    } else {
      transport = sit->second;
      VLOG(4) << "Found existing connection for client=" << client << " "
              << *transport;
    }
  }
  if (LIKELY(!dropPacket)) {
    DCHECK(transport->getEventBase()->isInEventBaseThread());
    transport->onNetworkData(client, std::move(networkData));
    return;
  }
  ServerConnectionIdParams connIdParam =
      connIdAlgo_->parseConnectionId(routingData.destinationConnId);
  if (UNLIKELY(connIdParam.hostId != hostId_)) {
    VLOG(3) << "Dropping packet routed to wrong host, CID="
            << routingData.destinationConnId.hex()
            << ", workerId=" << (uint32_t)workerId_
            << ", hostId=" << (uint32_t)hostId_
            << ", received hostId=" << (uint32_t)connIdParam.hostId;
    QUIC_STATS(
        infoCallback_,
        onPacketDropped,
        PacketDropReason::ROUTING_ERROR_WRONG_HOST);
    return sendResetPacket(
        routingData.headerForm,
        client,
        networkData,
        routingData.destinationConnId);
  }

  if (!packetForwardingEnabled_) {
    QUIC_STATS(
        infoCallback_, onPacketDropped, PacketDropReason::CONNECTION_NOT_FOUND);
    return sendResetPacket(
        routingData.headerForm,
        client,
        networkData,
        routingData.destinationConnId);
  }

  // There's no existing connection for the packet's CID or the client's
  // addr, and doesn't belong to the old server. Send a Reset.
  if (connIdParam.processId == static_cast<uint8_t>(processId_)) {
    QUIC_STATS(
        infoCallback_, onPacketDropped, PacketDropReason::CONNECTION_NOT_FOUND);
    return sendResetPacket(
        routingData.headerForm,
        client,
        networkData,
        routingData.destinationConnId);
  }

  // Optimistically route to another server
  // if the packet type is not Initial and if there is not any connection
  // associated with the given packet
  VLOG(4) << "Forwarding packet from client=" << client
          << " to another process, workerId=" << (uint32_t)workerId_
          << ", processId_=" << (uint32_t) static_cast<uint8_t>(processId_);
  takeoverPktHandler_.forwardPacketToAnotherServer(
      client, std::move(networkData.data), networkData.receiveTimePoint);
  QUIC_STATS(infoCallback_, onPacketForwarded);
}

void QuicServerWorker::sendResetPacket(
    const HeaderForm& headerForm,
    const folly::SocketAddress& client,
    const NetworkData& networkData,
    const ConnectionId& connId) {
  if (headerForm != HeaderForm::Short) {
    // Only send resets in response to short header packets.
    return;
  }
  uint16_t packetSize = networkData.data->computeChainDataLength();
  uint16_t maxResetPacketSize = std::min<uint16_t>(
      std::max<uint16_t>(kMinStatelessPacketSize, packetSize),
      kDefaultUDPSendPacketLen);
  CHECK(transportSettings_.statelessResetTokenSecret.hasValue());
  StatelessResetGenerator generator(
      *transportSettings_.statelessResetTokenSecret,
      getAddress().getFullyQualified());
  StatelessResetToken token = generator.generateToken(connId);
  StatelessResetPacketBuilder builder(maxResetPacketSize, token);
  auto resetData = std::move(builder).buildPacket();
  socket_->write(client, std::move(resetData));
  QUIC_STATS(infoCallback_, onWrite, resetData->computeChainDataLength());
  QUIC_STATS(infoCallback_, onPacketSent);
}

void QuicServerWorker::allowBeingTakenOver(
    std::unique_ptr<folly::AsyncUDPSocket> socket,
    const folly::SocketAddress& address) {
  DCHECK(!takeoverCB_);
  // We instantiate and bind the TakeoverHandlerCallback to the given address.
  // It is reset at shutdownAllConnections (i.e. only when the process dies).
  takeoverCB_ = std::make_unique<TakeoverHandlerCallback>(
      this,
      takeoverPktHandler_,
      transportSettings_,
      address,
      std::move(socket));
  takeoverCB_->bind();
}

void QuicServerWorker::startPacketForwarding(
    const folly::SocketAddress& destAddr) {
  packetForwardingEnabled_ = true;
  takeoverPktHandler_.setDestination(destAddr);
}

void QuicServerWorker::stopPacketForwarding() {
  packetForwardingEnabled_ = false;
  takeoverPktHandler_.stop();
}

void QuicServerWorker::onReadError(
    const folly::AsyncSocketException& ex) noexcept {
  VLOG(4) << "QuicServer readerr: " << ex.what();
  if (!callback_) {
    VLOG(0) << "Worker callback is null.  Ignoring worker error.";
    return;
  }
  callback_->handleWorkerError(LocalErrorCode::INTERNAL_ERROR);
}

void QuicServerWorker::onReadClosed() noexcept {
  shutdownAllConnections(LocalErrorCode::SHUTTING_DOWN);
}

int QuicServerWorker::getTakeoverHandlerSocketFD() {
  CHECK(takeoverCB_);
  return takeoverCB_->getSocketFD();
}

TakeoverProtocolVersion QuicServerWorker::getTakeoverProtocolVersion() const
    noexcept {
  return takeoverPktHandler_.getTakeoverProtocolVersion();
}

void QuicServerWorker::setProcessId(enum ProcessId id) noexcept {
  processId_ = id;
}

ProcessId QuicServerWorker::getProcessId() const noexcept {
  return processId_;
}

void QuicServerWorker::setWorkerId(uint8_t id) noexcept {
  workerId_ = id;
}

uint8_t QuicServerWorker::getWorkerId() const noexcept {
  return workerId_;
}

void QuicServerWorker::setHostId(uint16_t hostId) noexcept {
  hostId_ = hostId;
}

void QuicServerWorker::setNewConnectionSocketFactory(
    QuicUDPSocketFactory* factory) {
  socketFactory_ = factory;
  takeoverPktHandler_.setSocketFactory(socketFactory_);
}

void QuicServerWorker::setTransportFactory(
    QuicServerTransportFactory* factory) {
  transportFactory_ = factory;
}

void QuicServerWorker::setSupportedVersions(
    const std::vector<QuicVersion>& supportedVersions) {
  supportedVersions_ = supportedVersions;
}

void QuicServerWorker::setFizzContext(
    std::shared_ptr<const fizz::server::FizzServerContext> ctx) {
  ctx_ = ctx;
}

void QuicServerWorker::setTransportSettings(
    TransportSettings transportSettings) {
  transportSettings_ = transportSettings;
}

void QuicServerWorker::rejectNewConnections(bool rejectNewConnections) {
  rejectNewConnections_ = rejectNewConnections;
}

void QuicServerWorker::setHealthCheckToken(
    const std::string& healthCheckToken) {
  healthCheckToken_ = folly::IOBuf::copyBuffer(healthCheckToken);
}

std::unique_ptr<folly::AsyncUDPSocket> QuicServerWorker::makeSocket(
    folly::EventBase* evb) const {
  CHECK(socket_);
  return socketFactory_->make(evb, socket_->getNetworkSocket().toFd());
}

std::unique_ptr<folly::AsyncUDPSocket> QuicServerWorker::makeSocket(
    folly::EventBase* evb,
    int fd) const {
  return socketFactory_->make(evb, fd);
}

const QuicServerWorker::ConnIdToTransportMap&
QuicServerWorker::getConnectionIdMap() const {
  return connectionIdMap_;
}

const QuicServerWorker::SrcToTransportMap&
QuicServerWorker::getSrcToTransportMap() const {
  return sourceAddressMap_;
}

void QuicServerWorker::onConnectionIdAvailable(
    QuicServerTransport::Ptr transport,
    ConnectionId id) noexcept {
  VLOG(4) << "Adding into connectionIdMap_ for CID=" << id << " " << *transport;
  auto result =
      connectionIdMap_.emplace(std::make_pair(id, std::move(transport)));
  if (!result.second) {
    LOG(ERROR) << "connectionIdMap_ already has CID=" << id;
  } else {
    QUIC_STATS(infoCallback_, onNewConnection);
  }
}

void QuicServerWorker::onConnectionIdBound(
    QuicServerTransport::Ptr transport) noexcept {
  DCHECK(transport->getClientConnectionId());
  auto source = std::make_pair(
      transport->getOriginalPeerAddress(), *transport->getClientConnectionId());
  VLOG(4) << "Removing from sourceAddressMap_ address=" << source.first;
  auto iter = sourceAddressMap_.find(source);
  if (iter == sourceAddressMap_.end() || iter->second != transport) {
    LOG(ERROR) << "Transport not match, client=" << *transport;
  } else {
    sourceAddressMap_.erase(source);
    if (transport->shouldShedConnection()) {
      VLOG_EVERY_N(1, 100) << "Shedding connection";
      transport->closeNow(std::make_pair(
          QuicErrorCode(TransportErrorCode::SERVER_BUSY),
          std::string("shedding under load")));
    }
  }
}

void QuicServerWorker::onConnectionUnbound(
    const QuicServerTransport::SourceIdentity& source,
    folly::Optional<ConnectionId> connectionId) noexcept {
  VLOG(4) << "Removing from sourceAddressMap_ address=" << source.first;
  // TODO: verify we are removing the right transport
  sourceAddressMap_.erase(source);
  if (connectionId) {
    VLOG(4) << "Removing from connectionIdMap_ for CID=" << *connectionId
            << ", workerId=" << (uint32_t)workerId_;
    connectionIdMap_.erase(*connectionId);
    QUIC_STATS(infoCallback_, onConnectionClose, folly::none);
  }
}

void QuicServerWorker::shutdownAllConnections(LocalErrorCode error) {
  VLOG(4) << "QuicServer shutdown all connections."
          << " addressMap=" << sourceAddressMap_.size()
          << " connectionIdMap=" << connectionIdMap_.size();
  if (shutdown_) {
    return;
  }
  shutdown_ = true;
  if (socket_) {
    socket_->pauseRead();
  }
  if (takeoverCB_) {
    takeoverCB_->pause();
  }
  callback_ = nullptr;
  for (auto& it : sourceAddressMap_) {
    auto transport = it.second;
    transport->setRoutingCallback(nullptr);
    transport->setTransportInfoCallback(nullptr);
    transport->closeNow(
        std::make_pair(QuicErrorCode(error), std::string("shutting down")));
  }
  for (auto& it : connectionIdMap_) {
    auto transport = it.second;
    transport->setRoutingCallback(nullptr);
    transport->setTransportInfoCallback(nullptr);
    transport->closeNow(
        std::make_pair(QuicErrorCode(error), std::string("shutting down")));
    QUIC_STATS(infoCallback_, onConnectionClose, folly::none);
  }
  sourceAddressMap_.clear();
  connectionIdMap_.clear();
  takeoverPktHandler_.stop();
  if (infoCallback_) {
    infoCallback_.reset();
  }
  socket_.reset();
  takeoverCB_.reset();
}

QuicServerWorker::~QuicServerWorker() {
  shutdownAllConnections(LocalErrorCode::SHUTTING_DOWN);
}
} // namespace quic
