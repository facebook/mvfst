/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/Format.h>
#include <folly/chrono/Conv.h>
#include <folly/io/Cursor.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/system/ThreadId.h>
#include <quic/QuicConstants.h>
#include <quic/common/SocketUtil.h>
#include <quic/common/Timers.h>

#ifdef FOLLY_HAVE_MSG_ERRQUEUE
#include <linux/net_tstamp.h>
#else
#define SOF_TIMESTAMPING_SOFTWARE 0
#endif

#include <quic/server/AcceptObserver.h>
#include <quic/server/CCPReader.h>
#include <quic/server/QuicServerWorker.h>
#include <quic/server/handshake/StatelessResetGenerator.h>
#include <quic/state/QuicConnectionStats.h>

namespace quic {

QuicServerWorker::QuicServerWorker(
    std::shared_ptr<QuicServerWorker::WorkerCallback> callback,
    bool setEventCallback)
    : callback_(callback),
      setEventCallback_(setEventCallback),
      takeoverPktHandler_(this),
      observerList_(this) {
  ccpReader_ = std::make_unique<CCPReader>();
}

folly::EventBase* QuicServerWorker::getEventBase() const {
  return evb_;
}

void QuicServerWorker::setSocket(
    std::unique_ptr<folly::AsyncUDPSocket> socket) {
  socket_ = std::move(socket);
  evb_ = socket_->getEventBase();
}

void QuicServerWorker::bind(
    const folly::SocketAddress& address,
    folly::AsyncUDPSocket::BindOptions bindOptions) {
  DCHECK(!supportedVersions_.empty());
  CHECK(socket_);
  if (setEventCallback_) {
    socket_->setEventCallback(this);
  }
  // TODO this totally doesn't work, we can't apply socket options before
  // bind, since bind creates the fd.
  if (socketOptions_) {
    applySocketOptions(
        *socket_.get(),
        *socketOptions_,
        address.getFamily(),
        folly::SocketOptionKey::ApplyPos::PRE_BIND);
  }
  socket_->bind(address, bindOptions);
  if (socketOptions_) {
    applySocketOptions(
        *socket_.get(),
        *socketOptions_,
        address.getFamily(),
        folly::SocketOptionKey::ApplyPos::POST_BIND);
  }
  socket_->setDFAndTurnOffPMTU();
  if (transportSettings_.numGROBuffers_ > kDefaultNumGROBuffers) {
    socket_->setGRO(true);
    auto ret = socket_->getGRO();
    if (ret > 0) {
      numGROBuffers_ = (transportSettings_.numGROBuffers_ < kMaxNumGROBuffers)
          ? transportSettings_.numGROBuffers_
          : kMaxNumGROBuffers;
    }
  }
  socket_->setTimestamping(SOF_TIMESTAMPING_SOFTWARE);
}

void QuicServerWorker::applyAllSocketOptions() {
  CHECK(socket_);
  if (socketOptions_) {
    applySocketOptions(
        *socket_.get(),
        *socketOptions_,
        getAddress().getFamily(),
        folly::SocketOptionKey::ApplyPos::PRE_BIND);
    applySocketOptions(
        *socket_.get(),
        *socketOptions_,
        getAddress().getFamily(),
        folly::SocketOptionKey::ApplyPos::POST_BIND);
  }
}

void QuicServerWorker::setTransportSettingsOverrideFn(
    TransportSettingsOverrideFn fn) {
  transportSettingsOverrideFn_ = std::move(fn);
}

void QuicServerWorker::setTransportStatsCallback(
    std::unique_ptr<QuicTransportStatsCallback> statsCallback) noexcept {
  CHECK(statsCallback);
  statsCallback_ = std::move(statsCallback);
}

QuicTransportStatsCallback* QuicServerWorker::getTransportStatsCallback() const
    noexcept {
  return statsCallback_.get();
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

void QuicServerWorker::setRateLimiter(
    std::unique_ptr<RateLimiter> rateLimiter) {
  newConnRateLimiter_ = std::move(rateLimiter);
}

void QuicServerWorker::start() {
  CHECK(socket_);
  if (!pacingTimer_) {
    pacingTimer_ = TimerHighRes::newTimer(
        evb_, transportSettings_.pacingTimerTickInterval);
  }
  socket_->resumeRead(this);
  VLOG(10) << folly::format(
      "Registered read on worker={}, thread={}, processId={}",
      this,
      folly::getCurrentThreadID(),
      (int)processId_);
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
  readBuffer_ = folly::IOBuf::create(
      transportSettings_.maxRecvPacketSize * numGROBuffers_);
  *buf = readBuffer_->writableData();
  *len = transportSettings_.maxRecvPacketSize * numGROBuffers_;
}

// Returns true if we either drop the packet or send a version
// negotiation packet to the client. Returns false if there's
// no need for version negotiation.
bool QuicServerWorker::maybeSendVersionNegotiationPacketOrDrop(
    const folly::SocketAddress& client,
    bool isInitial,
    LongHeaderInvariant& invariant,
    size_t datagramLen) {
  folly::Optional<std::pair<VersionNegotiationPacket, Buf>>
      versionNegotiationPacket;
  if (isInitial && datagramLen < kMinInitialPacketSize) {
    VLOG(3) << "Dropping initial packet due to invalid size";
    QUIC_STATS(
        statsCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET);
    return true;
  }
  isInitial =
      isInitial && invariant.version != QuicVersion::VERSION_NEGOTIATION;
  if (rejectNewConnections_ && isInitial) {
    VersionNegotiationPacketBuilder builder(
        invariant.dstConnId,
        invariant.srcConnId,
        std::vector<QuicVersion>{QuicVersion::MVFST_INVALID});
    versionNegotiationPacket =
        folly::make_optional(std::move(builder).buildPacket());
  }
  if (!versionNegotiationPacket) {
    bool negotiationNeeded = std::find(
                                 supportedVersions_.begin(),
                                 supportedVersions_.end(),
                                 invariant.version) == supportedVersions_.end();
    if (negotiationNeeded && !isInitial) {
      VLOG(3) << "Dropping non-initial packet due to invalid version";
      QUIC_STATS(
          statsCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET);
      return true;
    }
    if (negotiationNeeded) {
      VersionNegotiationPacketBuilder builder(
          invariant.dstConnId, invariant.srcConnId, supportedVersions_);
      versionNegotiationPacket =
          folly::make_optional(std::move(builder).buildPacket());
    }
  }
  if (versionNegotiationPacket) {
    VLOG(4) << "Version negotiation sent to client=" << client;
    auto len = versionNegotiationPacket->second->computeChainDataLength();
    QUIC_STATS(statsCallback_, onWrite, len);
    QUIC_STATS(statsCallback_, onPacketProcessed);
    QUIC_STATS(statsCallback_, onPacketSent);
    socket_->write(client, versionNegotiationPacket->second);
    return true;
  }
  return false;
}

void QuicServerWorker::onDataAvailable(
    const folly::SocketAddress& client,
    size_t len,
    bool truncated,
    OnDataAvailableParams params) noexcept {
  auto packetReceiveTime = Clock::now();
  auto originalPacketReceiveTime = packetReceiveTime;
  if (params.ts) {
    // This is the software system time from the datagram.
    auto packetNowDuration =
        folly::to<std::chrono::microseconds>(params.ts.value()[0]);
    auto wallNowDuration =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch());
    auto durationSincePacketNow = wallNowDuration - packetNowDuration;
    if (packetNowDuration != 0us && durationSincePacketNow > 0us) {
      packetReceiveTime -= durationSincePacketNow;
    }
  }
  // System time can move backwards, so we want to make sure that the receive
  // time we are using is monotonic relative to itself.
  if (packetReceiveTime < largestPacketReceiveTime_) {
    packetReceiveTime = originalPacketReceiveTime;
  }
  largestPacketReceiveTime_ =
      std::max(largestPacketReceiveTime_, packetReceiveTime);
  VLOG(10) << folly::format(
      "Worker={}, Received data on thread={}, processId={}",
      this,
      folly::getCurrentThreadID(),
      (int)processId_);
  // Move readBuffer_ first so that we can get rid
  // of it immediately so that if we return early,
  // we've flushed it.
  Buf data = std::move(readBuffer_);

  if (params.gro <= 0) {
    if (truncated) {
      // This is an error, drop the packet.
      return;
    }
    data->append(len);
    QUIC_STATS(statsCallback_, onPacketReceived);
    QUIC_STATS(statsCallback_, onRead, len);
    handleNetworkData(client, std::move(data), packetReceiveTime);
  } else {
    // if we receive a truncated packet
    // we still need to consider the prev valid ones
    // AsyncUDPSocket::handleRead() sets the len to be the
    // buffer size in case the data is truncated
    if (truncated) {
      len -= len % params.gro;
    }

    data->append(len);
    QUIC_STATS(statsCallback_, onPacketReceived);
    QUIC_STATS(statsCallback_, onRead, len);

    size_t remaining = len;
    size_t offset = 0;
    while (remaining) {
      if (static_cast<int>(remaining) > params.gro) {
        auto tmp = data->cloneOne();
        // start at offset
        tmp->trimStart(offset);
        // the actual len is len - offset now
        // leave params.gro_ bytes
        tmp->trimEnd(len - offset - params.gro);
        DCHECK_EQ(tmp->length(), params.gro);

        offset += params.gro;
        remaining -= params.gro;
        handleNetworkData(client, std::move(tmp), packetReceiveTime);
      } else {
        // do not clone the last packet
        // start at offset, use all the remaining data
        data->trimStart(offset);
        DCHECK_EQ(data->length(), remaining);
        remaining = 0;
        handleNetworkData(client, std::move(data), packetReceiveTime);
      }
    }
  }
}

void QuicServerWorker::handleNetworkData(
    const folly::SocketAddress& client,
    Buf data,
    const TimePoint& packetReceiveTime,
    bool isForwardedData) noexcept {
  try {
    if (shutdown_) {
      VLOG(4) << "Packet received after shutdown, dropping";
      QUIC_STATS(
          statsCallback_, onPacketDropped, PacketDropReason::SERVER_SHUTDOWN);
      return;
    }

    if (!callback_) {
      VLOG(0) << "Worker callback is null.  Dropping packet.";
      QUIC_STATS(
          statsCallback_,
          onPacketDropped,
          PacketDropReason::WORKER_NOT_INITIALIZED);
      return;
    }
    folly::io::Cursor cursor(data.get());
    if (!cursor.canAdvance(sizeof(uint8_t))) {
      VLOG(4) << "Dropping packet too small";
      QUIC_STATS(
          statsCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET);
      return;
    }
    uint8_t initialByte = cursor.readBE<uint8_t>();
    HeaderForm headerForm = getHeaderForm(initialByte);

    if (headerForm == HeaderForm::Short) {
      folly::Expected<ShortHeaderInvariant, TransportErrorCode>
          parsedShortHeader = parseShortHeaderInvariants(initialByte, cursor);
      if (!parsedShortHeader) {
        if (!tryHandlingAsHealthCheck(client, *data)) {
          QUIC_STATS(
              statsCallback_, onPacketDropped, PacketDropReason::PARSE_ERROR);
          VLOG(6) << "Failed to parse short header";
        }
        return;
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
          NetworkData(std::move(data), packetReceiveTime),
          isForwardedData);
    }

    folly::Expected<ParsedLongHeaderInvariant, TransportErrorCode>
        parsedLongHeader = parseLongHeaderInvariant(initialByte, cursor);
    if (!parsedLongHeader) {
      if (!tryHandlingAsHealthCheck(client, *data)) {
        QUIC_STATS(
            statsCallback_, onPacketDropped, PacketDropReason::PARSE_ERROR);
        VLOG(6) << "Failed to parse long header";
      }
      return;
    }

    // TODO: check version before looking at type
    LongHeader::Types longHeaderType = parseLongHeaderType(initialByte);
    bool isInitial = longHeaderType == LongHeader::Types::Initial;
    bool isUsingClientConnId =
        isInitial || longHeaderType == LongHeader::Types::ZeroRtt;

    if (isInitial) {
      // This stats gets updated even if the client initial will be dropped.
      QUIC_STATS(
          statsCallback_,
          onClientInitialReceived,
          parsedLongHeader->invariant.version);
    }

    if (maybeSendVersionNegotiationPacketOrDrop(
            client,
            isInitial,
            parsedLongHeader->invariant,
            data->computeChainDataLength())) {
      return;
    }

    if (!isUsingClientConnId &&
        parsedLongHeader->invariant.dstConnId.size() <
            kMinSelfConnectionIdV1Size) {
      // drop packet if connId is present but is not valid.
      VLOG(3) << "Dropping packet due to invalid connectionId";
      QUIC_STATS(
          statsCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET);
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
        NetworkData(std::move(data), packetReceiveTime),
        isForwardedData);
  } catch (const std::exception& ex) {
    // Drop the packet.
    QUIC_STATS(statsCallback_, onPacketDropped, PacketDropReason::PARSE_ERROR);
    VLOG(6) << "Failed to parse packet header " << ex.what();
  }
}

void QuicServerWorker::eventRecvmsgCallback(MsgHdr* msgHdr, int res) {
  auto bytesRead = res;
  int gro = -1;
  auto& msg = msgHdr->data_;
  if (bytesRead > 0) {
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (msgHdr->data_.msg_control) {
      struct cmsghdr* cmsg;
      for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
           cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_UDP && cmsg->cmsg_type == UDP_GRO) {
          auto grosizeptr = (uint16_t*)CMSG_DATA(cmsg);
          gro = *grosizeptr;
          break;
        }
      }
    }
#endif
    bool truncated = false;
    if ((size_t)bytesRead > msgHdr->len_) {
      truncated = true;
      bytesRead = ssize_t(msgHdr->len_);
    }

    readBuffer_ = std::move(msgHdr->ioBuf_);

    folly::SocketAddress addr;
    addr.setFromSockaddr(
        reinterpret_cast<sockaddr*>(msg.msg_name), msg.msg_namelen);

    OnDataAvailableParams params;
    params.gro = gro;
    onDataAvailable(addr, bytesRead, truncated, params);
  }
  msgHdr_.reset(msgHdr);
}

bool QuicServerWorker::tryHandlingAsHealthCheck(
    const folly::SocketAddress& client,
    const folly::IOBuf& data) {
  // If we cannot parse the long header then it is not a QUIC invariant
  // packet, so just drop it after checking whether it could be a health
  // check.
  if (!healthCheckToken_) {
    return false;
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
    return true;
  }
  return false;
}

void QuicServerWorker::forwardNetworkData(
    const folly::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData,
    bool isForwardedData) {
  // if it's not Client initial or ZeroRtt, AND if the connectionId version
  // mismatches: foward if pktForwarding is enabled else dropPacket
  if (!routingData.isUsingClientConnId &&
      !connIdAlgo_->canParse(routingData.destinationConnId)) {
    if (packetForwardingEnabled_ && !isForwardedData) {
      VLOG(3) << folly::format(
          "Forwarding packet with unknown connId version from client={} to another process, routingInfo={}",
          client.describe(),
          logRoutingInfo(routingData.destinationConnId));
      auto recvTime = networkData.receiveTimePoint;
      takeoverPktHandler_.forwardPacketToAnotherServer(
          client, std::move(networkData).moveAllData(), recvTime);
      QUIC_STATS(statsCallback_, onPacketForwarded);
      return;
    } else {
      VLOG(3) << folly::format(
          "Dropping packet due to unknown connectionId version, routingInfo={}",
          logRoutingInfo(routingData.destinationConnId));
      QUIC_STATS(
          statsCallback_,
          onPacketDropped,
          PacketDropReason::CONNECTION_NOT_FOUND);
    }
    return;
  }
  callback_->routeDataToWorker(
      client, std::move(routingData), std::move(networkData), isForwardedData);
}

void QuicServerWorker::setPacingTimer(
    TimerHighRes::SharedPtr pacingTimer) noexcept {
  pacingTimer_ = std::move(pacingTimer);
}

void QuicServerWorker::dispatchPacketData(
    const folly::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData,
    bool isForwardedData) noexcept {
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
    VLOG(3) << folly::format(
        "Dropping non-long header packet with no connid match"
        " headerForm={}, routingInfo={}",
        static_cast<typename std::underlying_type<HeaderForm>::type>(
            routingData.headerForm),
        logRoutingInfo(routingData.destinationConnId));
    // Try forwarding the packet to the old server (if it is enabled)
    dropPacket = true;
  }

  bool cannotMakeTransport = false;
  if (!dropPacket && !transport) {
    // For LongHeader packets without existing associated connection, try to
    // route with destinationConnId chosen by the peer and IP address of the
    // peer.
    CHECK(transportFactory_);
    auto source = std::make_pair(client, routingData.destinationConnId);
    auto sit = sourceAddressMap_.find(source);
    if (sit == sourceAddressMap_.end()) {
      // TODO for O-RTT types we need to create new connections to handle
      // the case, where the new server gets packets sent to the old one due
      // to network reordering
      if (!routingData.isInitial) {
        VLOG(3) << folly::format(
            "Dropping packet from client={}, routingInfo={}",
            client.describe(),
            logRoutingInfo(routingData.destinationConnId));
        dropPacket = true;
      } else {
        VLOG(4) << folly::format(
            "Creating new connection for client={}, routingInfo={}",
            client.describe(),
            logRoutingInfo(routingData.destinationConnId));

        // This could be a new connection, add it in the map
        // verify that the initial packet is at least min initial bytes
        // to avoid amplification attacks.
        if (networkData.totalData < kMinInitialPacketSize) {
          // Don't even attempt to forward the packet, just drop it.
          VLOG(3) << "Dropping small initial packet from client=" << client;
          QUIC_STATS(
              statsCallback_,
              onPacketDropped,
              PacketDropReason::INVALID_PACKET);
          return;
        }
        if (newConnRateLimiter_ &&
            newConnRateLimiter_->check(networkData.receiveTimePoint)) {
          // TODO RETRY
          VersionNegotiationPacketBuilder builder(
              routingData.destinationConnId,
              routingData.sourceConnId.value_or(
                  ConnectionId(std::vector<uint8_t>())),
              std::vector<QuicVersion>{QuicVersion::MVFST_INVALID});
          auto versionNegotiationPacket = std::move(builder).buildPacket();
          socket_->write(client, versionNegotiationPacket.second);
          QUIC_STATS(statsCallback_, onConnectionRateLimited);
          return;
        }
        // create 'accepting' transport
        auto sock = makeSocket(getEventBase());
        auto trans = transportFactory_->make(
            getEventBase(), std::move(sock), client, ctx_);
        if (!trans) {
          dropPacket = true;
          cannotMakeTransport = true;
        } else {
          CHECK(trans);
          if (transportSettings_.dataPathType ==
                  DataPathType::ContinuousMemory &&
              bufAccessor_) {
            trans->setBufAccessor(bufAccessor_.get());
          }
          trans->setPacingTimer(pacingTimer_);
          trans->setRoutingCallback(this);
          trans->setSupportedVersions(supportedVersions_);
          trans->setOriginalPeerAddress(client);
#ifdef CCP_ENABLED
          trans->setCcpDatapath(getCcpReader()->getDatapath());
#endif
          trans->setCongestionControllerFactory(ccFactory_);
          if (transportSettingsOverrideFn_) {
            folly::Optional<TransportSettings> overridenTransportSettings =
                transportSettingsOverrideFn_(
                    transportSettings_, client.getIPAddress());
            if (overridenTransportSettings) {
              if (overridenTransportSettings->dataPathType !=
                  transportSettings_.dataPathType) {
                // It's too complex to support that.
                LOG(ERROR)
                    << "Overriding DataPathType isn't supported. Requested daapath="
                    << (overridenTransportSettings->dataPathType ==
                                DataPathType::ContinuousMemory
                            ? "ContinuousMemory"
                            : "ChainedMemory");
              }
              trans->setTransportSettings(*overridenTransportSettings);
            } else {
              trans->setTransportSettings(transportSettings_);
            }
          } else {
            trans->setTransportSettings(transportSettings_);
          }
          trans->setConnectionIdAlgo(connIdAlgo_.get());
          trans->setServerConnectionIdRejector(this);
          if (routingData.sourceConnId) {
            trans->setClientConnectionId(*routingData.sourceConnId);
          }
          trans->setClientChosenDestConnectionId(routingData.destinationConnId);
          // parameters to create server chosen connection id
          ServerConnectionIdParams serverConnIdParams(
              cidVersion_,
              hostId_,
              static_cast<uint8_t>(processId_),
              workerId_);
          trans->setServerConnectionIdParams(std::move(serverConnIdParams));
          if (statsCallback_) {
            trans->setTransportStatsCallback(statsCallback_.get());
          }
          trans->accept();
          auto result = sourceAddressMap_.emplace(std::make_pair(
              std::make_pair(client, routingData.destinationConnId), trans));
          if (!result.second) {
            LOG(ERROR) << folly::format(
                "Routing entry already exists for client={}, routingInfo={}",
                client.describe(),
                logRoutingInfo(routingData.destinationConnId));
            dropPacket = true;
          } else {
            for (const auto& observer : observerList_.getAll()) {
              observer->accept(trans.get());
            }
          }
          transport = trans;
        }
      }
    } else {
      transport = sit->second;
      VLOG(4) << "Found existing connection for client=" << client << " "
              << *transport;
    }
  }
  if (!dropPacket) {
    DCHECK(transport->getEventBase()->isInEventBaseThread());
    transport->onNetworkData(client, std::move(networkData));
    return;
  }
  if (cannotMakeTransport) {
    VLOG(3)
        << "Dropping packet due to transport factory did not make transport";
    QUIC_STATS(
        statsCallback_,
        onPacketDropped,
        PacketDropReason::CANNOT_MAKE_TRANSPORT);
    return;
  }
  if (!connIdAlgo_->canParse(routingData.destinationConnId)) {
    VLOG(3) << "Dropping packet with bad DCID, routingInfo="
            << logRoutingInfo(routingData.destinationConnId);
    QUIC_STATS(statsCallback_, onPacketDropped, PacketDropReason::PARSE_ERROR);
    // TODO do we need to reset?
    return;
  }
  auto connIdParam =
      connIdAlgo_->parseConnectionId(routingData.destinationConnId);
  if (connIdParam.hasError()) {
    VLOG(3) << folly::format(
        "Dropping packet due to DCID parsing error={}, , errorCode={}, routingInfo={}",
        connIdParam.error().what(),
        folly::to<std::string>(connIdParam.error().errorCode()),
        logRoutingInfo(routingData.destinationConnId));
    QUIC_STATS(statsCallback_, onPacketDropped, PacketDropReason::PARSE_ERROR);
    // TODO do we need to reset?
    return;
  }
  if (connIdParam->hostId != hostId_) {
    VLOG_EVERY_N(2, 100) << "Dropping packet routed to wrong host, routingInfo="
                         << logRoutingInfo(routingData.destinationConnId);
    QUIC_STATS(
        statsCallback_,
        onPacketDropped,
        PacketDropReason::ROUTING_ERROR_WRONG_HOST);
    return sendResetPacket(
        routingData.headerForm,
        client,
        networkData,
        routingData.destinationConnId);
  }

  if (!packetForwardingEnabled_ || isForwardedData) {
    QUIC_STATS(
        statsCallback_,
        onPacketDropped,
        PacketDropReason::CONNECTION_NOT_FOUND);
    return sendResetPacket(
        routingData.headerForm,
        client,
        networkData,
        routingData.destinationConnId);
  }

  // There's no existing connection for the packet's CID or the client's
  // addr, and doesn't belong to the old server. Send a Reset.
  if (connIdParam->processId == static_cast<uint8_t>(processId_)) {
    QUIC_STATS(
        statsCallback_,
        onPacketDropped,
        PacketDropReason::CONNECTION_NOT_FOUND);
    return sendResetPacket(
        routingData.headerForm,
        client,
        networkData,
        routingData.destinationConnId);
  }

  // Optimistically route to another server
  // if the packet type is not Initial and if there is not any connection
  // associated with the given packet
  VLOG(4) << folly::format(
      "Forwarding packet from client={} to another process, routingInfo={}",
      client.describe(),
      logRoutingInfo(routingData.destinationConnId));
  auto recvTime = networkData.receiveTimePoint;
  takeoverPktHandler_.forwardPacketToAnotherServer(
      client, std::move(networkData).moveAllData(), recvTime);
  QUIC_STATS(statsCallback_, onPacketForwarded);
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
  auto packetSize = networkData.totalData;
  auto resetSize = std::min<uint16_t>(packetSize, kDefaultMaxUDPPayload);
  // Per the spec, less than 43 we should respond with packet size - 1.
  if (packetSize < 43) {
    resetSize = std::max<uint16_t>(packetSize - 1, kMinStatelessPacketSize);
  } else {
    resetSize = std::max<uint16_t>(
        folly::Random::secureRand32() % resetSize, kMinStatelessPacketSize);
  }
  CHECK(transportSettings_.statelessResetTokenSecret.has_value());
  StatelessResetGenerator generator(
      *transportSettings_.statelessResetTokenSecret,
      getAddress().getFullyQualified());
  StatelessResetToken token = generator.generateToken(connId);
  StatelessResetPacketBuilder builder(resetSize, token);
  auto resetData = std::move(builder).buildPacket();
  auto resetDataLen = resetData->computeChainDataLength();
  socket_->write(client, std::move(resetData));
  QUIC_STATS(statsCallback_, onWrite, resetDataLen);
  QUIC_STATS(statsCallback_, onPacketSent);
  QUIC_STATS(statsCallback_, onStatelessReset);
}

void QuicServerWorker::allowBeingTakenOver(
    std::unique_ptr<folly::AsyncUDPSocket> socket,
    const folly::SocketAddress& address) {
  DCHECK(!takeoverCB_);
  // We instantiate and bind the TakeoverHandlerCallback to the given address.
  // It is reset at shutdownAllConnections (i.e. only when the process dies).
  takeoverCB_ = std::make_unique<TakeoverHandlerCallback>(
      this, takeoverPktHandler_, transportSettings_, std::move(socket));
  takeoverCB_->bind(address);
}

const folly::SocketAddress& QuicServerWorker::overrideTakeoverHandlerAddress(
    std::unique_ptr<folly::AsyncUDPSocket> socket,
    const folly::SocketAddress& address) {
  CHECK(takeoverCB_);
  takeoverCB_->rebind(std::move(socket), address);
  return takeoverCB_->getAddress();
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

void QuicServerWorker::setHostId(uint32_t hostId) noexcept {
  hostId_ = hostId;
}

void QuicServerWorker::setConnectionIdVersion(
    ConnectionIdVersion cidVersion) noexcept {
  cidVersion_ = cidVersion;
}

CCPReader* QuicServerWorker::getCcpReader() const noexcept {
  return ccpReader_.get();
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
  if (transportSettings_.batchingMode != QuicBatchingMode::BATCHING_MODE_GSO) {
    if (transportSettings_.dataPathType == DataPathType::ContinuousMemory) {
      LOG(ERROR) << "Unsupported data path type and batching mode combination";
    }
    transportSettings_.dataPathType = DataPathType::ChainedMemory;
  }
  if (transportSettings_.dataPathType == DataPathType::ContinuousMemory) {
    // TODO: maxBatchSize is only a good start value when each transport does
    // its own socket writing. If we experiment with multiple transports GSO
    // together, we will need a better value.
    bufAccessor_ = std::make_unique<SimpleBufAccessor>(
        kDefaultMaxUDPPayload * transportSettings_.maxBatchSize);
    VLOG(10) << "GSO write buf accessor created for ContinuousMemory data path";
  }
}

void QuicServerWorker::rejectNewConnections(bool rejectNewConnections) {
  rejectNewConnections_ = rejectNewConnections;
}

void QuicServerWorker::enablePartialReliability(bool enabled) {
  transportSettings_.partialReliabilityEnabled = enabled;
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
  QuicServerTransport* transportPtr = transport.get();
  std::weak_ptr<QuicServerTransport> weakTransport = transport;
  auto result =
      connectionIdMap_.emplace(std::make_pair(id, std::move(transport)));
  if (!result.second) {
    // In the case of duplicates, log if they represent the same transport,
    // or different ones.
    auto it = result.first;
    QuicServerTransport* existingTransportPtr = it->second.get();
    LOG(ERROR) << "connectionIdMap_ already has CID=" << id
               << " Is same transport: "
               << (existingTransportPtr == transportPtr);
  } else if (boundServerTransports_.emplace(transportPtr, weakTransport)
                 .second) {
    QUIC_STATS(statsCallback_, onNewConnection);
  }
}

void QuicServerWorker::onConnectionIdBound(
    QuicServerTransport::Ptr transport) noexcept {
  auto clientInitialDestCid = transport->getClientChosenDestConnectionId();
  CHECK(clientInitialDestCid);
  auto source = std::make_pair(
      transport->getOriginalPeerAddress(), *clientInitialDestCid);
  VLOG(4) << "Removing from sourceAddressMap_ address=" << source.first;
  auto iter = sourceAddressMap_.find(source);
  if (iter == sourceAddressMap_.end() || iter->second != transport) {
    LOG(ERROR) << "Transport not match, client=" << *transport;
  } else {
    sourceAddressMap_.erase(source);
  }
}

void QuicServerWorker::onConnectionUnbound(
    QuicServerTransport* transport,
    const QuicServerTransport::SourceIdentity& source,
    const std::vector<ConnectionIdData>& connectionIdData) noexcept {
  VLOG(4) << "Removing from sourceAddressMap_ address=" << source.first;
  // Ensures we only process `onConnectionUnbound()` once.
  transport->setRoutingCallback(nullptr);
  boundServerTransports_.erase(transport);

  if (connectionIdData.size()) {
    QUIC_STATS(statsCallback_, onConnectionClose, folly::none);
  }

  for (auto& connId : connectionIdData) {
    VLOG(4) << folly::format(
        "Removing CID from connectionIdMap_, routingInfo={}",
        logRoutingInfo(connId.connId));
    auto it = connectionIdMap_.find(connId.connId);
    // This should be nullptr in most cases. In order to investigate if
    // an incorrect server transport is removed, this will be set to the value
    // of the incorrect transport, to see if boundServerTransports_ will
    // still hold a pointer to the incorrect transport.
    QuicServerTransport* incorrectTransportPtr = nullptr;
    if (it == connectionIdMap_.end()) {
      LOG(ERROR) << "connectionIdMap_ didn't include CID= " << connId.connId;
    } else {
      QuicServerTransport* existingPtr = it->second.get();
      if (existingPtr != transport) {
        LOG(ERROR) << "Incorrect transport being removed for duplicate CID="
                   << connId.connId;
        incorrectTransportPtr = existingPtr;
      }
    }
    connectionIdMap_.erase(connId.connId);
    if (incorrectTransportPtr != nullptr) {
      if (boundServerTransports_.find(incorrectTransportPtr) !=
          boundServerTransports_.end()) {
        LOG(ERROR)
            << "boundServerTransports_ contains deleted transport for duplicate CID="
            << connId.connId;
      }
    }
  }

  // TODO: verify we are removing the right transport
  sourceAddressMap_.erase(source);
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

  // Shut down all transports without bound connection ids.
  for (auto& it : sourceAddressMap_) {
    auto transport = it.second;
    transport->setRoutingCallback(nullptr);
    transport->setTransportStatsCallback(nullptr);
    transport->closeNow(
        std::make_pair(QuicErrorCode(error), std::string("shutting down")));
  }

  // Shut down all transports with bound connection ids.
  for (auto transport : boundServerTransports_) {
    if (auto t = transport.second.lock()) {
      t->setRoutingCallback(nullptr);
      t->setTransportStatsCallback(nullptr);
      t->closeNow(
          std::make_pair(QuicErrorCode(error), std::string("shutting down")));
      QUIC_STATS(statsCallback_, onConnectionClose, folly::none);
    }
  }
  sourceAddressMap_.clear();
  connectionIdMap_.clear();
  takeoverPktHandler_.stop();
  if (statsCallback_) {
    statsCallback_.reset();
  }
  socket_.reset();
  takeoverCB_.reset();
}

QuicServerWorker::~QuicServerWorker() {
  shutdownAllConnections(LocalErrorCode::SHUTTING_DOWN);
}

bool QuicServerWorker::rejectConnectionId(const ConnectionId& candidate) const
    noexcept {
  return connectionIdMap_.find(candidate) != connectionIdMap_.end();
}

std::string QuicServerWorker::logRoutingInfo(const ConnectionId& connId) const {
  folly::StringPiece base =
      "CID={}, cidVersion={}, workerId={}, processId={}, hostId={}, threadId={}, ";
  if (!connIdAlgo_->canParse(connId)) {
    return folly::format(
               base,
               connId.hex(),
               (uint32_t)cidVersion_,
               (uint32_t)workerId_,
               (uint32_t)processId_,
               (uint32_t)hostId_,
               folly::getCurrentThreadID())
        .str();
  }
  auto connIdParam = connIdAlgo_->parseConnectionId(connId);
  if (connIdParam.hasError()) {
    return folly::format(
               base,
               connId.hex(),
               (uint32_t)cidVersion_,
               (uint32_t)workerId_,
               (uint32_t)processId_,
               (uint32_t)hostId_,
               folly::getCurrentThreadID())
        .str();
  }
  std::string extended = base.toString() +
      "cidVersion in packet={}, workerId in packet={}, processId in packet={}, hostId in packet={}, ";
  return folly::format(
             extended,
             connId.hex(),
             (uint32_t)cidVersion_,
             (uint32_t)workerId_,
             (uint32_t)processId_,
             (uint32_t)hostId_,
             folly::getCurrentThreadID(),
             (uint32_t)connIdParam->version,
             (uint32_t)connIdParam->workerId,
             (uint32_t)connIdParam->processId,
             (uint32_t)connIdParam->hostId)
      .str();
}

QuicServerWorker::AcceptObserverList::AcceptObserverList(
    QuicServerWorker* worker)
    : worker_(worker) {}

QuicServerWorker::AcceptObserverList::~AcceptObserverList() {
  for (const auto& cb : observers_) {
    cb->acceptorDestroy(worker_);
  }
}

void QuicServerWorker::AcceptObserverList::add(AcceptObserver* observer) {
  observers_.emplace_back(CHECK_NOTNULL(observer));
  observer->observerAttach(worker_);
}

bool QuicServerWorker::AcceptObserverList::remove(AcceptObserver* observer) {
  const auto eraseIt =
      std::remove(observers_.begin(), observers_.end(), observer);
  if (eraseIt == observers_.end()) {
    return false;
  }

  for (auto it = eraseIt; it != observers_.end(); it++) {
    (*it)->observerDetach(worker_);
  }
  observers_.erase(eraseIt, observers_.end());
  return true;
}

void QuicServerWorker::getAllConnectionsStats(
    std::vector<QuicConnectionStats>& stats) {
  folly::F14FastMap<const QuicServerConnectionState*, uint32_t> uniqueConns;
  for (const auto& conn : connectionIdMap_) {
    if (!conn.second) {
      continue;
    }
    auto connState =
        static_cast<const QuicServerConnectionState*>(conn.second->getState());
    if (!connState) {
      continue;
    }
    uniqueConns[connState]++;
  }
  auto now = Clock::now();
  stats.reserve(stats.size() + uniqueConns.size());
  for (const auto& connEntry : uniqueConns) {
    QuicConnectionStats connStats;
    auto conn = connEntry.first;
    connStats.workerID = workerId_;
    connStats.numConnIDs = connEntry.second;
    connStats.localAddress = conn->serverAddr.describe();
    connStats.peerAddress = conn->peerAddress.describe();
    connStats.duration = now - conn->connectionTime;
    if (conn->congestionController) {
      connStats.congestionController =
          congestionControlTypeToString(conn->congestionController->type())
              .str();
    }
    connStats.ptoCount = conn->lossState.ptoCount;
    connStats.srtt = std::chrono::duration_cast<std::chrono::milliseconds>(
        conn->lossState.srtt);
    connStats.rttvar = std::chrono::duration_cast<std::chrono::milliseconds>(
        conn->lossState.rttvar);
    connStats.peerAckDelayExponent = conn->peerAckDelayExponent;
    connStats.udpSendPacketLen = conn->udpSendPacketLen;
    if (conn->streamManager) {
      connStats.numStreams = conn->streamManager->streams().size();
    }

    if (conn->clientChosenDestConnectionId.hasValue()) {
      connStats.clientChosenDestConnectionId =
          conn->clientChosenDestConnectionId->hex();
    }
    if (conn->clientConnectionId.hasValue()) {
      connStats.clientConnectionId = conn->clientConnectionId->hex();
    }
    if (conn->serverConnectionId.hasValue()) {
      connStats.serverConnectionId = conn->serverConnectionId->hex();
    }

    connStats.totalBytesSent = conn->lossState.totalBytesSent;
    connStats.totalBytesReceived = conn->lossState.totalBytesRecvd;
    connStats.totalBytesRetransmitted = conn->lossState.totalBytesRetransmitted;
    if (conn->version.hasValue()) {
      connStats.version = static_cast<uint32_t>(*conn->version);
    }
    stats.emplace_back(connStats);
  }
}

} // namespace quic
