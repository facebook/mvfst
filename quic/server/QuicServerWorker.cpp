/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <fmt/format.h>
#include <folly/chrono/Conv.h>
#include <folly/io/Cursor.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/system/ThreadId.h>
#include <quic/QuicConstants.h>
#include <quic/common/SocketUtil.h>
#include <quic/common/Timers.h>
#include <atomic>

#ifdef FOLLY_HAVE_MSG_ERRQUEUE
#include <linux/net_tstamp.h>
#else
#define SOF_TIMESTAMPING_SOFTWARE 0
#endif

#include <folly/Conv.h>
#include <quic/congestion_control/Bbr.h>
#include <quic/congestion_control/Copa.h>
#include <quic/fizz/handshake/FizzRetryIntegrityTagGenerator.h>
#include <quic/server/AcceptObserver.h>
#include <quic/server/CCPReader.h>
#include <quic/server/QuicServerWorker.h>
#include <quic/server/handshake/StatelessResetGenerator.h>
#include <quic/server/handshake/TokenGenerator.h>
#include <quic/state/QuicConnectionStats.h>

namespace quic {

std::atomic_int globalUnfinishedHandshakes{0};

QuicServerWorker::QuicServerWorker(
    std::shared_ptr<QuicServerWorker::WorkerCallback> callback,
    bool setEventCallback)
    : callback_(callback),
      setEventCallback_(setEventCallback),
      takeoverPktHandler_(this),
      observerList_(this) {
  ccpReader_ = std::make_unique<CCPReader>();
  pending0RttData_.setPruneHook(
      [&](auto, auto) { QUIC_STATS(statsCallback_, onZeroRttBufferedPruned); });
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

QuicTransportStatsCallback* QuicServerWorker::getTransportStatsCallback()
    const noexcept {
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

void QuicServerWorker::setUnfinishedHandshakeLimit(
    std::function<int()> limitFn) {
  unfinishedHandshakeLimitFn_ = std::move(limitFn);
}

void QuicServerWorker::start() {
  CHECK(socket_);
  if (!pacingTimer_) {
    pacingTimer_ = TimerHighRes::newTimer(
        evb_, transportSettings_.pacingTimerTickInterval);
  }
  socket_->resumeRead(this);
  VLOG(10) << fmt::format(
      "Registered read on worker={}, thread={}, processId={}",
      fmt::ptr(this),
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
  if (rejectNewConnections_() && isInitial) {
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
  VLOG(10) << fmt::format(
      "Worker={}, Received data on thread={}, processId={}",
      fmt::ptr(this),
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

    if (isBlockListedSrcPort_(client.getPort())) {
      VLOG(4) << "Dropping packet with blocklisted src port: "
              << client.getPort();
      QUIC_STATS(
          statsCallback_, onPacketDropped, PacketDropReason::INVALID_SRC_PORT);
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
          false, /* isInitial */
          false, /* is0Rtt */
          false, /* isUsingClientConnId */
          std::move(parsedShortHeader->destinationConnId),
          folly::none);
      return forwardNetworkData(
          client,
          std::move(routingData),
          NetworkData(std::move(data), packetReceiveTime),
          folly::none, /* quicVersion */
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
    bool is0Rtt = longHeaderType == LongHeader::Types::ZeroRtt;
    bool isUsingClientConnId = isInitial || is0Rtt;

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
        is0Rtt,
        isUsingClientConnId,
        std::move(parsedLongHeader->invariant.dstConnId),
        std::move(parsedLongHeader->invariant.srcConnId));
    return forwardNetworkData(
        client,
        std::move(routingData),
        NetworkData(std::move(data), packetReceiveTime),
        parsedLongHeader->invariant.version,
        isForwardedData);
  } catch (const std::exception& ex) {
    // Drop the packet.
    QUIC_STATS(statsCallback_, onPacketDropped, PacketDropReason::PARSE_ERROR);
    VLOG(6) << "Failed to parse packet header " << ex.what();
  }
}

void QuicServerWorker::eventRecvmsgCallback(MsgHdr* msgHdr, int res) {
  auto bytesRead = res;
  auto& msg = msgHdr->data_;
  if (bytesRead > 0) {
    OnDataAvailableParams params;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (msgHdr->data_.msg_control) {
      folly::AsyncUDPSocket::fromMsg(params, msg);
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
    folly::Optional<QuicVersion> quicVersion,
    bool isForwardedData) {
  // if it's not Client initial or ZeroRtt, AND if the connectionId version
  // mismatches: foward if pktForwarding is enabled else dropPacket
  if (!routingData.isUsingClientConnId &&
      !connIdAlgo_->canParse(routingData.destinationConnId)) {
    if (packetForwardingEnabled_ && !isForwardedData) {
      VLOG(3) << fmt::format(
          "Forwarding packet with unknown connId version from client={} to another process, routingInfo={}",
          client.describe(),
          logRoutingInfo(routingData.destinationConnId));
      auto recvTime = networkData.receiveTimePoint;
      takeoverPktHandler_.forwardPacketToAnotherServer(
          client, std::move(networkData).moveAllData(), recvTime);
      QUIC_STATS(statsCallback_, onPacketForwarded);
      return;
    } else {
      VLOG(3) << fmt::format(
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
      client,
      std::move(routingData),
      std::move(networkData),
      std::move(quicVersion),
      isForwardedData);
}

void QuicServerWorker::setPacingTimer(
    TimerHighRes::SharedPtr pacingTimer) noexcept {
  pacingTimer_ = std::move(pacingTimer);
}

void QuicServerWorker::dispatchPacketData(
    const folly::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData,
    folly::Optional<QuicVersion> quicVersion,
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
    VLOG(3) << fmt::format(
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
      // If it's a 0RTT packet and we have no CID, we probably lost the initial
      // and want to buffer it for a while.
      if (routingData.is0Rtt) {
        auto itr = pending0RttData_.find(routingData.destinationConnId);
        if (itr == pending0RttData_.end()) {
          itr =
              pending0RttData_.insert(routingData.destinationConnId, {}).first;
        }
        auto& vec = itr->second;
        if (vec.size() != vec.max_size()) {
          vec.emplace_back(std::move(networkData));
          QUIC_STATS(statsCallback_, onZeroRttBuffered);
        }
        return;
      } else if (!routingData.isInitial) {
        VLOG(3) << fmt::format(
            "Dropping packet from client={}, routingInfo={}",
            client.describe(),
            logRoutingInfo(routingData.destinationConnId));
        dropPacket = true;
      } else {
        VLOG(4) << fmt::format(
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

        // If there is a token present, decrypt it (could be either a retry
        // token or a new token)
        folly::io::Cursor cursor(networkData.packets.front().get());
        auto maybeEncryptedToken = maybeGetEncryptedToken(cursor);
        bool hasTokenSecret = transportSettings_.retryTokenSecret.hasValue();

        // If the retryTokenSecret is not set, just skip evaluating validity of
        // token and assume true
        auto isValidRetryToken = !hasTokenSecret ||
            (maybeEncryptedToken &&
             validRetryToken(
                 *maybeEncryptedToken,
                 routingData.destinationConnId,
                 client.getIPAddress()));

        auto isValidNewToken = !hasTokenSecret ||
            (maybeEncryptedToken &&
             validNewToken(*maybeEncryptedToken, client.getIPAddress()));

        if (isValidNewToken) {
          QUIC_STATS(statsCallback_, onNewTokenReceived);
        } else if (maybeEncryptedToken && !isValidRetryToken) {
          // Failed to decrypt the token as either a new or retry token
          QUIC_STATS(statsCallback_, onTokenDecryptFailure);
        }

        // If rate-limiting is configured and there is no retry token,
        // send a retry packet back to the client
        if (!isValidRetryToken &&
            ((newConnRateLimiter_ &&
              newConnRateLimiter_->check(networkData.receiveTimePoint)) ||
             (unfinishedHandshakeLimitFn_.has_value() &&
              globalUnfinishedHandshakes >=
                  (*unfinishedHandshakeLimitFn_)()))) {
          if (hasTokenSecret) {
            sendRetryPacket(
                client,
                routingData.destinationConnId,
                routingData.sourceConnId.value_or(
                    ConnectionId(std::vector<uint8_t>())));
            QUIC_STATS(statsCallback_, onConnectionRateLimited);
            return;
          } else {
            VLOG(4)
                << "Not sending retry packet since retry token secret is not set";
          }
        }

        // Check that we have a proper quic version before creating transport.
        CHECK(quicVersion.has_value())
            << "no QUIC version supplied for transport creation";

        // create 'accepting' transport
        auto sock = makeSocket(getEventBase());

        auto trans = transportFactory_->make(
            getEventBase(), std::move(sock), client, quicVersion.value(), ctx_);
        if (!trans) {
          dropPacket = true;
          cannotMakeTransport = true;
        } else {
          globalUnfinishedHandshakes++;
          CHECK(trans);
          if (transportSettings_.dataPathType ==
                  DataPathType::ContinuousMemory &&
              bufAccessor_) {
            trans->setBufAccessor(bufAccessor_.get());
          }
          trans->setPacingTimer(pacingTimer_);
          trans->setRoutingCallback(this);
          trans->setHandshakeFinishedCallback(this);
          trans->setSupportedVersions(supportedVersions_);
          trans->setOriginalPeerAddress(client);
#ifdef CCP_ENABLED
          trans->setCcpDatapath(getCcpReader()->getDatapath());
#endif
          trans->setCongestionControllerFactory(ccFactory_);
          if (statsCallback_) {
            trans->setTransportStatsCallback(statsCallback_.get());
          }
          auto overridenTransportSettings = transportSettingsOverrideFn_
              ? transportSettingsOverrideFn_(
                    transportSettings_, client.getIPAddress())
              : folly::none;

          if (overridenTransportSettings) {
            if (overridenTransportSettings->dataPathType !=
                transportSettings_.dataPathType) {
              // It's too complex to support that.
              LOG(ERROR)
                  << "Overriding DataPathType isn't supported. Requested datapath="
                  << (overridenTransportSettings->dataPathType ==
                              DataPathType::ContinuousMemory
                          ? "ContinuousMemory"
                          : "ChainedMemory");
            }
            trans->setTransportSettings(*overridenTransportSettings);
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
          trans->accept();
          auto result = sourceAddressMap_.emplace(std::make_pair(
              std::make_pair(client, routingData.destinationConnId), trans));
          if (!result.second) {
            LOG(ERROR) << fmt::format(
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
    // If we had pending 0RTT data for this DCID, process it.
    if (routingData.isInitial && !pending0RttData_.empty()) {
      auto itr = pending0RttData_.find(routingData.destinationConnId);
      if (itr != pending0RttData_.end()) {
        for (auto& data : itr->second) {
          transport->onNetworkData(client, std::move(data));
        }
        pending0RttData_.erase(itr);
      }
    }
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
    VLOG(3) << fmt::format(
        "Dropping packet due to DCID parsing error={}, , errorCode={}, routingInfo={}",
        connIdParam.error().what(),
        folly::to<std::string>(connIdParam.error().errorCode()),
        logRoutingInfo(routingData.destinationConnId));
    QUIC_STATS(statsCallback_, onPacketDropped, PacketDropReason::PARSE_ERROR);
    // TODO do we need to reset?
    return;
  }
  if (connIdParam->hostId != hostId_) {
    VLOG_EVERY_N(2, 100) << fmt::format(
        "Dropping packet routed to wrong host, from client={}, routingInfo={},",
        client.describe(),
        logRoutingInfo(routingData.destinationConnId));
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
  VLOG(4) << fmt::format(
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

folly::Optional<std::string> QuicServerWorker::maybeGetEncryptedToken(
    folly::io::Cursor& cursor) {
  // Move cursor to the byte right after the initial byte
  if (!cursor.canAdvance(1)) {
    return folly::none;
  }
  auto initialByte = cursor.readBE<uint8_t>();

  // We already know this is an initial packet, which uses a long header
  auto parsedLongHeader = parseLongHeader(initialByte, cursor);
  if (!parsedLongHeader || !parsedLongHeader->parsedLongHeader.has_value()) {
    return folly::none;
  }

  auto header = parsedLongHeader->parsedLongHeader.value().header;
  if (!header.hasToken()) {
    return folly::none;
  }
  return header.getToken();
}

/**
 * Helper method to calculate the delta between nowInMs and the time the token
 * was issued. This delta is compared against the max lifetime of the token
 * (e.g. 1 day for new tokens and 5 min for retry tokens) to determine
 * validity.
 */
bool checkTokenAge(uint64_t tokenIssuedMs, uint64_t kTokenValidMs) {
  uint64_t nowInMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();

  // Retry timestamps can also come from the future as the system clock can
  // move both forwards and backwards due to it being synchronized by NTP
  auto tokenAgeMs = nowInMs > tokenIssuedMs ? nowInMs - tokenIssuedMs
                                            : tokenIssuedMs - nowInMs;

  return tokenAgeMs <= kTokenValidMs;
}

bool QuicServerWorker::validRetryToken(
    std::string& encryptedToken,
    const ConnectionId& dstConnId,
    const folly::IPAddress& clientIp) {
  CHECK(transportSettings_.retryTokenSecret.hasValue());

  TokenGenerator tokenGenerator(transportSettings_.retryTokenSecret.value());

  // Create a psuedo token to generate the assoc data.
  RetryToken token(dstConnId, clientIp, 0);

  auto maybeDecryptedRetryTokenMs = tokenGenerator.decryptToken(
      folly::IOBuf::copyBuffer(encryptedToken), token.genAeadAssocData());

  return maybeDecryptedRetryTokenMs &&
      checkTokenAge(maybeDecryptedRetryTokenMs, kMaxRetryTokenValidMs);
}

bool QuicServerWorker::validNewToken(
    std::string& encryptedToken,
    const folly::IPAddress& clientIp) {
  CHECK(transportSettings_.retryTokenSecret.hasValue());

  TokenGenerator tokenGenerator(transportSettings_.retryTokenSecret.value());

  // Create a psuedo token to generate the assoc data.
  NewToken token(clientIp);

  auto maybeDecryptedNewTokenMs = tokenGenerator.decryptToken(
      folly::IOBuf::copyBuffer(encryptedToken), token.genAeadAssocData());

  return maybeDecryptedNewTokenMs &&
      checkTokenAge(maybeDecryptedNewTokenMs, kMaxNewTokenValidMs);
}

void QuicServerWorker::sendRetryPacket(
    const folly::SocketAddress& client,
    const ConnectionId& dstConnId,
    const ConnectionId& srcConnId) {
  // Create the encrypted retry token
  TokenGenerator generator(transportSettings_.retryTokenSecret.value());

  // RetryToken defaults to currentTimeInMs
  RetryToken retryToken(dstConnId, client.getIPAddress(), client.getPort());
  auto encryptedToken = generator.encryptToken(retryToken);

  CHECK(encryptedToken.has_value());
  std::string encryptedTokenStr =
      encryptedToken.value()->moveToFbString().toStdString();

  // Create the integrity tag
  // For the tag to be correctly validated by the client, the initalByte
  // needs to match the initialByte in the retry packet
  uint8_t initialByte = kHeaderFormMask | LongHeader::kFixedBitMask |
      (static_cast<uint8_t>(LongHeader::Types::Retry)
       << LongHeader::kTypeShift);

  // Flip the src conn ID and dst conn ID as per section 7.3 of QUIC draft
  // for both pseudo retry builder and the actual retry packet builder
  PseudoRetryPacketBuilder pseudoBuilder(
      initialByte,
      dstConnId, /* src conn id */
      srcConnId, /* dst conn id */
      dstConnId, /* orginal dst conn id */
      QuicVersion::MVFST_INVALID,
      folly::IOBuf::copyBuffer(encryptedTokenStr));
  Buf pseudoRetryPacketBuf = std::move(pseudoBuilder).buildPacket();
  FizzRetryIntegrityTagGenerator fizzRetryIntegrityTagGenerator;
  auto integrityTag = fizzRetryIntegrityTagGenerator.getRetryIntegrityTag(
      QuicVersion::MVFST_INVALID, pseudoRetryPacketBuf.get());

  // Create the actual retry packet
  RetryPacketBuilder builder(
      dstConnId, /* src conn id */
      srcConnId, /* dst conn id */
      QuicVersion::MVFST_INVALID,
      std::move(encryptedTokenStr),
      std::move(integrityTag));

  auto retryData = std::move(builder).buildPacket();
  auto retryDataLen = retryData->computeChainDataLength();

  socket_->write(client, retryData);
  QUIC_STATS(statsCallback_, onWrite, retryDataLen);
  QUIC_STATS(statsCallback_, onPacketSent);
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

TakeoverProtocolVersion QuicServerWorker::getTakeoverProtocolVersion()
    const noexcept {
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

void QuicServerWorker::rejectNewConnections(
    std::function<bool()> rejectNewConnections) {
  rejectNewConnections_ = std::move(rejectNewConnections);
}

void QuicServerWorker::setIsBlockListedSrcPort(
    std::function<bool(uint16_t)> isBlockListedSrcPort) {
  isBlockListedSrcPort_ = std::move(isBlockListedSrcPort);
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

  auto& localConnectionError = transport->getState()->localConnectionError;
  if (transport->getConnectionsStats().totalBytesSent == 0 &&
      !(localConnectionError && localConnectionError->code.asLocalErrorCode() &&
        *localConnectionError->code.asLocalErrorCode() ==
            LocalErrorCode::CONNECTION_ABANDONED)) {
    QUIC_STATS(statsCallback_, onConnectionCloseZeroBytesWritten);
  }

  // Ensures we only process `onConnectionUnbound()` once.
  transport->setRoutingCallback(nullptr);
  boundServerTransports_.erase(transport);

  for (auto& connId : connectionIdData) {
    VLOG(4) << fmt::format(
        "Removing CID from connectionIdMap_, routingInfo={}",
        logRoutingInfo(connId.connId));
    auto it = connectionIdMap_.find(connId.connId);
    // This should be nullptr in most cases. In order to investigate if
    // an incorrect server transport is removed, this will be set to the value
    // of the incorrect transport, to see if boundServerTransports_ will
    // still hold a pointer to the incorrect transport.
    QuicServerTransport* incorrectTransportPtr = nullptr;
    if (it == connectionIdMap_.end()) {
      VLOG(3) << "CID not found in connectionIdMap_ CID= " << connId.connId;
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

  sourceAddressMap_.erase(source);
}

void QuicServerWorker::onHandshakeFinished() noexcept {
  CHECK_GE(--globalUnfinishedHandshakes, 0);
}

void QuicServerWorker::onHandshakeUnfinished() noexcept {
  CHECK_GE(--globalUnfinishedHandshakes, 0);
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
    transport->setHandshakeFinishedCallback(nullptr);
    transport->closeNow(
        QuicError(QuicErrorCode(error), std::string("shutting down")));
  }

  // Shut down all transports with bound connection ids.
  for (auto transport : boundServerTransports_) {
    if (auto t = transport.second.lock()) {
      t->setRoutingCallback(nullptr);
      t->setTransportStatsCallback(nullptr);
      t->setHandshakeFinishedCallback(nullptr);
      t->closeNow(
          QuicError(QuicErrorCode(error), std::string("shutting down")));
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
  pacingTimer_.reset();
}

QuicServerWorker::~QuicServerWorker() {
  shutdownAllConnections(LocalErrorCode::SHUTTING_DOWN);
}

bool QuicServerWorker::rejectConnectionId(
    const ConnectionId& candidate) const noexcept {
  return connectionIdMap_.find(candidate) != connectionIdMap_.end();
}

std::string QuicServerWorker::logRoutingInfo(const ConnectionId& connId) const {
  constexpr auto base =
      "CID={}, cidVersion={}, workerId={}, processId={}, hostId={}, threadId={}, ";
  if (!connIdAlgo_->canParse(connId)) {
    return fmt::format(
        base,
        connId.hex(),
        (uint32_t)cidVersion_,
        (uint32_t)workerId_,
        (uint32_t)processId_,
        (uint32_t)hostId_,
        folly::getCurrentThreadID());
  }
  auto connIdParam = connIdAlgo_->parseConnectionId(connId);
  if (connIdParam.hasError()) {
    return fmt::format(
        base,
        connId.hex(),
        (uint32_t)cidVersion_,
        (uint32_t)workerId_,
        (uint32_t)processId_,
        (uint32_t)hostId_,
        folly::getCurrentThreadID());
  }
  std::string extended = std::string(base) +
      "cidVersion in packet={}, workerId in packet={}, processId in packet={}, hostId in packet={}, ";
  return fmt::vformat(
      extended,
      fmt::make_format_args(
          connId.hex(),
          (uint32_t)cidVersion_,
          (uint32_t)workerId_,
          (uint32_t)processId_,
          (uint32_t)hostId_,
          folly::getCurrentThreadID(),
          (uint32_t)connIdParam->version,
          (uint32_t)connIdParam->workerId,
          (uint32_t)connIdParam->processId,
          (uint32_t)connIdParam->hostId));
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
  // adding the same observer multiple times is not allowed
  CHECK(
      std::find(observers_.begin(), observers_.end(), observer) ==
      observers_.end());

  observers_.emplace_back(CHECK_NOTNULL(observer));
  observer->observerAttach(worker_);
}

bool QuicServerWorker::AcceptObserverList::remove(AcceptObserver* observer) {
  auto it = std::find(observers_.begin(), observers_.end(), observer);
  if (it == observers_.end()) {
    return false;
  }
  observer->observerDetach(worker_);
  observers_.erase(it);
  return true;
}

void QuicServerWorker::getAllConnectionsStats(
    std::vector<QuicConnectionStats>& stats) {
  folly::F14FastMap<QuicServerTransport::Ptr, uint32_t> uniqueConns;
  for (const auto& conn : connectionIdMap_) {
    if (!conn.second) {
      continue;
    }
    auto connState =
        static_cast<const QuicServerConnectionState*>(conn.second->getState());
    if (!connState) {
      continue;
    }
    uniqueConns[conn.second]++;
  }
  stats.reserve(stats.size() + uniqueConns.size());
  for (const auto& connEntry : uniqueConns) {
    QuicConnectionStats connStats = connEntry.first->getConnectionsStats();
    connStats.workerID = workerId_;
    connStats.numConnIDs = connEntry.second;
    stats.emplace_back(connStats);
  }
}

} // namespace quic
