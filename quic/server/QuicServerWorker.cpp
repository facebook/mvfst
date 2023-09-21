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
#include <quic/server/QuicServerWorker.h>
#include <quic/server/handshake/StatelessResetGenerator.h>
#include <quic/server/handshake/TokenGenerator.h>
#include <quic/server/third-party/siphash.h>
#include <quic/state/QuicConnectionStats.h>

// This hook is invoked by mvfst for every UDP socket it creates.
#if FOLLY_HAVE_WEAK_SYMBOLS
extern "C" FOLLY_ATTR_WEAK void mvfst_hook_on_socket_create(int fd);
#else
static void (*mvfst_hook_on_socket_create)(int fd) = nullptr;
#endif

namespace {
bool isValidConnIdLength(const quic::ConnectionId& connId) {
  return quic::kMinInitialDestinationConnIdLength <= connId.size() &&
      connId.size() <= quic::kMaxConnectionIdSize;
}
} // namespace

namespace quic {

std::atomic_int globalUnfinishedHandshakes{0};

QuicServerWorker::QuicServerWorker(
    std::shared_ptr<QuicServerWorker::WorkerCallback> callback,
    SetEventCallback ec)
    : callback_(std::move(callback)),
      setEventCallback_(ec),
      takeoverPktHandler_(this),
      observerList_(this) {
  pending0RttData_.setPruneHook(
      [&](auto, auto) { QUIC_STATS(statsCallback_, onZeroRttBufferedPruned); });
}

folly::EventBase* QuicServerWorker::getEventBase() const {
  return evb_.get();
}

void QuicServerWorker::setSocket(
    std::unique_ptr<QuicAsyncUDPSocketWrapper> socket) {
  socket_ = std::move(socket);
  evb_ = folly::Executor::KeepAlive(socket_->getEventBase());
}

void QuicServerWorker::bind(
    const folly::SocketAddress& address,
    QuicAsyncUDPSocketWrapper::BindOptions bindOptions) {
  DCHECK(!supportedVersions_.empty());
  CHECK(socket_);
  switch (setEventCallback_) {
    case SetEventCallback::NONE:
      break;
    case SetEventCallback::RECVMSG:
      socket_->setEventCallback(this);
      break;
    case SetEventCallback::RECVMSG_MULTISHOT:
      socket_->setRecvmsgMultishotCallback(this);
      break;
  };
  // TODO this totally doesn't work, we can't apply socket options before
  // bind, since bind creates the fd.
  if (socketOptions_) {
    applySocketOptions(
        *socket_,
        *socketOptions_,
        address.getFamily(),
        folly::SocketOptionKey::ApplyPos::PRE_BIND);
  }
  socket_->bind(address, bindOptions);
  if (socketOptions_) {
    applySocketOptions(
        *socket_,
        *socketOptions_,
        address.getFamily(),
        folly::SocketOptionKey::ApplyPos::POST_BIND);
  }
  socket_->setDFAndTurnOffPMTU();
  if (transportSettings_.numGROBuffers_ > kDefaultNumGROBuffers) {
    socket_->setGRO(true);
    if (socket_->getGRO() > 0) {
      numGROBuffers_ = std::min(
          transportSettings_.numGROBuffers_, (uint32_t)kMaxNumGROBuffers);
    }
  }
  socket_->setTimestamping(SOF_TIMESTAMPING_SOFTWARE);
  socket_->setTXTime({CLOCK_MONOTONIC, /*deadline=*/false});

  if (mvfst_hook_on_socket_create) {
    mvfst_hook_on_socket_create(getSocketFd(*socket_));
  }
}

void QuicServerWorker::applyAllSocketOptions() {
  CHECK(socket_);
  if (socketOptions_) {
    applySocketOptions(
        *socket_,
        *socketOptions_,
        getAddress().getFamily(),
        folly::SocketOptionKey::ApplyPos::PRE_BIND);
    applySocketOptions(
        *socket_,
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
        evb_.get(), transportSettings_.pacingTimerResolution);
  }
  socket_->resumeRead(this);
  VLOG(10) << fmt::format(
      "Registered read on worker={}, thread={}, processId={}",
      fmt::ptr(this),
      folly::getCurrentThreadID(),
      (int)processId_);
}

void QuicServerWorker::timeoutExpired() noexcept {
  logTimeBasedStats();
}

void QuicServerWorker::logTimeBasedStats() {
  for (auto [transport, handle] : boundServerTransports_) {
    if (!handle.expired()) {
      transport->logTimeBasedStats();
    }
  }
  evb_->timer().scheduleTimeout(this, timeLoggingSamplingInterval_);
}

void QuicServerWorker::pauseRead() {
  CHECK(socket_);
  socket_->pauseRead();
}

int QuicServerWorker::getFD() {
  CHECK(socket_);
  return getSocketFd(*socket_);
}

const folly::SocketAddress& QuicServerWorker::getAddress() const {
  CHECK(socket_);
  return socket_->address();
}

void QuicServerWorker::getReadBuffer(void** buf, size_t* len) noexcept {
  auto readBufferSize = transportSettings_.maxRecvPacketSize * numGROBuffers_;
  readBuffer_ = folly::IOBuf::createCombined(readBufferSize);
  *buf = readBuffer_->writableData();
  *len = readBufferSize;
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
        statsCallback_, onPacketDropped, PacketDropReason::INVALID_PACKET_SIZE);
    return true;
  }
  isInitial =
      isInitial && invariant.version != QuicVersion::VERSION_NEGOTIATION;
  if (rejectNewConnections_() && isInitial) {
    VersionNegotiationPacketBuilder builder(
        invariant.dstConnId,
        invariant.srcConnId,
        std::vector<QuicVersion>{QuicVersion::MVFST_INVALID});
    versionNegotiationPacket.emplace(std::move(builder).buildPacket());
  }
  if (!versionNegotiationPacket) {
    bool negotiationNeeded = std::find(
                                 supportedVersions_.begin(),
                                 supportedVersions_.end(),
                                 invariant.version) == supportedVersions_.end();
    if (negotiationNeeded && !isInitial) {
      VLOG(3) << "Dropping non-initial packet due to invalid version";
      QUIC_STATS(
          statsCallback_,
          onPacketDropped,
          PacketDropReason::INVALID_PACKET_VERSION);
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

void QuicServerWorker::sendVersionNegotiationPacket(
    const folly::SocketAddress& client,
    LongHeaderInvariant& invariant) {
  VersionNegotiationPacketBuilder builder(
      invariant.dstConnId, invariant.srcConnId, supportedVersions_);
  auto versionNegotiationPacket = std::move(builder).buildPacket();
  VLOG(4) << "Version negotiation sent to client=" << client;
  auto len = versionNegotiationPacket.second->computeChainDataLength();
  QUIC_STATS(statsCallback_, onWrite, len);
  QUIC_STATS(statsCallback_, onPacketProcessed);
  QUIC_STATS(statsCallback_, onPacketSent);
  socket_->write(client, versionNegotiationPacket.second);
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
      if (static_cast<int>(remaining) <= params.gro) {
        // do not clone the last packet
        // start at offset, use all the remaining data
        data->trimStart(offset);
        DCHECK_EQ(data->length(), remaining);
        handleNetworkData(client, std::move(data), packetReceiveTime);
        break;
      }
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
    }
  }
}

void QuicServerWorker::handleNetworkData(
    const folly::SocketAddress& client,
    Buf data,
    const TimePoint& packetReceiveTime,
    bool isForwardedData) noexcept {
  // if packet drop reason is set, invoke stats cb accordingly
  auto packetDropReason = PacketDropReason::NONE;
  auto maybeReportPacketDrop = folly::makeGuard([&]() {
    if (packetDropReason != PacketDropReason::NONE) {
      QUIC_STATS(statsCallback_, onPacketDropped, packetDropReason);
    }
  });

  try {
    // check error conditions for packet drop & early return
    folly::io::Cursor cursor(data.get());
    if (shutdown_) {
      VLOG(4) << "Packet received after shutdown, dropping";
      packetDropReason = PacketDropReason::SERVER_SHUTDOWN;
    } else if (isBlockListedSrcPort_(client.getPort())) {
      VLOG(4) << "Dropping packet with blocklisted src port: "
              << client.getPort();
      packetDropReason = PacketDropReason::INVALID_SRC_PORT;
    } else if (!callback_) {
      VLOG(0) << "Worker callback is null.  Dropping packet.";
      packetDropReason = PacketDropReason::WORKER_NOT_INITIALIZED;
    } else if (!cursor.canAdvance(sizeof(uint8_t))) {
      VLOG(4) << "Dropping packet too small";
      packetDropReason = PacketDropReason::INVALID_PACKET_INITIAL_BYTE;
    }

    // terminate early
    if (packetDropReason != PacketDropReason::NONE) {
      return;
    }

    uint8_t initialByte = cursor.readBE<uint8_t>();
    HeaderForm headerForm = getHeaderForm(initialByte);
    if (headerForm == HeaderForm::Short) {
      if (auto maybeParsedShortHeader =
              parseShortHeaderInvariants(initialByte, cursor)) {
        RoutingData routingData(
            headerForm,
            false, /* isInitial */
            false, /* is0Rtt */
            std::move(maybeParsedShortHeader->destinationConnId),
            folly::none);
        return forwardNetworkData(
            client,
            std::move(routingData),
            NetworkData(std::move(data), packetReceiveTime),
            folly::none, /* quicVersion */
            isForwardedData);
      }
    } else if (
        auto maybeParsedLongHeader =
            parseLongHeaderInvariant(initialByte, cursor)) {
      // TODO: check version before looking at type
      LongHeader::Types longHeaderType = parseLongHeaderType(initialByte);
      bool isInitial = longHeaderType == LongHeader::Types::Initial;
      bool is0Rtt = longHeaderType == LongHeader::Types::ZeroRtt;
      auto& invariant = maybeParsedLongHeader->invariant;

      if (isInitial) {
        // This stats gets updated even if the client initial will be dropped.
        QUIC_STATS(statsCallback_, onClientInitialReceived, invariant.version);
      }

      if (maybeSendVersionNegotiationPacketOrDrop(
              client, isInitial, invariant, data->computeChainDataLength())) {
        return;
      }

      bool isClientChosenDcid = isInitial || is0Rtt;
      if (!isClientChosenDcid &&
          invariant.dstConnId.size() < kMinSelfConnectionIdV1Size) {
        // drop packet if connId is present but is not valid.
        VLOG(3) << "Dropping packet due to invalid connectionId";
        packetDropReason = PacketDropReason::INVALID_PACKET_CID;
        return;
      }
      RoutingData routingData(
          headerForm,
          isInitial,
          is0Rtt,
          std::move(invariant.dstConnId),
          std::move(invariant.srcConnId));
      return forwardNetworkData(
          client,
          std::move(routingData),
          NetworkData(std::move(data), packetReceiveTime),
          invariant.version,
          isForwardedData);
    }

    if (!tryHandlingAsHealthCheck(client, *data)) {
      VLOG(6) << "Failed to parse long header";
      packetDropReason = PacketDropReason::PARSE_ERROR_LONG_HEADER;
    }
  } catch (const std::exception& ex) {
    // Drop the packet.
    VLOG(6) << "Failed to parse packet header " << ex.what();
    packetDropReason = PacketDropReason::PARSE_ERROR_EXCEPTION;
  }
}

void QuicServerWorker::recvmsgMultishotCallback(
    MultishotHdr* hdr,
    int res,
    std::unique_ptr<folly::IOBuf> io_buf) {
  if (res < 0) {
    return;
  }

  folly::EventRecvmsgMultishotCallback::ParsedRecvMsgMultishot p;
  if (!folly::EventRecvmsgMultishotCallback::parseRecvmsgMultishot(
          io_buf->coalesce(), hdr->data_, p)) {
    return;
  }

  auto bytesRead = p.payload.size();
  if (bytesRead > 0) {
    OnDataAvailableParams params;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (p.control.size()) {
      // hacky
      struct msghdr msg;
      msg.msg_controllen = p.control.size();
      msg.msg_control = (void*)p.control.data();
      QuicAsyncUDPSocketWrapper::fromMsg(params, msg);
    }
#endif
    bool truncated = false;
    if ((size_t)bytesRead != p.realPayloadLength) {
      truncated = true;
    }

    folly::SocketAddress addr;
    addr.setFromSockaddr(
        reinterpret_cast<sockaddr const*>(p.name.data()), p.name.size());
    io_buf->trimStart(p.payload.data() - io_buf->data());
    readBuffer_ = std::move(io_buf);

    // onDataAvailable will add bytesRead back
    readBuffer_->trimEnd(bytesRead);
    onDataAvailable(addr, bytesRead, truncated, params);
  }
}

void QuicServerWorker::eventRecvmsgCallback(MsgHdr* msgHdr, int bytesRead) {
  auto& msg = msgHdr->data_;
  if (bytesRead > 0) {
    OnDataAvailableParams params;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (msg.msg_control) {
      QuicAsyncUDPSocketWrapper::fromMsg(params, msg);
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
  // mismatches: forward if pktForwarding is enabled else dropPacket
  if (!routingData.clientChosenDcid &&
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
          PacketDropReason::UNKNOWN_CID_VERSION);
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

QuicServerTransport::Ptr QuicServerWorker::makeTransport(
    QuicVersion quicVersion,
    const folly::SocketAddress& client,
    const folly::Optional<ConnectionId>& srcConnId,
    const ConnectionId& dstConnId,
    bool validNewToken) {
  // create 'accepting' transport
  auto* evb = getEventBase();
  auto sock = makeSocket(evb);
  auto trans =
      transportFactory_->make(evb, std::move(sock), client, quicVersion, ctx_);
  if (trans) {
    globalUnfinishedHandshakes++;
    if (transportSettings_.dataPathType == DataPathType::ContinuousMemory &&
        bufAccessor_) {
      trans->setBufAccessor(bufAccessor_.get());
    }
    trans->setPacingTimer(pacingTimer_);
    trans->setRoutingCallback(this);
    trans->setHandshakeFinishedCallback(this);
    trans->setSupportedVersions(supportedVersions_);
    trans->setOriginalPeerAddress(client);
    if (validNewToken) {
      trans->verifiedClientAddress();
    }
    trans->setCongestionControllerFactory(ccFactory_);
    trans->setTransportStatsCallback(statsCallback_.get()); // ok if nullptr
    if (quicVersion == QuicVersion::MVFST_EXPERIMENTAL) {
      transportSettings_.initCwndInMss = 45;
    }

    auto transportSettings = transportSettingsOverrideFn_
        ? transportSettingsOverrideFn_(
              transportSettings_, client.getIPAddress())
              .value_or(transportSettings_)
        : transportSettings_;
    LOG_IF(
        ERROR,
        transportSettings.dataPathType != transportSettings_.dataPathType)
        << "Overriding DataPathType isn't supported. Requested datapath="
        << (transportSettings.dataPathType == DataPathType::ContinuousMemory
                ? "ContinuousMemory"
                : "ChainedMemory");
    trans->setTransportSettings(transportSettings);
    trans->setConnectionIdAlgo(connIdAlgo_.get());
    trans->setServerConnectionIdRejector(this);
    if (srcConnId) {
      trans->setClientConnectionId(*srcConnId);
    }
    trans->setClientChosenDestConnectionId(dstConnId);
    // parameters to create server chosen connection id
    trans->setServerConnectionIdParams(ServerConnectionIdParams(
        cidVersion_, hostId_, static_cast<uint8_t>(processId_), workerId_));
    trans->accept();
    auto result = sourceAddressMap_.emplace(
        std::make_pair(std::make_pair(client, dstConnId), trans));
    CHECK(result.second);
    for (const auto& observer : observerList_.getAll()) {
      observer->accept(trans.get());
    }
  }

  return trans;
}

PacketDropReason QuicServerWorker::isDstConnIdMisrouted(
    const ConnectionId& dstConnId,
    const folly::SocketAddress& client) {
  // parse dst conn-id to determine if packet was misrouted
  if (!connIdAlgo_->canParse(dstConnId)) {
    VLOG(3) << "Dropping packet with bad DCID, routingInfo="
            << logRoutingInfo(dstConnId);
    // TODO do we need to reset?
    return PacketDropReason::PARSE_ERROR_BAD_DCID;
  }

  auto maybeParsedConnIdParam = connIdAlgo_->parseConnectionId(dstConnId);
  if (maybeParsedConnIdParam.hasError()) {
    const auto& ex = maybeParsedConnIdParam.error();
    VLOG(3) << fmt::format(
        "Dropping packet due to DCID parsing error={}, errorCode={},"
        "routingInfo = {} ",
        ex.what(),
        folly::to_underlying(ex.errorCode()),
        logRoutingInfo(dstConnId));
    // TODO do we need to reset?
    return PacketDropReason::PARSE_ERROR_DCID;
  }

  const auto& connIdParams = maybeParsedConnIdParam.value();
  if (connIdParams.hostId != hostId_) {
    VLOG(3) << fmt::format(
        "Dropping packet routed to wrong host, from client={}, routingInfo={},",
        client.describe(),
        logRoutingInfo(dstConnId));
    return PacketDropReason::ROUTING_ERROR_WRONG_HOST;
  }
  if (connIdParams.processId == static_cast<uint8_t>(processId_)) {
    // There's no existing connection for the packet's CID or the client's
    // addr, and doesn't belong to the old server. Send a Reset.
    VLOG(3) << fmt::format(
        "Dropping packet, unknown DCID, from client={}, routingInfo={},",
        client.describe(),
        logRoutingInfo(dstConnId));
    return PacketDropReason::CONNECTION_NOT_FOUND;
  }

  return PacketDropReason::NONE;
}

void QuicServerWorker::dispatchPacketData(
    const folly::SocketAddress& client,
    RoutingData&& routingData,
    NetworkData&& networkData,
    folly::Optional<QuicVersion> quicVersion,
    bool isForwardedData) noexcept {
  DCHECK(socket_);
  CHECK(transportFactory_);

  // if set, log drop reason and do *not* attempt to forward packet
  auto packetDropReason = PacketDropReason::NONE;
  // if set, *should* attempt to forward packet to another server
  bool shouldFwdPacket = false;
  const auto& maybeSrcConnId = routingData.sourceConnId;
  const auto& dstConnId = routingData.destinationConnId;
  auto cit = connectionIdMap_.find(dstConnId);

  // if conditions satisfy, drop packet or fwd to another server
  auto handlePacketFwdOrDrop = folly::makeGuard([&]() {
    if (packetDropReason == PacketDropReason::NONE && !shouldFwdPacket) {
      // nothing to do here, early return
      return;
    }
    // should either be marked as dropped or fwd-ed, can't be both
    CHECK((packetDropReason != PacketDropReason::NONE) ^ shouldFwdPacket);

    if (packetDropReason != PacketDropReason::NONE) {
      QUIC_STATS(statsCallback_, onPacketDropped, packetDropReason);
      return;
    }

    packetDropReason = isDstConnIdMisrouted(dstConnId, client);
    if (packetDropReason != PacketDropReason::NONE) {
      QUIC_STATS(statsCallback_, onPacketDropped, packetDropReason);
      if (packetDropReason == PacketDropReason::ROUTING_ERROR_WRONG_HOST ||
          packetDropReason == PacketDropReason::CONNECTION_NOT_FOUND) {
        // packet was misrouted, send reset packet
        sendResetPacket(routingData.headerForm, client, networkData, dstConnId);
      }
      return;
    }

    // send reset packet if packet fwd-ing isn't enabled or packet has
    // already been fwd-ed
    if (!packetForwardingEnabled_ || isForwardedData) {
      packetDropReason = PacketDropReason::CANNOT_FORWARD_DATA;
      VLOG(3) << fmt::format(
          "Dropping packet, cannot forward, from client={}, routingInfo={},",
          client.describe(),
          logRoutingInfo(dstConnId));
      QUIC_STATS(statsCallback_, onPacketDropped, packetDropReason);
      sendResetPacket(routingData.headerForm, client, networkData, dstConnId);
      return;
    }

    // Optimistically route to another server if the packet type is not
    // Initial and if there is not any connection associated with the given
    // packet
    VLOG(4) << fmt::format(
        "Forwarding packet from client={} to another process, routingInfo={}",
        client.describe(),
        logRoutingInfo(dstConnId));
    auto recvTime = networkData.receiveTimePoint;
    takeoverPktHandler_.forwardPacketToAnotherServer(
        client, std::move(networkData).moveAllData(), recvTime);
    QUIC_STATS(statsCallback_, onPacketForwarded);
  });

  // helper fn to handle fwd-ing data to the transport
  auto fwdNetworkDataToTransport = [&](QuicServerTransport* transport) {
    DCHECK(transport->getEventBase()->isInEventBaseThread());
    transport->onNetworkData(client, std::move(networkData));
    // process pending 0rtt data for this DCID if present
    if (routingData.isInitial && !pending0RttData_.empty()) {
      auto itr = pending0RttData_.find(dstConnId);
      if (itr != pending0RttData_.end()) {
        for (auto& data : itr->second) {
          transport->onNetworkData(client, std::move(data));
        }
        pending0RttData_.erase(itr);
      }
    }
  };

  if (cit != connectionIdMap_.end()) {
    VLOG(10) << "Found existing connection for CID=" << dstConnId.hex() << " "
             << *cit->second.get();
    fwdNetworkDataToTransport(cit->second.get());
    return;
  }

  if (routingData.headerForm == HeaderForm::Short) {
    // Drop if short header packet w/ unrecognized dst conn id
    VLOG(3) << fmt::format(
        "Dropping short header packet with no connid match routingInfo={}",
        logRoutingInfo(dstConnId));
    // try forwarding the packet to the old server (if it is enabled)
    shouldFwdPacket = true;
    return;
  }

  // For LongHeader packets without existing associated connection, try to
  // route with destinationConnId chosen by the peer and IP address of the
  // peer.
  CHECK(routingData.headerForm == HeaderForm::Long);
  auto sit = sourceAddressMap_.find({client, dstConnId});
  if (sit != sourceAddressMap_.end()) {
    VLOG(4) << "Found existing connection for client=" << client << " "
            << sit->second.get();
    fwdNetworkDataToTransport(sit->second.get());
    return;
  }

  // If it's a 0RTT packet and we have no CID, we probably lost the
  // initial and want to buffer it for a while.
  if (routingData.is0Rtt) {
    // creates vector if it doesn't already exist
    auto& vec = pending0RttData_.insert(dstConnId, {}).first->second;
    if (vec.size() < vec.max_size()) {
      vec.emplace_back(std::move(networkData));
      QUIC_STATS(statsCallback_, onZeroRttBuffered);
    }
    return;
  }

  // non-initial packet w/o existing connection may have been misrouted.
  if (!routingData.isInitial) {
    VLOG(3) << fmt::format(
        "Dropping packet from client={}, routingInfo={}",
        client.describe(),
        logRoutingInfo(dstConnId));
    // try forwarding the packet to the old server (if it is enabled)
    shouldFwdPacket = true;
    return;
  }

  // check that we have a proper quic version before creating transport
  CHECK(quicVersion.has_value()) << "no QUIC version to create transport";
  VLOG(4) << fmt::format(
      "Creating new connection for client={}, routingInfo={}",
      client.describe(),
      logRoutingInfo(dstConnId));

  // This could be a new connection, add it in the map
  // verify that the initial packet is at least min initial bytes
  // to avoid amplification attacks. Also check CID sizes.
  if (networkData.totalData < kMinInitialPacketSize ||
      !isValidConnIdLength(dstConnId)) {
    // Don't even attempt to forward the packet, just drop it.
    VLOG(3) << "Dropping small initial packet from client=" << client;
    packetDropReason = PacketDropReason::INVALID_PACKET_SIZE_INITIAL;
    return;
  }

  // If there is a token present, decrypt it (could be either a retry
  // token or a new token)
  folly::io::Cursor cursor(networkData.packets.front().buf.get());
  auto maybeEncryptedToken = maybeGetEncryptedToken(cursor);
  bool hasTokenSecret = transportSettings_.retryTokenSecret.hasValue();

  // If the retryTokenSecret is not set, just skip evaluating validity of
  // token and assume true
  bool isValidRetryToken = !hasTokenSecret ||
      (maybeEncryptedToken &&
       validRetryToken(*maybeEncryptedToken, dstConnId, client.getIPAddress()));

  bool isValidNewToken = !hasTokenSecret ||
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
        globalUnfinishedHandshakes >= (*unfinishedHandshakeLimitFn_)()))) {
    QUIC_STATS(statsCallback_, onConnectionRateLimited);
    sendRetryPacket(
        client,
        dstConnId,
        maybeSrcConnId.value_or(ConnectionId(std::vector<uint8_t>())));
    return;
  }

  auto transport = makeTransport(
      quicVersion.value(), client, maybeSrcConnId, dstConnId, isValidNewToken);
  if (!transport) {
    // Act as though we received a junk Initial – don't forward packet.
    CHECK(maybeSrcConnId.has_value());
    LongHeaderInvariant inv{
        QuicVersion::MVFST_INVALID, maybeSrcConnId.value(), dstConnId};
    packetDropReason = PacketDropReason::CANNOT_MAKE_TRANSPORT;
    sendVersionNegotiationPacket(client, inv);
    return;
  }
  fwdNetworkDataToTransport(transport.get());
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
static bool checkTokenAge(uint64_t tokenIssuedMs, uint64_t kTokenValidMs) {
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

  // Create a pseudo token to generate the assoc data.
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

  // Create a pseudo token to generate the assoc data.
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
  if (!transportSettings_.retryTokenSecret.hasValue()) {
    VLOG(4) << "Not sending retry packet since retry token secret is not set";
    return;
  }

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
      dstConnId, /* original dst conn id */
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
    std::unique_ptr<QuicAsyncUDPSocketWrapper> socket,
    const folly::SocketAddress& address) {
  DCHECK(!takeoverCB_);
  // We instantiate and bind the TakeoverHandlerCallback to the given address.
  // It is reset at shutdownAllConnections (i.e. only when the process dies).
  takeoverCB_ = std::make_unique<TakeoverHandlerCallback>(
      this, takeoverPktHandler_, transportSettings_, std::move(socket));
  takeoverCB_->bind(address);
}

const folly::SocketAddress& QuicServerWorker::overrideTakeoverHandlerAddress(
    std::unique_ptr<QuicAsyncUDPSocketWrapper> socket,
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

std::unique_ptr<QuicAsyncUDPSocketWrapper> QuicServerWorker::makeSocket(
    folly::EventBase* evb) const {
  CHECK(socket_);
  auto sock = socketFactory_->make(evb, getSocketFd(*socket_));
  if (sock && mvfst_hook_on_socket_create) {
    mvfst_hook_on_socket_create(getSocketFd(*sock));
  }
  return sock;
}

std::unique_ptr<QuicAsyncUDPSocketWrapper> QuicServerWorker::makeSocket(
    folly::EventBase* evb,
    int fd) const {
  auto sock = socketFactory_->make(evb, fd);
  if (sock && mvfst_hook_on_socket_create) {
    mvfst_hook_on_socket_create(getSocketFd(*sock));
  }
  return sock;
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
    if (!isScheduled()) {
      // If we aren't currently running, start the timer.
      evb_->timer().scheduleTimeout(this, timeLoggingSamplingInterval_);
    }
    QUIC_STATS(statsCallback_, onNewConnection);
  }
}

void QuicServerWorker::onConnectionIdRetired(
    QuicServerTransport::Ref transport,
    ConnectionId id) noexcept {
  auto it = connectionIdMap_.find(id);
  if (it == connectionIdMap_.end()) {
    LOG(ERROR) << "Failed to retire CID=" << id << " " << transport;
  } else {
    VLOG(4) << "Retiring CID=" << id << " " << transport;
    connectionIdMap_.erase(it);
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
  // Cancel the timeout if we don't have any connections.
  if (boundServerTransports_.empty()) {
    cancelTimeout();
  }

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
  cancelTimeout();
  boundServerTransports_.clear();
  sourceAddressMap_.clear();
  connectionIdMap_.clear();
  takeoverPktHandler_.stop();
  if (statsCallback_) {
    statsCallback_.reset();
  }
  socket_.reset();
  takeoverCB_.reset();
  pacingTimer_.reset();
  evb_.reset();
}

QuicServerWorker::~QuicServerWorker() {
  shutdownAllConnections(LocalErrorCode::SHUTTING_DOWN);
}

bool QuicServerWorker::rejectConnectionId(
    const ConnectionId& candidate) const noexcept {
  return connectionIdMap_.find(candidate) != connectionIdMap_.end();
}

std::string QuicServerWorker::logRoutingInfo(const ConnectionId& connId) const {
  std::string base = fmt::format(
      "CID={}, cidVersion={}, workerId={}, processId={}, hostId={}, threadId={}, ",
      connId.hex(),
      (uint32_t)cidVersion_,
      (uint32_t)workerId_,
      (uint32_t)processId_,
      (uint32_t)hostId_,
      folly::getCurrentThreadID());

  if (connIdAlgo_->canParse(connId)) {
    auto maybeParsedConnIdParam = connIdAlgo_->parseConnectionId(connId);
    if (maybeParsedConnIdParam.hasValue()) {
      const auto& connIdParam = maybeParsedConnIdParam.value();
      return base +
          fmt::format(
                 "cidVersion in packet={}, workerId in packet={}, processId in packet={}, hostId in packet={}, ",
                 (uint32_t)connIdParam.version,
                 (uint32_t)connIdParam.workerId,
                 (uint32_t)connIdParam.processId,
                 (uint32_t)connIdParam.hostId);
    }
  }

  return base;
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
  for (const auto& [connId, transport] : connectionIdMap_) {
    if (transport && transport->getState()) {
      uniqueConns[transport]++;
    }
  }
  stats.reserve(stats.size() + uniqueConns.size());
  for (const auto& [transport, count] : uniqueConns) {
    QuicConnectionStats connStats = transport->getConnectionsStats();
    connStats.workerID = workerId_;
    connStats.numConnIDs = count;
    stats.emplace_back(connStats);
  }
}

size_t QuicServerWorker::SourceIdentityHash::operator()(
    const QuicServerTransport::SourceIdentity& sid) const {
  static const ::siphash::Key hashKey(
      folly::Random::secureRandom<std::uint64_t>(),
      folly::Random::secureRandom<std::uint64_t>());

  // We opt to manually lay out the key in order to ensure that our key
  // has a unique object representation. (i.e. no padding).
  //
  // (sockaddr, quic connection id, port)
  constexpr size_t kKeySize =
      sizeof(struct sockaddr_storage) + kMaxConnectionIdSize + sizeof(uint16_t);

  // Zero initialization is intentional here.
  std::array<unsigned char, kKeySize> key{};

  struct sockaddr_storage* storage =
      reinterpret_cast<struct sockaddr_storage*>(key.data());
  const auto& sockaddr = sid.first;
  sockaddr.getAddress(storage);

  unsigned char* connid = key.data() + sizeof(struct sockaddr_storage);
  memcpy(connid, sid.second.data(), sid.second.size());

  uint16_t* port = reinterpret_cast<uint16_t*>(
      key.data() + sizeof(struct sockaddr_storage) + kMaxConnectionIdSize);
  *port = sid.first.getPort();

  return siphash::siphash24(key.data(), key.size(), &hashKey);
}

} // namespace quic
