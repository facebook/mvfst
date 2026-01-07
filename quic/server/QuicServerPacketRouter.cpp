/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/system/ThreadId.h>
#include <quic/QuicConstants.h>
#include <quic/common/MvfstLogging.h>

#include <quic/server/QuicServerPacketRouter.h>
#include <quic/server/QuicServerWorker.h>

namespace quic {

/* Set max for the allocation of buffer to extract TakeoverProtocol related
 * information, such as client address, from packets forwarded by peer server.
 */
constexpr uint16_t kMaxBufSizeForTakeoverEncapsulation = 64;

TakeoverHandlerCallback::TakeoverHandlerCallback(
    QuicServerWorker* worker,
    TakeoverPacketHandler& takeoverPktHandler,
    const TransportSettings& transportSettings,
    std::unique_ptr<FollyAsyncUDPSocketAlias> socket)
    : worker_(worker),
      takeoverPktHandler_(takeoverPktHandler),
      transportSettings_(transportSettings),
      socket_(std::move(socket)) {}

TakeoverHandlerCallback::~TakeoverHandlerCallback() {
  if (socket_) {
    socket_->pauseRead();
    socket_.reset();
  }
}

void TakeoverHandlerCallback::bind(const folly::SocketAddress& addr) {
  MVCHECK(socket_);
  // first reset existing socket if any
  socket_->bind(addr);
  socket_->resumeRead(this);
}

void TakeoverHandlerCallback::rebind(
    std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
    const folly::SocketAddress& addr) {
  if (socket_) {
    // first reset existing socket if any
    socket_->pauseRead();
    socket_.reset();
  }
  socket_ = std::move(socket);
  socket_->bind(addr);
  socket_->resumeRead(this);
}

void TakeoverHandlerCallback::pause() {
  if (socket_) {
    socket_->pauseRead();
  }
}

const folly::SocketAddress& TakeoverHandlerCallback::getAddress() const {
  MVCHECK(socket_);
  return socket_->address();
}

int TakeoverHandlerCallback::getSocketFD() {
  MVCHECK(socket_);
  return socket_->getNetworkSocket().toFd();
}

void TakeoverHandlerCallback::getReadBuffer(void** buf, size_t* len) noexcept {
  readBuffer_ = BufHelpers::create(
      transportSettings_.maxRecvPacketSize +
      kMaxBufSizeForTakeoverEncapsulation);
  *buf = readBuffer_->writableData();
  *len = transportSettings_.maxRecvPacketSize +
      kMaxBufSizeForTakeoverEncapsulation;
}

void TakeoverHandlerCallback::onDataAvailable(
    const folly::SocketAddress& client,
    size_t len,
    bool truncated,
    OnDataAvailableParams /*params*/) noexcept {
  MVVLOG(10) << "Worker=" << this << " Received (takeover) data on thread="
             << folly::getCurrentThreadID()
             << ", workerId=" << static_cast<uint32_t>(worker_->getWorkerId())
             << ", processId="
             << static_cast<uint32_t>(worker_->getProcessId());
  // Move readBuffer_ first so that we can get rid
  // of it immediately so that if we return early,
  // we've flushed it.
  BufPtr data = std::move(readBuffer_);
  QUIC_STATS(worker_->getStatsCallback(), onForwardedPacketReceived);
  if (truncated) {
    // This is an error, drop the packet.
    return;
  }
  data->append(len);
  takeoverPktHandler_.processForwardedPacket(client, std::move(data));
}

void TakeoverHandlerCallback::onReadError(
    const folly::AsyncSocketException& ex) noexcept {
  folly::DelayedDestruction::DestructorGuard dg(this);
  MVVLOG(4) << "Error on TakeoverHandlerCallback " << ex.what();
  if (socket_) {
    socket_->pauseRead();
    // delete the socket_ in the next loop
    socket_->getEventBase()->runInLoop([this, dg] { socket_.reset(); });
  }
}

void TakeoverHandlerCallback::onReadClosed() noexcept {
  //  If we delete the socket in the callback of close, then this might cause
  //  some reentrancy in deletion, since close() in AsyncUDPSocket doesn't
  //  guard itself against deletion in the onReadClosed() callback.
  //  Doing nothing since the ASyncUDPSocket will implicitly pause the reads.
}

void TakeoverPacketHandler::setDestination(
    const folly::SocketAddress& destAddr) {
  pktForwardDestAddr_ = folly::SocketAddress(destAddr);
  packetForwardingEnabled_ = true;
}

void TakeoverPacketHandler::forwardPacketToAnotherServer(
    const folly::SocketAddress& peerAddress,
    NetworkData&& networkData) {
  const TimePoint receiveTimePoint = networkData.getReceiveTimePoint();
  BufPtr buf = std::move(networkData).moveAllData();

  // create buffer for the peerAddress address and receiveTimePoint
  // Serialize: version (4B), socket(2 + 16)B and time of ack (8B)
  auto bufSize = sizeof(TakeoverProtocolVersion) + sizeof(uint16_t) +
      peerAddress.getActualSize() + sizeof(uint64_t);
  BufPtr writeBuffer = BufHelpers::create(bufSize);
  BufWriter bufWriter(writeBuffer->writableData(), bufSize);
  bufWriter.writeBE<uint32_t>(folly::to_underlying(takeoverProtocol_));
  sockaddr_storage addrStorage;
  uint16_t socklen = peerAddress.getAddress(&addrStorage);
  bufWriter.writeBE<uint16_t>(socklen);
  bufWriter.push((uint8_t*)&addrStorage, socklen);
  uint64_t tick = receiveTimePoint.time_since_epoch().count();
  bufWriter.writeBE<uint64_t>(tick);
  writeBuffer->append(bufSize);

  writeBuffer->appendToChain(std::move(buf));
  forwardPacket(std::move(writeBuffer));
}

TakeoverPacketHandler::TakeoverPacketHandler(QuicServerWorker* worker)
    : worker_(worker) {}

TakeoverPacketHandler::~TakeoverPacketHandler() {
  stop();
}

void TakeoverPacketHandler::setSocketFactory(QuicUDPSocketFactory* factory) {
  socketFactory_ = factory;
}

void TakeoverPacketHandler::forwardPacket(BufPtr writeBuffer) {
  if (!pktForwardingSocket_) {
    MVCHECK(socketFactory_);
    pktForwardingSocket_ = socketFactory_->make(worker_->getEventBase(), -1);
    folly::SocketAddress localAddress;
    localAddress.setFromHostPort("::1", 0);
    pktForwardingSocket_->bind(localAddress);
  }
  pktForwardingSocket_->write(pktForwardDestAddr_, std::move(writeBuffer));
}

std::unique_ptr<FollyAsyncUDPSocketAlias> TakeoverPacketHandler::makeSocket(
    folly::EventBase* evb) {
  return std::make_unique<FollyAsyncUDPSocketAlias>(evb);
}

void TakeoverPacketHandler::processForwardedPacket(
    const folly::SocketAddress& /*client*/,
    BufPtr data) {
  // The 'client' here is the local server that is taking over the port
  // First we decode the actual client and time from the packet
  // and send it to the worker_ to handle it properly
  MVCHECK(!data->isChained());
  ContiguousReadCursor cursor(data->data(), data->length());
  uint32_t protocol = 0;
  if (!cursor.tryReadBE(protocol)) {
    MVVLOG(4) << "Cannot read takeover protocol version. Dropping.";
    return;
  }
  if (protocol != static_cast<uint32_t>(takeoverProtocol_)) {
    MVVLOG(4) << "Unexpected takeover protocol version=" << protocol;
    return;
  }
  uint16_t addrLen = 0;
  if (!cursor.tryReadBE(addrLen)) {
    MVVLOG(4) << "Malformed packet received. Dropping.";
    return;
  }
  if (addrLen > kMaxBufSizeForTakeoverEncapsulation) {
    MVVLOG(2) << "Buffer size for takeover encapsulation: " << addrLen
              << " exceeds the max limit: "
              << kMaxBufSizeForTakeoverEncapsulation;
    return;
  }
  struct sockaddr* sockaddr = nullptr;
  auto addrData = cursor.peekBytes();
  if (addrData.size() >= addrLen) {
    sockaddr = (struct sockaddr*)addrData.data();
    cursor.skip(addrLen);
  } else {
    MVVLOG(4) << "Cannot extract peerAddress address of length=" << addrLen
              << " from the forwarded packet. Dropping the packet.";
    return;
  }
  folly::SocketAddress peerAddress;
  try {
    MVCHECK_NOTNULL(sockaddr);
    peerAddress.setFromSockaddr(sockaddr, addrLen);
  } catch (const std::exception& ex) {
    MVLOG_ERROR << "Invalid client address encoded: addrlen=" << addrLen
                << " ex=" << ex.what();
    return;
  }
  // decode the packetReceiveTime
  uint64_t pktReceiveEpoch = 0;
  if (!cursor.tryReadBE(pktReceiveEpoch)) {
    MVVLOG(4)
        << "Malformed packet received without packetReceiveTime. Dropping.";
    return;
  }
  Clock::duration tick(pktReceiveEpoch);
  TimePoint clientPacketReceiveTime(tick);
  data->trimStart(cursor.getCurrentPosition());
  QUIC_STATS(worker_->getStatsCallback(), onForwardedPacketProcessed);
  ReceivedUdpPacket packet(std::move(data));
  packet.timings.receiveTimePoint = clientPacketReceiveTime;
  worker_->handleNetworkData(
      peerAddress,
      packet,
      /* isForwardedData */ true);
}

void TakeoverPacketHandler::stop() {
  packetForwardingEnabled_ = false;
  pktForwardingSocket_.reset();
}
} // namespace quic
