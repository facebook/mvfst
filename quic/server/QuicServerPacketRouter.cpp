/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/io/Cursor.h>
#include <folly/system/ThreadId.h>
#include <quic/QuicConstants.h>

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
    std::unique_ptr<folly::AsyncUDPSocket> socket)
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
  CHECK(socket_);
  // first reset existing socket if any
  socket_->bind(addr);
  socket_->resumeRead(this);
}

void TakeoverHandlerCallback::rebind(
    std::unique_ptr<folly::AsyncUDPSocket> socket,
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
  CHECK(socket_);
  return socket_->address();
}

int TakeoverHandlerCallback::getSocketFD() {
  CHECK(socket_);
  return socket_->getNetworkSocket().toFd();
}

void TakeoverHandlerCallback::getReadBuffer(void** buf, size_t* len) noexcept {
  readBuffer_ = folly::IOBuf::create(
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
  VLOG(10) << "Worker=" << this << " Received (takeover) data on thread="
           << folly::getCurrentThreadID()
           << ", workerId=" << static_cast<uint32_t>(worker_->getWorkerId())
           << ", processId=" << static_cast<uint32_t>(worker_->getProcessId());
  // Move readBuffer_ first so that we can get rid
  // of it immediately so that if we return early,
  // we've flushed it.
  Buf data = std::move(readBuffer_);
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
  VLOG(4) << "Error on TakeoverHandlerCallback " << ex.what();
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
  //  Doing nothing since the ASyncUDPSocket will implictly pause the reads.
}

void TakeoverPacketHandler::setDestination(
    const folly::SocketAddress& destAddr) {
  pktForwardDestAddr_ = folly::SocketAddress(destAddr);
  packetForwardingEnabled_ = true;
}

void TakeoverPacketHandler::forwardPacketToAnotherServer(
    const folly::SocketAddress& peerAddress,
    Buf data,
    const TimePoint& packetReceiveTime) {
  // create buffer for the peerAddress address and clientPacketReceiveTime
  // Serialize: version (4B), socket(2 + 16)B and time of ack (8B)
  auto bufSize = sizeof(TakeoverProtocolVersion) + sizeof(uint16_t) +
      peerAddress.getActualSize() + sizeof(uint64_t);
  Buf writeBuffer = folly::IOBuf::create(bufSize);
  folly::io::Appender appender(writeBuffer.get(), bufSize);
  appender.writeBE<uint32_t>(static_cast<uint32_t>(takeoverProtocol_));
  sockaddr_storage addrStorage;
  uint16_t socklen = peerAddress.getAddress(&addrStorage);
  appender.writeBE<uint16_t>(socklen);
  appender.push((uint8_t*)&addrStorage, socklen);
  uint64_t tick = packetReceiveTime.time_since_epoch().count();
  appender.writeBE<uint64_t>(tick);
  writeBuffer->prependChain(std::move(data));
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

void TakeoverPacketHandler::forwardPacket(Buf writeBuffer) {
  if (!pktForwardingSocket_) {
    CHECK(socketFactory_);
    pktForwardingSocket_ = socketFactory_->make(worker_->getEventBase(), -1);
    folly::SocketAddress localAddress;
    localAddress.setFromHostPort("::1", 0);
    pktForwardingSocket_->bind(localAddress);
  }
  pktForwardingSocket_->write(pktForwardDestAddr_, std::move(writeBuffer));
}

std::unique_ptr<folly::AsyncUDPSocket> TakeoverPacketHandler::makeSocket(
    folly::EventBase* evb) {
  auto sock = std::make_unique<folly::AsyncUDPSocket>(evb);
  return sock;
}

void TakeoverPacketHandler::processForwardedPacket(
    const folly::SocketAddress& /*client*/,
    Buf data) {
  // The 'client' here is the local server that is taking over the port
  // First we decode the actual client and time from the packet
  // and send it to the worker_ to handle it properly

  folly::io::Cursor cursor(data.get());
  if (!cursor.canAdvance(sizeof(TakeoverProtocolVersion))) {
    VLOG(4) << "Cannot read takeover protocol version. Dropping.";
    return;
  }
  uint32_t protocol =
      cursor.readBE<std::underlying_type<TakeoverProtocolVersion>::type>();
  if (protocol != static_cast<uint32_t>(takeoverProtocol_)) {
    VLOG(4) << "Unexpected takeover protocol version=" << protocol;
    return;
  }
  if (!cursor.canAdvance(sizeof(uint16_t))) {
    VLOG(4) << "Malformed packet received. Dropping.";
    return;
  }
  uint16_t addrLen = cursor.readBE<uint16_t>();
  if (addrLen > kMaxBufSizeForTakeoverEncapsulation) {
    VLOG(2) << "Buffer size for takeover encapsulation: " << addrLen
            << " exceeds the max limit: "
            << kMaxBufSizeForTakeoverEncapsulation;
    return;
  }
  struct sockaddr* sockaddr = nullptr;
  uint8_t sockaddrBuf[kMaxBufSizeForTakeoverEncapsulation];
  std::pair<const uint8_t*, size_t> addrData = cursor.peek();
  if (addrData.second >= addrLen) {
    // the address is contiguous in the queue
    sockaddr = (struct sockaddr*)addrData.first;
    cursor.skip(addrLen);
  } else {
    // the address is not contiguous, copy it to a local buffer
    if (!cursor.canAdvance(addrLen)) {
      VLOG(4) << "Cannot extract peerAddress address of length=" << addrLen
              << " from the forwarded packet. Dropping the packet.";
      return;
    }
    cursor.pull(sockaddrBuf, addrLen);
    sockaddr = (struct sockaddr*)sockaddrBuf;
  }
  folly::SocketAddress peerAddress;
  try {
    CHECK_NOTNULL(sockaddr);
    peerAddress.setFromSockaddr(sockaddr, addrLen);
  } catch (const std::exception& ex) {
    LOG(ERROR) << "Invalid client address encoded: addrlen=" << addrLen
               << " ex=" << ex.what();
    return;
  }
  // decode the packetReceiveTime
  if (!cursor.canAdvance(sizeof(uint64_t))) {
    VLOG(4) << "Malformed packet received without packetReceiveTime. Dropping.";
    return;
  }
  auto pktReceiveEpoch = cursor.readBE<uint64_t>();
  Clock::duration tick(pktReceiveEpoch);
  TimePoint clientPacketReceiveTime(tick);
  data->trimStart(cursor - data.get());
  QUIC_STATS(worker_->getStatsCallback(), onForwardedPacketProcessed);
  worker_->handleNetworkData(
      peerAddress,
      std::move(data),
      clientPacketReceiveTime,
      /* isForwardedData */ true);
}

void TakeoverPacketHandler::stop() {
  packetForwardingEnabled_ = false;
  pktForwardingSocket_.reset();
}
} // namespace quic
