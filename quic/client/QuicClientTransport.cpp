/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/QuicClientTransport.h>

namespace quic {

QuicClientTransport::~QuicClientTransport() {
  VLOG(10) << "Destroyed connection to server=" << conn_->peerAddress;
  // The caller probably doesn't need the conn callback after destroying the
  // transport.
  resetConnectionCallbacks();
  // Close without draining.
  closeImpl(
      QuicError(
          QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
          std::string("Closing from client destructor")),
      false /* drainConnection */);
  // closeImpl may have been called earlier with drain = true, so force close.
  closeUdpSocket();

  if (clientConn_->happyEyeballsState.secondSocket) {
    auto sock = std::move(clientConn_->happyEyeballsState.secondSocket);
    sock->pauseRead();
    sock->close();
  }
}

void QuicClientTransport::onNotifyDataAvailable(
    QuicAsyncUDPSocket& sock) noexcept {
  auto self = this->shared_from_this();
  CHECK(conn_) << "trying to receive packets without a connection";
  auto readBufferSize =
      conn_->transportSettings.maxRecvPacketSize * numGROBuffers_;
  const uint16_t numPackets = conn_->transportSettings.maxRecvBatchSize;

  const size_t readAllocSize =
      conn_->transportSettings.readCoalescingSize > kDefaultUDPSendPacketLen
      ? conn_->transportSettings.readCoalescingSize
      : readBufferSize;

  if (conn_->transportSettings.networkDataPerSocketRead) {
    readWithRecvmsgSinglePacketLoop(sock, readAllocSize);
  } else if (conn_->transportSettings.shouldUseWrapperRecvmmsgForBatchRecv) {
    readWithRecvmmsgWrapper(sock, readAllocSize, numPackets);
  } else if (conn_->transportSettings.shouldUseRecvmmsgForBatchRecv) {
    readWithRecvmmsg(sock, readAllocSize, numPackets);
  } else if (conn_->transportSettings.shouldUseRecvfromForBatchRecv) {
    readWithRecvfrom(sock, readAllocSize, numPackets);
  } else {
    readWithRecvmsg(sock, readAllocSize, numPackets);
  }
}

void QuicClientTransport::readWithRecvmmsgWrapper(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets) {
  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;
  Optional<folly::SocketAddress> server;

  const auto result = sock.recvmmsgNetworkData(
      readBufferSize, numPackets, networkData, server, totalData);

  // track the received packets
  for (const auto& packet : networkData.getPackets()) {
    if (packet.buf.empty()) {
      continue;
    }
    auto len = packet.buf.chainLength();
    maybeQlogDatagram(len);
  }
  trackDatagramsReceived(
      networkData.getPackets().size(), networkData.getTotalData());

  // Propagate errors
  // TODO(bschlinker): Investigate generalization of loopDetectorCallback
  // TODO(bschlinker): Consider merging this into ReadCallback
  if (result.maybeNoReadReason) {
    const auto& noReadReason = result.maybeNoReadReason.value();
    switch (noReadReason) {
      case NoReadReason::RETRIABLE_ERROR:
        if (conn_->loopDetectorCallback) {
          conn_->readDebugState.noReadReason = NoReadReason::RETRIABLE_ERROR;
        }
        break;
      case NoReadReason::NONRETRIABLE_ERROR:
        // If we got a non-retriable error, we might have received
        // a packet that we could process, however let's just quit early.
        sock.pauseRead();
        if (conn_->loopDetectorCallback) {
          conn_->readDebugState.noReadReason = NoReadReason::NONRETRIABLE_ERROR;
        }
        onReadError(folly::AsyncSocketException(
            folly::AsyncSocketException::INTERNAL_ERROR,
            "::recvmmsg() failed",
            errno));
        break;
      case NoReadReason::READ_OK:
      case NoReadReason::EMPTY_DATA:
      case NoReadReason::TRUNCATED:
      case NoReadReason::STALE_DATA:
        break;
    }
  }
  processPackets(std::move(networkData), server);
}

void QuicClientTransport::readWithRecvmmsg(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets) {
  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;
  Optional<folly::SocketAddress> server;

  // TODO(bschlinker): Deprecate in favor of Wrapper::recvmmsg
  recvmmsgStorage_.resize(numPackets);
  recvMmsg(sock, readBufferSize, numPackets, networkData, server, totalData);

  processPackets(std::move(networkData), server);
}

void QuicClientTransport::readWithRecvfrom(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets) {
  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;
  Optional<folly::SocketAddress> server;
  recvFrom(sock, readBufferSize, numPackets, networkData, server, totalData);
  processPackets(std::move(networkData), server);
}

void QuicClientTransport::readWithRecvmsg(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets) {
  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;
  Optional<folly::SocketAddress> server;

  // TODO(bschlinker): Deprecate in favor of Wrapper::recvmmsg
  recvMsg(sock, readBufferSize, numPackets, networkData, server, totalData);

  processPackets(std::move(networkData), server);
}

} // namespace quic
