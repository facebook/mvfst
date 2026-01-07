/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/QuicClientTransport.h>
#include <quic/common/MvfstLogging.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>
#include <quic/loss/QuicLossFunctions.h>

namespace quic {

QuicClientTransport::~QuicClientTransport() {
  MVVLOG(10) << "Destroyed connection to server=" << conn_->peerAddress;
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

  cleanupHappyEyeballsState();
}

void QuicClientTransport::onNotifyDataAvailable(
    QuicAsyncUDPSocket& sock) noexcept {
  auto self = this->shared_from_this();
  MVCHECK(conn_, "trying to receive packets without a connection");
  auto readBufferSize = std::max(
                            conn_->transportSettings.maxRecvPacketSize,
                            uint64_t(kDefaultUDPReadBufferSize)) *
      numGROBuffers_;
  const uint16_t numPackets = conn_->transportSettings.maxRecvBatchSize;

  const size_t readAllocSize =
      conn_->transportSettings.readCoalescingSize > kDefaultUDPSendPacketLen
      ? conn_->transportSettings.readCoalescingSize
      : readBufferSize;

  auto result = [&]() -> quic::Expected<void, QuicError> {
    if (conn_->transportSettings.networkDataPerSocketRead) {
      return readWithRecvmsgSinglePacketLoop(sock, readAllocSize);
    } else if (conn_->transportSettings.shouldUseWrapperRecvmmsgForBatchRecv) {
      return readWithRecvmmsgWrapper(sock, readAllocSize, numPackets);
    } else if (conn_->transportSettings.shouldUseRecvmmsgForBatchRecv) {
      return readWithRecvmmsg(sock, readAllocSize, numPackets);
    } else {
      return readWithRecvmsg(sock, readAllocSize, numPackets);
    }
  }();
  if (!result.has_value()) {
    asyncClose(result.error());
  }
}

quic::Expected<void, QuicError> QuicClientTransport::readWithRecvmmsgWrapper(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets) {
  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;
  Optional<folly::SocketAddress> server;

  const auto result = sock.recvmmsgNetworkData(
      readBufferSize, numPackets, networkData, server, totalData);

  if (!result.has_value()) {
    return quic::make_unexpected(result.error());
  }

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
  if (result->maybeNoReadReason) {
    const auto& noReadReason = result->maybeNoReadReason.value();
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
        onReadError(
            folly::AsyncSocketException(
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
  auto localAddressRes = sock.address();
  if (FOLLY_UNLIKELY(localAddressRes.hasError())) {
    return quic::make_unexpected(localAddressRes.error());
  }

  return processPackets(
      localAddressRes.value(), std::move(networkData), server);
}

quic::Expected<void, QuicError> QuicClientTransport::readWithRecvmmsg(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets) {
  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;
  Optional<folly::SocketAddress> server;

  // TODO(bschlinker): Deprecate in favor of Wrapper::recvmmsg
  recvmmsgStorage_.resize(numPackets);
  auto recvResult = recvMmsg(
      sock, readBufferSize, numPackets, networkData, server, totalData);
  if (!recvResult.has_value()) {
    return recvResult;
  }

  auto localAddressRes = sock.address();
  if (FOLLY_UNLIKELY(localAddressRes.hasError())) {
    return quic::make_unexpected(localAddressRes.error());
  }

  return processPackets(
      localAddressRes.value(), std::move(networkData), server);
}

quic::Expected<void, QuicError> QuicClientTransport::readWithRecvmsg(
    QuicAsyncUDPSocket& sock,
    uint64_t readBufferSize,
    uint16_t numPackets) {
  NetworkData networkData;
  networkData.reserve(numPackets);
  size_t totalData = 0;
  Optional<folly::SocketAddress> server;

  // TODO(bschlinker): Deprecate in favor of Wrapper::recvmmsg
  auto recvResult =
      recvMsg(sock, readBufferSize, numPackets, networkData, server, totalData);
  if (!recvResult.has_value()) {
    return recvResult;
  }

  auto localAddressRes = sock.address();
  if (FOLLY_UNLIKELY(localAddressRes.hasError())) {
    return quic::make_unexpected(localAddressRes.error());
  }

  return processPackets(
      localAddressRes.value(), std::move(networkData), server);
}

void QuicClientTransport::setHappyEyeballsEnabled(bool happyEyeballsEnabled) {
  happyEyeballsEnabled_ = happyEyeballsEnabled;
}

void QuicClientTransport::setHappyEyeballsCachedFamily(
    sa_family_t cachedFamily) {
  happyEyeballsCachedFamily_ = cachedFamily;
}

void QuicClientTransport::addNewSocket(
    std::unique_ptr<QuicAsyncUDPSocket> socket) {
  happyEyeballsAddSocket(*clientConn_, std::move(socket));
}

void QuicClientTransport::
    happyEyeballsConnAttemptDelayTimeoutExpired() noexcept {
  // Declare 0-RTT data as lost so that they will be retransmitted over the
  // second socket.
  happyEyeballsStartSecondSocket(clientConn_->happyEyeballsState);
  // If this gets called from the write path then we haven't added the packets
  // to the outstanding packet list yet.
  runOnEvbAsync([&](auto) {
    auto result = markZeroRttPacketsLost(*conn_, markPacketLoss);
    LOG_IF(ERROR, !result.has_value())
        << "Failed to mark 0-RTT packets as lost.";
  });
}

void QuicClientTransport::cleanupHappyEyeballsState() {
  if (clientConn_->happyEyeballsState.secondSocket) {
    auto sock = std::move(clientConn_->happyEyeballsState.secondSocket);
    sock->pauseRead();
    (void)sock->close();
  }
}

void QuicClientTransport::startHappyEyeballsIfEnabled() {
  if (happyEyeballsEnabled_) {
    // TODO Supply v4 delay amount from somewhere when we want to tune this
    startHappyEyeballs(
        *clientConn_,
        evb_.get(),
        happyEyeballsCachedFamily_,
        happyEyeballsConnAttemptDelayTimeout_,
        happyEyeballsCachedFamily_ == AF_UNSPEC
            ? kHappyEyeballsV4Delay
            : kHappyEyeballsConnAttemptDelayWithCache,
        this,
        this,
        socketOptions_);
  }
}

void QuicClientTransport::happyEyeballsOnDataReceivedIfEnabled(
    const folly::SocketAddress& peerAddress) {
  if (happyEyeballsEnabled_) {
    MVCHECK(socket_);
    happyEyeballsOnDataReceived(
        *clientConn_,
        happyEyeballsConnAttemptDelayTimeout_,
        socket_,
        peerAddress);
  }
}

void QuicClientTransport::cancelHappyEyeballsConnAttemptDelayTimeout() {
  cancelTimeout(&happyEyeballsConnAttemptDelayTimeout_);
}

bool QuicClientTransport::happyEyeballsAddPeerAddressIfEnabled(
    const folly::SocketAddress& peerAddress) {
  if (happyEyeballsEnabled_) {
    conn_->udpSendPacketLen = std::min(
        conn_->udpSendPacketLen,
        (peerAddress.getFamily() == AF_INET6 ? kDefaultV6UDPSendPacketLen
                                             : kDefaultV4UDPSendPacketLen));
    happyEyeballsAddPeerAddress(*clientConn_, peerAddress);
    return true;
  }
  return false;
}

} // namespace quic
