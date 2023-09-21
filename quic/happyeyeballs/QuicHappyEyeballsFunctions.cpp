/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>

#include <quic/common/SocketUtil.h>

#include <quic/state/StateData.h>

#include <folly/SocketAddress.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/net/NetOps.h>
#include <folly/portability/Sockets.h>
#include <quic/common/QuicAsyncUDPSocketWrapper.h>

#include <chrono>
#include <memory>

// This hook is invoked by mvfst for every UDP socket it creates.
#if FOLLY_HAVE_WEAK_SYMBOLS
extern "C" FOLLY_ATTR_WEAK void mvfst_hook_on_socket_create(int fd);
#else
static void (*mvfst_hook_on_socket_create)(int fd) = nullptr;
#endif

namespace fsp = folly::portability::sockets;

namespace quic {

void happyEyeballsAddPeerAddress(
    QuicClientConnectionState& connection,
    const folly::SocketAddress& peerAddress) {
  // TODO: Do not wait for both IPv4 and IPv6 addresses to return before
  // attempting connection establishment. -- RFC8305
  // RFC8305 HappyEyeballs version 2 implementation will be more complex:
  // HappyEyeballs cache should be checked before DNS queries while the connect
  // part in built within QUIC, which will make HappyEyeballs module separated
  // in two code bases.
  // Current implementation (version 1) will assume all addresses are supplied
  // before start(), that is, addNewPeerAddress cannot be called after start()
  // is called.

  // TODO: Support multiple addresses

  if (peerAddress.getFamily() == AF_INET) {
    DCHECK(!connection.happyEyeballsState.v4PeerAddress.isInitialized());
    connection.happyEyeballsState.v4PeerAddress = peerAddress;
  } else {
    DCHECK(!connection.happyEyeballsState.v6PeerAddress.isInitialized());
    connection.happyEyeballsState.v6PeerAddress = peerAddress;
  }
}

void happyEyeballsAddSocket(
    QuicClientConnectionState& connection,
    std::unique_ptr<QuicAsyncUDPSocketWrapper> socket) {
  connection.happyEyeballsState.secondSocket = std::move(socket);
}

void startHappyEyeballs(
    QuicClientConnectionState& connection,
    QuicEventBase* evb,
    sa_family_t cachedFamily,
    QuicTimerCallback& connAttemptDelayTimeout,
    std::chrono::milliseconds connAttempDelay,
    QuicAsyncUDPSocketWrapper::ErrMessageCallback* errMsgCallback,
    QuicAsyncUDPSocketWrapper::ReadCallback* readCallback,
    const folly::SocketOptionMap& options) {
  if (connection.happyEyeballsState.v6PeerAddress.isInitialized() &&
      connection.happyEyeballsState.v4PeerAddress.isInitialized()) {
    // A second socket has to be added before happy eyeballs starts
    DCHECK(connection.happyEyeballsState.secondSocket);

    if (cachedFamily == AF_INET) {
      connection.originalPeerAddress =
          connection.happyEyeballsState.v4PeerAddress;
      connection.peerAddress = connection.happyEyeballsState.v4PeerAddress;
      connection.happyEyeballsState.secondPeerAddress =
          connection.happyEyeballsState.v6PeerAddress;
    } else {
      connection.originalPeerAddress =
          connection.happyEyeballsState.v6PeerAddress;
      connection.peerAddress = connection.happyEyeballsState.v6PeerAddress;
      connection.happyEyeballsState.secondPeerAddress =
          connection.happyEyeballsState.v4PeerAddress;
    }

    connection.happyEyeballsState.connAttemptDelayTimeout =
        &connAttemptDelayTimeout;

    evb->scheduleTimeout(&connAttemptDelayTimeout, connAttempDelay);

    try {
      happyEyeballsSetUpSocket(
          *connection.happyEyeballsState.secondSocket,
          connection.localAddress,
          connection.happyEyeballsState.secondPeerAddress,
          connection.transportSettings,
          errMsgCallback,
          readCallback,
          options);
    } catch (const std::exception&) {
      // If second socket bind throws exception, give it up
      connAttemptDelayTimeout.cancelTimeout();
      connection.happyEyeballsState.finished = true;
    }
  } else if (connection.happyEyeballsState.v6PeerAddress.isInitialized()) {
    connection.originalPeerAddress =
        connection.happyEyeballsState.v6PeerAddress;
    connection.peerAddress = connection.happyEyeballsState.v6PeerAddress;
    connection.happyEyeballsState.finished = true;
  } else if (connection.happyEyeballsState.v4PeerAddress.isInitialized()) {
    connection.originalPeerAddress =
        connection.happyEyeballsState.v4PeerAddress;
    connection.peerAddress = connection.happyEyeballsState.v4PeerAddress;
    connection.happyEyeballsState.finished = true;
  }
}

void happyEyeballsSetUpSocket(
    QuicAsyncUDPSocketWrapper& socket,
    folly::Optional<folly::SocketAddress> localAddress,
    const folly::SocketAddress& peerAddress,
    const TransportSettings& transportSettings,
    QuicAsyncUDPSocketWrapper::ErrMessageCallback* errMsgCallback,
    QuicAsyncUDPSocketWrapper::ReadCallback* readCallback,
    const folly::SocketOptionMap& options) {
  auto sockFamily = localAddress.value_or(peerAddress).getFamily();
  socket.setReuseAddr(false);
  auto initSockAndApplyOpts = [&]() {
    socket.init(sockFamily);
    applySocketOptions(
        socket,
        options,
        sockFamily,
        folly::SocketOptionKey::ApplyPos::PRE_BIND);
  };

  if (localAddress.has_value()) {
    initSockAndApplyOpts();
    socket.bind(*localAddress);
  }
  if (transportSettings.connectUDP) {
    initSockAndApplyOpts();
    socket.connect(peerAddress);
  }
  if (!socket.isBound()) {
    auto addr = folly::SocketAddress(
        peerAddress.getFamily() == AF_INET ? "0.0.0.0" : "::", 0);
    initSockAndApplyOpts();
    socket.bind(addr);
  }
  applySocketOptions(
      socket, options, sockFamily, folly::SocketOptionKey::ApplyPos::POST_BIND);

#ifdef SO_NOSIGPIPE
  folly::SocketOptionKey nopipeKey = {SOL_SOCKET, SO_NOSIGPIPE};
  if (!options.count(nopipeKey)) {
    socket.applyOptions(
        {{nopipeKey, 1}}, folly::SocketOptionKey::ApplyPos::POST_BIND);
  }
#endif

  if (mvfst_hook_on_socket_create) {
    mvfst_hook_on_socket_create(getSocketFd(socket));
  }

  // never fragment, always turn off PMTU
  socket.setDFAndTurnOffPMTU();

  if (transportSettings.enableSocketErrMsgCallback) {
    socket.setErrMessageCallback(errMsgCallback);
  }
  socket.resumeRead(readCallback);
}

void happyEyeballsStartSecondSocket(
    QuicClientConnectionState::HappyEyeballsState& happyEyeballsState) {
  CHECK(!happyEyeballsState.finished);

  happyEyeballsState.shouldWriteToSecondSocket = true;
}

void happyEyeballsOnDataReceived(
    QuicClientConnectionState& connection,
    QuicTimerCallback& connAttemptDelayTimeout,
    std::unique_ptr<QuicAsyncUDPSocketWrapper>& socket,
    const folly::SocketAddress& peerAddress) {
  if (connection.happyEyeballsState.finished) {
    return;
  }
  connAttemptDelayTimeout.cancelTimeout();
  connection.happyEyeballsState.finished = true;
  connection.happyEyeballsState.shouldWriteToFirstSocket = true;
  connection.happyEyeballsState.shouldWriteToSecondSocket = false;
  // If second socket won, update main socket and peerAddress
  if (connection.peerAddress.getFamily() != peerAddress.getFamily()) {
    CHECK(connection.happyEyeballsState.secondSocket);
    socket.swap(connection.happyEyeballsState.secondSocket);
    connection.originalPeerAddress = peerAddress;
    connection.peerAddress = peerAddress;
  }
  connection.happyEyeballsState.secondSocket->pauseRead();
  connection.happyEyeballsState.secondSocket->close();
  connection.happyEyeballsState.secondSocket.reset();
}

} // namespace quic
