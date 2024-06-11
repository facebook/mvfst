/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/events/QuicEventBase.h>

#include <folly/io/SocketOptionMap.h>
#include <folly/net/NetOps.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>

#include <chrono>
#include <memory>

namespace folly {
class EventBase;
class SocketAddress;
} // namespace folly

namespace quic {
struct TransportSettings;

void happyEyeballsAddPeerAddress(
    QuicClientConnectionState& connection,
    const folly::SocketAddress& peerAddress);

void happyEyeballsAddSocket(
    QuicClientConnectionState& connection,
    std::unique_ptr<QuicAsyncUDPSocket> socket);

void startHappyEyeballs(
    QuicClientConnectionState& connection,
    QuicEventBase* evb,
    sa_family_t cachedFamily,
    QuicTimerCallback& connAttemptDelayTimeout,
    std::chrono::milliseconds connAttemptDelay,
    QuicAsyncUDPSocket::ErrMessageCallback* errMsgCallback,
    QuicAsyncUDPSocket::ReadCallback* readCallback,
    const folly::SocketOptionMap& options);

void happyEyeballsSetUpSocket(
    QuicAsyncUDPSocket& socket,
    Optional<folly::SocketAddress> localAddress,
    const folly::SocketAddress& peerAddress,
    const TransportSettings& transportSettings,
    const uint8_t socketTos,
    QuicAsyncUDPSocket::ErrMessageCallback* errMsgCallback,
    QuicAsyncUDPSocket::ReadCallback* readCallback,
    const folly::SocketOptionMap& options);

void happyEyeballsStartSecondSocket(
    QuicClientConnectionState::HappyEyeballsState& happyEyeballsState);

void happyEyeballsOnDataReceived(
    QuicClientConnectionState& connection,
    QuicTimerCallback& connAttemptDelayTimeout,
    std::unique_ptr<QuicAsyncUDPSocket>& socket,
    const folly::SocketAddress& peerAddress);
} // namespace quic
