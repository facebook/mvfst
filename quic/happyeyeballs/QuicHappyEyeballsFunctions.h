/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/client/state/ClientStateMachine.h>

#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/net/NetOps.h>

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
    std::unique_ptr<folly::AsyncUDPSocket> socket);

void startHappyEyeballs(
    QuicClientConnectionState& connection,
    folly::EventBase* evb,
    sa_family_t cachedFamily,
    folly::HHWheelTimer::Callback& connAttemptDelayTimeout,
    std::chrono::milliseconds connAttemptDelay,
    folly::AsyncUDPSocket::ErrMessageCallback* errMsgCallback,
    folly::AsyncUDPSocket::ReadCallback* readCallback,
    const folly::SocketOptionMap& options);

void happyEyeballsSetUpSocket(
    folly::AsyncUDPSocket& socket,
    folly::Optional<folly::SocketAddress> localAddress,
    const folly::SocketAddress& peerAddress,
    const TransportSettings& transportSettings,
    folly::AsyncUDPSocket::ErrMessageCallback* errMsgCallback,
    folly::AsyncUDPSocket::ReadCallback* readCallback,
    const folly::SocketOptionMap& options);

void happyEyeballsStartSecondSocket(
    QuicClientConnectionState::HappyEyeballsState& happyEyeballsState);

void happyEyeballsOnDataReceived(
    QuicClientConnectionState& connection,
    folly::HHWheelTimer::Callback& connAttemptDelayTimeout,
    std::unique_ptr<folly::AsyncUDPSocket>& socket,
    const folly::SocketAddress& peerAddress);
} // namespace quic
