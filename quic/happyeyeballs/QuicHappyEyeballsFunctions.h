/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/state/StateData.h>

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
    QuicConnectionStateBase& connection,
    const folly::SocketAddress& peerAddress);

void happyEyeballsAddSocket(
    QuicConnectionStateBase& connection,
    std::unique_ptr<folly::AsyncUDPSocket> socket);

void startHappyEyeballs(
    QuicConnectionStateBase& connection,
    folly::EventBase* evb,
    sa_family_t cachedFamily,
    folly::HHWheelTimer::Callback& connAttemptDelayTimeout,
    std::chrono::milliseconds connAttemptDelay,
    folly::AsyncUDPSocket::ErrMessageCallback* errMsgCallback,
    folly::AsyncUDPSocket::ReadCallback* readCallback);

void resetHappyEyeballs(QuicConnectionStateBase& connection);

void happyEyeballsSetUpSocket(
    folly::AsyncUDPSocket& socket,
    folly::Optional<folly::SocketAddress> localAddress,
    const folly::SocketAddress& peerAddress,
    const TransportSettings& transportSettings,
    folly::AsyncUDPSocket::ErrMessageCallback* errMsgCallback,
    folly::AsyncUDPSocket::ReadCallback* readCallback);

void happyEyeballsStartSecondSocket(
    QuicConnectionStateBase::HappyEyeballsState& happyEyeballsState);

void happyEyeballsOnDataReceived(
    QuicConnectionStateBase& connection,
    folly::HHWheelTimer::Callback& connAttemptDelayTimeout,
    std::unique_ptr<folly::AsyncUDPSocket>& socket,
    const folly::SocketAddress& peerAddress);
} // namespace quic
