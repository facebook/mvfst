/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/QuicEventBase.h>

#include <folly/io/SocketOptionMap.h>
#include <folly/net/NetOps.h>
#include <quic/common/QuicAsyncUDPSocketWrapper.h>

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
    std::unique_ptr<QuicAsyncUDPSocketWrapper> socket);

void startHappyEyeballs(
    QuicClientConnectionState& connection,
    QuicEventBase* evb,
    sa_family_t cachedFamily,
    QuicTimerCallback& connAttemptDelayTimeout,
    std::chrono::milliseconds connAttemptDelay,
    QuicAsyncUDPSocketWrapper::ErrMessageCallback* errMsgCallback,
    QuicAsyncUDPSocketWrapper::ReadCallback* readCallback,
    const folly::SocketOptionMap& options);

void happyEyeballsSetUpSocket(
    QuicAsyncUDPSocketWrapper& socket,
    folly::Optional<folly::SocketAddress> localAddress,
    const folly::SocketAddress& peerAddress,
    const TransportSettings& transportSettings,
    QuicAsyncUDPSocketWrapper::ErrMessageCallback* errMsgCallback,
    QuicAsyncUDPSocketWrapper::ReadCallback* readCallback,
    const folly::SocketOptionMap& options);

void happyEyeballsStartSecondSocket(
    QuicClientConnectionState::HappyEyeballsState& happyEyeballsState);

void happyEyeballsOnDataReceived(
    QuicClientConnectionState& connection,
    QuicTimerCallback& connAttemptDelayTimeout,
    std::unique_ptr<QuicAsyncUDPSocketWrapper>& socket,
    const folly::SocketAddress& peerAddress);
} // namespace quic
