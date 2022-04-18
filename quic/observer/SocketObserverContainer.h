/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/ObserverContainer.h>
#include <quic/observer/SocketObserverInterface.h>

namespace quic {
class QuicSocket;

using SocketObserverContainerBaseT = folly::ObserverContainer<
    SocketObserverInterfaceTransitional,
    QuicSocket,
    folly::ObserverContainerBasePolicyDefault<
        SocketObserverInterfaceTransitional::Events /* EventEnum */,
        32 /* BitsetSize (max number of interface events) */>>;

class SocketObserverContainer : public SocketObserverContainerBaseT {
  using SocketObserverContainerBaseT::SocketObserverContainerBaseT;
};

} // namespace quic
