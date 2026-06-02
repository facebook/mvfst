/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>

namespace quic {

class QuicUDPSocketFactory {
 public:
  virtual ~QuicUDPSocketFactory() = default;

  virtual std::unique_ptr<FollyAsyncUDPSocketAlias> make(
      folly::EventBase* evb,
      int fd) = 0;

  /**
   * Create a per-connection writer that shares the listener's kernel fd
   * and (if MSG_ZEROCOPY is enabled on the listener) its per-fd ZC
   * bookkeeping. The default implementation delegates to
   * `listenerSock->createPeerOnSameFd()`, which is the
   * folly::AsyncUDPSocket factory that wires up `FDOwnership::SHARED`,
   * shared `ZeroCopyFdBookkeeping`, and `setZeroCopy(true)` in one
   * step. The alias inherits the listener's EventBase — sharing across
   * EventBases would violate the bookkeeping's thread-safety invariant.
   * Subclasses that need to construct a different concrete socket type
   * may override this; for plain shared-fd usage the default is
   * sufficient.
   */
  virtual std::unique_ptr<FollyAsyncUDPSocketAlias> makeAlias(
      FollyAsyncUDPSocketAlias* listenerSock) {
    return listenerSock->createPeerOnSameFd();
  }
};
} // namespace quic
