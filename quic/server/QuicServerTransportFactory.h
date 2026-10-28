/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/io/async/EventBase.h>
#include <quic/server/QuicServerTransport.h>

namespace quic {

class QuicServerTransportFactory {
 public:
  virtual ~QuicServerTransportFactory() = default;

  // Returns an unaccepted transport (or nullptr to reject the connection).
  // The factory owns TLS selection and application transport policy: install
  // them on the transport before returning. Must not call accept() or
  // deliver packets. A factory attached to several workers must tolerate
  // concurrent make() calls.
  virtual QuicServerTransport::Ptr make(
      folly::EventBase* evb,
      std::unique_ptr<FollyAsyncUDPSocketAlias> socket,
      const quic::SocketAddress& addr,
      QuicVersion quicVersion) noexcept = 0;
};
} // namespace quic
