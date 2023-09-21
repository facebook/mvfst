/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/QuicEventBase.h>

#ifdef MVFST_USE_LIBEV
#include <quic/common/QuicAsyncUDPSocketImpl.h>
#else
#include <folly/io/async/AsyncUDPSocket.h>
#endif

namespace quic {

#ifdef MVFST_USE_LIBEV
using QuicAsyncUDPSocketType = QuicAsyncUDPSocketImpl;
#else
using QuicAsyncUDPSocketType = folly::AsyncUDPSocket;
using NetworkFdType = folly::NetworkSocket;
#endif

class QuicAsyncUDPSocketWrapper : public QuicAsyncUDPSocketType {
 public:
  using QuicAsyncUDPSocketType::QuicAsyncUDPSocketType;
  ~QuicAsyncUDPSocketWrapper() override = default;

  class ReadCallback : public QuicAsyncUDPSocketType::ReadCallback {
   public:
    ~ReadCallback() override = default;

    virtual void onNotifyDataAvailable(
        QuicAsyncUDPSocketWrapper& /* sock */) noexcept {}

   private:
    void onNotifyDataAvailable(QuicAsyncUDPSocketType& sock) noexcept final {
      onNotifyDataAvailable(static_cast<QuicAsyncUDPSocketWrapper&>(sock));
    }
  };

  using ErrMessageCallback = QuicAsyncUDPSocketType::ErrMessageCallback;

 private:
};

class QuicAsyncUDPSocketWrapperImpl : public QuicAsyncUDPSocketWrapper {
 public:
  using QuicAsyncUDPSocketWrapper::QuicAsyncUDPSocketWrapper;
  ~QuicAsyncUDPSocketWrapperImpl() override = default;
};

int getSocketFd(const QuicAsyncUDPSocketWrapper& s);
NetworkFdType toNetworkFdType(int fd);

} // namespace quic
