/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocket.h>
#include <quic/server/QuicServerTransport.h>

namespace quic {

class QuicHandshakeSocketHolder
    : public quic::QuicSocket::ConnectionSetupCallback {
 public:
  class Callback {
   public:
    virtual ~Callback() = default;
    virtual void onQuicTransportReady(
        std::shared_ptr<quic::QuicSocket> quicSocket) = 0;
    virtual void onConnectionSetupError(
        std::shared_ptr<quic::QuicSocket> quicSocket,
        quic::QuicError code) = 0;
  };

  static QuicServerTransport::Ptr makeServerTransport(
      folly::EventBase* evb,
      std::unique_ptr<quic::QuicAsyncUDPSocketWrapper> socket,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx,
      Callback* callback) {
    auto acceptCb = std::make_unique<QuicHandshakeSocketHolder>(callback);
    auto transport = quic::QuicServerTransport::make(
        evb, std::move(socket), acceptCb.get(), nullptr, std::move(ctx));
    acceptCb->quicSocket_ = transport;
    (void)acceptCb.release();
    return transport;
  }

  // Please use static factory function
  explicit QuicHandshakeSocketHolder(Callback* callback)
      : callback_(callback) {}

 private:
  void onConnectionSetupError(quic::QuicError code) noexcept override {
    quicSocket_->setConnectionSetupCallback(nullptr);
    if (callback_) {
      callback_->onConnectionSetupError(std::move(quicSocket_), code);
    }
    delete this;
  }
  void onReplaySafe() noexcept override {
    // Unused for server
  }
  void onTransportReady() noexcept override {
    quicSocket_->setConnectionSetupCallback(nullptr);
    if (callback_) {
      // The callback needs to set a new connection callback on quicSocket,
      // otherwise it will have a null pointer.
      callback_->onQuicTransportReady(std::move(quicSocket_));
    }
    delete this;
  }

  Callback* callback_{nullptr};
  std::shared_ptr<quic::QuicSocket> quicSocket_;
};

} // namespace quic
