/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/async_tran/QuicAsyncTransportAcceptor.h>
#include <quic/server/async_tran/QuicServerAsyncTransport.h>

namespace {
using AsyncTransportHook = quic::QuicAsyncTransportAcceptor::AsyncTransportHook;
using namespace quic;

/*
 * couple of things here:
 * - unforunately we have to also no-op inherit from
 *   QuicSocket::ConnectionCallback due to callback ordering bug (T159286843)
 *
 * - above issue will cause a missed callback to
 *   ConnectionCallback::onBidirectionalStreamsAvailable &
 *   ConnectionCallback::onUnidirectionalStreamsAvailable as they're invoked
 *   prior to setting the new ConnectionCallback in ::onTransportReady
 *
 * - wait for terminal connection setup event (::onTransportReady or
 *   ::onConnectionSetupError) to create asyncWrapper
 */
class ServerTransportConnectionSetupCallback
    : public QuicSocket::ConnectionSetupCallback,
      public QuicSocket::ConnectionCallback {
 public:
  ServerTransportConnectionSetupCallback(AsyncTransportHook* hook)
      : hook_(hook) {}

  void onConnectionSetupError(QuicError /*code*/) noexcept override {
    // no longer interested in connection setup callback events
    transport_->setConnectionSetupCallback(nullptr);
    delete this;
  }

  void onTransportReady() noexcept override {
    // create wrapper to set as new ConnectionCallback
    auto asyncWrapper =
        QuicServerAsyncTransport::UniquePtr(new QuicServerAsyncTransport());
    CHECK(transport_);
    transport_->setConnectionCallback(asyncWrapper.get());
    asyncWrapper->setServerSocket(transport_);
    // no longer interested in connection setup callback events
    transport_->setConnectionSetupCallback(nullptr);
    // call hook
    (*hook_)(std::move(asyncWrapper));
    delete this;
  }

  // no-op mandatory ConnectionCallback overrides (to be removed when task is
  // fixed) which will never be executed
  void onNewBidirectionalStream(StreamId /*id*/) noexcept override {
    CHECK(false);
  }
  void onNewUnidirectionalStream(StreamId /*id*/) noexcept override {
    CHECK(false);
  }
  void onStopSending(StreamId /*id*/, ApplicationErrorCode /*error*/) noexcept
      override {
    CHECK(false);
  }
  void onConnectionEnd() noexcept override {
    CHECK(false);
  }
  void onConnectionError(QuicError /*code*/) noexcept override {
    CHECK(false);
  }

  AsyncTransportHook* hook_{nullptr};
  quic::QuicServerTransport::Ptr transport_{nullptr};
};
} // namespace

namespace quic {

QuicAsyncTransportAcceptor::QuicAsyncTransportAcceptor(
    folly::EventBase* evb,
    AsyncTransportHook asyncTransportHook)
    : asyncTransportHook_(std::move(asyncTransportHook)), evb_(evb) {}

quic::QuicServerTransport::Ptr QuicAsyncTransportAcceptor::make(
    folly::EventBase* evb,
    std::unique_ptr<QuicAsyncUDPSocketWrapper> sock,
    const folly::SocketAddress&,
    QuicVersion,
    std::shared_ptr<const fizz::server::FizzServerContext> ctx) noexcept {
  CHECK_EQ(evb, evb_);

  // wait for onTransportReady before invoking asyncTransportHook_
  auto* connSetupCallback =
      CHECK_NOTNULL(std::make_unique<ServerTransportConnectionSetupCallback>(
                        &asyncTransportHook_)
                        .release());
  // create quic socket
  auto transport = quic::QuicServerTransport::make(
      evb, std::move(sock), connSetupCallback, connSetupCallback, ctx);
  connSetupCallback->transport_ = transport;

  return transport;
}

} // namespace quic
