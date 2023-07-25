/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/QuicClientAsyncTransport.h>

#include <folly/Conv.h>
#include <folly/experimental/symbolizer/Symbolizer.h>

namespace quic {

QuicClientAsyncTransport::QuicClientAsyncTransport(
    const std::shared_ptr<quic::QuicClientTransport>& clientSock) {
  setSocket(clientSock);
  clientSock->start(this, this);
}

QuicClientAsyncTransport::~QuicClientAsyncTransport() {
  if (sock_) {
    sock_->setConnectionCallback(nullptr);
    sock_->setConnectionSetupCallback(nullptr);
  }
}

void QuicClientAsyncTransport::onNewBidirectionalStream(
    StreamId /*id*/) noexcept {
  CHECK(false);
}
void QuicClientAsyncTransport::onNewUnidirectionalStream(
    StreamId /*id*/) noexcept {
  CHECK(false);
}

void QuicClientAsyncTransport::onStopSending(
    StreamId /*id*/,
    ApplicationErrorCode /*error*/) noexcept {}

void QuicClientAsyncTransport::onConnectionEnd() noexcept {
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::UNKNOWN, "Quic connection ended");
  // TODO: closeNow inside this callback may actually trigger graceful close
  closeNowImpl(std::move(ex));
}

void QuicClientAsyncTransport::onConnectionError(QuicError error) noexcept {
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::UNKNOWN,
      folly::to<std::string>("Quic connection error", error.message));
  // TODO: closeNow inside this callback may actually trigger graceful close
  closeNowImpl(std::move(ex));
}

void QuicClientAsyncTransport::onTransportReady() noexcept {
  auto streamId = sock_->createBidirectionalStream();
  if (!streamId) {
    folly::AsyncSocketException ex(
        folly::AsyncSocketException::UNKNOWN, "Quic failed to create stream");
    closeNowImpl(std::move(ex));
  }
  setStreamId(streamId.value());
}

} // namespace quic
