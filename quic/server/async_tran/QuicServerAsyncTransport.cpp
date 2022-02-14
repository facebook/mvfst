/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/async_tran/QuicServerAsyncTransport.h>

#include <folly/Conv.h>

namespace quic {

void QuicServerAsyncTransport::setServerSocket(
    std::shared_ptr<quic::QuicSocket> sock) {
  setSocket(std::move(sock));
}

void QuicServerAsyncTransport::onNewBidirectionalStream(StreamId id) noexcept {
  if (id != 0) {
    CHECK(false) << "Only single stream 0 is supported";
  }
  setStreamId(id);
}
void QuicServerAsyncTransport::onNewUnidirectionalStream(
    StreamId /*id*/) noexcept {
  CHECK(false) << "Unidirectional stream not supported";
}

void QuicServerAsyncTransport::onStopSending(
    StreamId /*id*/,
    ApplicationErrorCode /*error*/) noexcept {}

void QuicServerAsyncTransport::onConnectionEnd() noexcept {
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::UNKNOWN, "Quic connection ended");
  closeNowImpl(std::move(ex));
}

void QuicServerAsyncTransport::onConnectionError(QuicError code) noexcept {
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::UNKNOWN,
      folly::to<std::string>("Quic connection error", code.message));
  closeNowImpl(std::move(ex));
}

void QuicServerAsyncTransport::onTransportReady() noexcept {}

} // namespace quic
