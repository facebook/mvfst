/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicTransportBaseLite.h>
#include <quic/state/QuicStreamFunctions.h>

namespace {
constexpr auto APP_NO_ERROR = quic::GenericApplicationErrorCode::NO_ERROR;
} // namespace

namespace quic {

bool QuicTransportBaseLite::good() const {
  return closeState_ == CloseState::OPEN && hasWriteCipher() && !error();
}

bool QuicTransportBaseLite::error() const {
  return conn_->localConnectionError.has_value();
}

void QuicTransportBaseLite::setConnectionSetupCallback(
    folly::MaybeManagedPtr<ConnectionSetupCallback> callback) {
  connSetupCallback_ = callback;
}

void QuicTransportBaseLite::setConnectionCallback(
    folly::MaybeManagedPtr<ConnectionCallback> callback) {
  connCallback_ = callback;
}

void QuicTransportBaseLite::processConnectionSetupCallbacks(
    QuicError&& cancelCode) {
  // connSetupCallback_ could be null if start() was never
  // invoked and the transport was destroyed or if the app initiated close.
  if (connSetupCallback_) {
    connSetupCallback_->onConnectionSetupError(std::move(cancelCode));
  }
}

void QuicTransportBaseLite::processConnectionCallbacks(QuicError&& cancelCode) {
  // connCallback_ could be null if start() was never
  // invoked and the transport was destroyed or if the app initiated close.
  if (!connCallback_) {
    return;
  }

  if (useConnectionEndWithErrorCallback_) {
    connCallback_->onConnectionEnd(cancelCode);
    return;
  }

  if (bool noError = processCancelCode(cancelCode)) {
    connCallback_->onConnectionEnd();
  } else {
    connCallback_->onConnectionError(std::move(cancelCode));
  }
}

folly::Expected<QuicSocketLite::StreamTransportInfo, LocalErrorCode>
QuicTransportBaseLite::getStreamTransportInfo(StreamId id) const {
  if (!conn_->streamManager->streamExists(id)) {
    return folly::makeUnexpected(LocalErrorCode::STREAM_NOT_EXISTS);
  }
  auto stream = CHECK_NOTNULL(conn_->streamManager->getStream(id));
  auto packets = getNumPacketsTxWithNewData(*stream);
  return StreamTransportInfo{
      stream->totalHolbTime,
      stream->holbCount,
      bool(stream->lastHolbTime),
      packets,
      stream->streamLossCount,
      stream->finalWriteOffset,
      stream->finalReadOffset,
      stream->streamReadError,
      stream->streamWriteError};
}

const folly::SocketAddress& QuicTransportBaseLite::getPeerAddress() const {
  return conn_->peerAddress;
}

bool QuicTransportBaseLite::processCancelCode(const QuicError& cancelCode) {
  bool noError = false;
  switch (cancelCode.code.type()) {
    case QuicErrorCode::Type::LocalErrorCode: {
      LocalErrorCode localErrorCode = *cancelCode.code.asLocalErrorCode();
      noError = localErrorCode == LocalErrorCode::NO_ERROR ||
          localErrorCode == LocalErrorCode::IDLE_TIMEOUT ||
          localErrorCode == LocalErrorCode::SHUTTING_DOWN;
      break;
    }
    case QuicErrorCode::Type::TransportErrorCode: {
      TransportErrorCode transportErrorCode =
          *cancelCode.code.asTransportErrorCode();
      noError = transportErrorCode == TransportErrorCode::NO_ERROR;
      break;
    }
    case QuicErrorCode::Type::ApplicationErrorCode:
      auto appErrorCode = *cancelCode.code.asApplicationErrorCode();
      noError = appErrorCode == APP_NO_ERROR;
  }
  return noError;
}

} // namespace quic
