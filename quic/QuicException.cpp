/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/QuicException.h>

#include <folly/Overload.h>
#include <glog/logging.h>

namespace quic {

QuicTransportException::QuicTransportException(
    const std::string& msg,
    TransportErrorCode errCode)
    : std::runtime_error(msg), errCode_(errCode){};

QuicTransportException::QuicTransportException(
    const char* msg,
    TransportErrorCode errCode)
    : std::runtime_error(msg), errCode_(errCode){};

QuicTransportException::QuicTransportException(
    const std::string& msg,
    TransportErrorCode errCode,
    FrameType frameType)
    : std::runtime_error(msg), errCode_(errCode), frameType_(frameType){};

QuicTransportException::QuicTransportException(
    const char* msg,
    TransportErrorCode errCode,
    FrameType frameType)
    : std::runtime_error(msg), errCode_(errCode), frameType_(frameType){};

QuicInternalException::QuicInternalException(
    const std::string& msg,
    LocalErrorCode errCode)
    : std::runtime_error(msg), errorCode_(errCode){};

QuicInternalException::QuicInternalException(
    const char* msg,
    LocalErrorCode errCode)
    : std::runtime_error(msg), errorCode_(errCode){};

QuicApplicationException::QuicApplicationException(
    const std::string& msg,
    ApplicationErrorCode errorCode)
    : std::runtime_error(msg), errorCode_(errorCode){};

QuicApplicationException::QuicApplicationException(
    const char* msg,
    ApplicationErrorCode errorCode)
    : std::runtime_error(msg), errorCode_(errorCode){};

std::string toString(LocalErrorCode code) {
  switch (code) {
    case LocalErrorCode::NO_ERROR:
      return "No Error";
    case LocalErrorCode::CONNECT_FAILED:
      return "Connect failed";
    case LocalErrorCode::CODEC_ERROR:
      return "Codec Error";
    case LocalErrorCode::STREAM_CLOSED:
      return "Stream is closed";
    case LocalErrorCode::STREAM_NOT_EXISTS:
      return "Stream does not exist";
    case LocalErrorCode::CREATING_EXISTING_STREAM:
      return "Creating an existing stream";
    case LocalErrorCode::SHUTTING_DOWN:
      return "Shutting down";
    case LocalErrorCode::RESET_CRYPTO_STREAM:
      return "Reset the crypto stream";
    case LocalErrorCode::CWND_OVERFLOW:
      return "CWND overflow";
    case LocalErrorCode::INFLIGHT_BYTES_OVERFLOW:
      return "Inflight bytes overflow";
    case LocalErrorCode::LOST_BYTES_OVERFLOW:
      return "Lost bytes overflow";
    case LocalErrorCode::NEW_VERSION_NEGOTIATED:
      return "New version negotiatied";
    case LocalErrorCode::INVALID_WRITE_CALLBACK:
      return "Invalid write callback";
    case LocalErrorCode::TLS_HANDSHAKE_FAILED:
      return "TLS handshake failed";
    case LocalErrorCode::APP_ERROR:
      return "App error";
    case LocalErrorCode::INTERNAL_ERROR:
      return "Internal error";
    case LocalErrorCode::TRANSPORT_ERROR:
      return "Transport error";
    case LocalErrorCode::INVALID_WRITE_DATA:
      return "Invalid write data";
    case LocalErrorCode::INVALID_STATE_TRANSITION:
      return "Invalid state transition";
    case LocalErrorCode::CONNECTION_CLOSED:
      return "Connection closed";
    case LocalErrorCode::EARLY_DATA_REJECTED:
      return "Early data rejected";
    case LocalErrorCode::CONNECTION_RESET:
      return "Connection reset";
    case LocalErrorCode::IDLE_TIMEOUT:
      return "Idle timeout";
    case LocalErrorCode::PACKET_NUMBER_ENCODING:
      return "Packet number encoding";
    case LocalErrorCode::INVALID_OPERATION:
      return "Invalid operation";
    case LocalErrorCode::STREAM_LIMIT_EXCEEDED:
      return "Stream limit exceeded";
    case LocalErrorCode::CONNECTION_ABANDONED:
      return "Connection abandoned";
  }
  LOG(WARNING) << "toString has unhandled ErrorCode";
  return "Unknown error";
}

std::string toString(TransportErrorCode code) {
  switch (code) {
    case TransportErrorCode::NO_ERROR:
      return "No Error";
    case TransportErrorCode::INTERNAL_ERROR:
      return "Internal Error";
    case TransportErrorCode::FLOW_CONTROL_ERROR:
      return "Flow control error";
    case TransportErrorCode::STREAM_LIMIT_ERROR:
      return "Stream limit error";
    case TransportErrorCode::STREAM_STATE_ERROR:
      return "Stream State error";
    case TransportErrorCode::FINAL_SIZE_ERROR:
      return "Final offset error";
    case TransportErrorCode::FRAME_ENCODING_ERROR:
      return "Frame format error";
    case TransportErrorCode::TRANSPORT_PARAMETER_ERROR:
      return "Transport parameter error";
    case TransportErrorCode::PROTOCOL_VIOLATION:
      return "Protocol violation";
    case TransportErrorCode::INVALID_MIGRATION:
      return "Invalid migration";
    case TransportErrorCode::SERVER_BUSY:
      return "Server busy";
    case TransportErrorCode::TLS_HANDSHAKE_FAILED:
      return "Handshake Failed";
  }
  LOG(WARNING) << "toString has unhandled ErrorCode";
  return "Unknown error";
}

std::string toString(QuicErrorCode code) {
  return folly::variant_match(
      code,
      [](ApplicationErrorCode errorCode) {
        return folly::to<std::string>(errorCode);
      },
      [](LocalErrorCode errorCode) { return toString(errorCode); },
      [](TransportErrorCode errorCode) { return toString(errorCode); });
}

std::string toString(
    const std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>&
        error) {
  return folly::to<std::string>(
      folly::variant_match(
          error.first,
          [](ApplicationErrorCode errorCode) {
            return "ApplicationError: " + toString(errorCode) + ", ";
          },
          [](LocalErrorCode errorCode) {
            return "LocalError: " + toString(errorCode) + ", ";
          },
          [](TransportErrorCode errorCode) {
            return "TransportError: " + toString(errorCode) + ", ";
          }),
      error.second.value_or(folly::StringPiece()).toString());
}
} // namespace quic
