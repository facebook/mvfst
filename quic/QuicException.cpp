/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.

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
    case TransportErrorCode::FINAL_OFFSET_ERROR:
      return "Final offset error";
    case TransportErrorCode::FRAME_ENCODING_ERROR:
      return "Frame format error";
    case TransportErrorCode::TRANSPORT_PARAMETER_ERROR:
      return "Transport parameter error";
    case TransportErrorCode::VERSION_NEGOTIATION_ERROR:
      return "Version negotiation error";
    case TransportErrorCode::PROTOCOL_VIOLATION:
      return "Protocol violation";
    case TransportErrorCode::INVALID_MIGRATION:
      return "Invalid migration";
    case TransportErrorCode::TLS_HANDSHAKE_FAILED:
      return "Handshake Failed";
    case TransportErrorCode::TLS_FATAL_ALERT_GENERATED:
      return "TLS Alert Sent";
    case TransportErrorCode::TLS_FATAL_ALERT_RECEIVED:
      return "TLS Alert Received";
  }
  LOG(WARNING) << "toString has unhandled ErrorCode";
  return "Unknown error";
}

std::string toString(ApplicationErrorCode code) {
  switch (code) {
    case ApplicationErrorCode::STOPPING:
      return "Stopping";
    case ApplicationErrorCode::HTTP_NO_ERROR:
      return "HTTP: No error";
    case ApplicationErrorCode::HTTP_PUSH_REFUSED:
      return "HTTP: Client refused pushed content";
    case ApplicationErrorCode::HTTP_INTERNAL_ERROR:
      return "HTTP: Internal error";
    case ApplicationErrorCode::HTTP_PUSH_ALREADY_IN_CACHE:
      return "HTTP: Pushed content already cached";
    case ApplicationErrorCode::HTTP_REQUEST_CANCELLED:
      return "HTTP: Data no longer needed";
    case ApplicationErrorCode::HTTP_INCOMPLETE_REQUEST:
      return "HTTP: Stream terminated early";
    case ApplicationErrorCode::HTTP_CONNECT_ERROR:
      return "HTTP: Reset or error on CONNECT request";
    case ApplicationErrorCode::HTTP_EXCESSIVE_LOAD:
      return "HTTP: Peer generating excessive load";
    case ApplicationErrorCode::HTTP_VERSION_FALLBACK:
      return "HTTP: Retry over HTTP/1.1";
    case ApplicationErrorCode::HTTP_WRONG_STREAM:
      return "HTTP: A frame was sent on the wrong stream";
    case ApplicationErrorCode::HTTP_PUSH_LIMIT_EXCEEDED:
      return "HTTP: Maximum Push ID exceeded";
    case ApplicationErrorCode::HTTP_DUPLICATE_PUSH:
      return "HTTP: Push ID was fulfilled multiple times";
    case ApplicationErrorCode::HTTP_UNKNOWN_STREAM_TYPE:
      return "HTTP: Unknown unidirectional stream type";
    case ApplicationErrorCode::HTTP_WRONG_STREAM_COUNT:
      return "HTTP: Too many unidirectional streams";
    case ApplicationErrorCode::HTTP_CLOSED_CRITICAL_STREAM:
      return "HTTP: Critical stream was closed";
    case ApplicationErrorCode::HTTP_WRONG_STREAM_DIRECTION:
      return "HTTP: Unidirectional stream in wrong direction";
    case ApplicationErrorCode::HTTP_EARLY_RESPONSE:
      return "HTTP: Remainder of request not needed";
    case ApplicationErrorCode::HTTP_MISSING_SETTINGS:
      return "HTTP: No SETTINGS frame received";
    case ApplicationErrorCode::HTTP_UNEXPECTED_FRAME:
      return "HTTP: Unexpected frame from client";
    case ApplicationErrorCode::HTTP_REQUEST_REJECTED:
      return "HTTP: Server did not process request";
    case ApplicationErrorCode::HTTP_QPACK_DECOMPRESSION_FAILED:
      return "HTTP: QPACK decompression failed";
    case ApplicationErrorCode::HTTP_QPACK_DECODER_STREAM_ERROR:
      return "HTTP: Error on QPACK decoder stream";
    case ApplicationErrorCode::HTTP_QPACK_ENCODER_STREAM_ERROR:
      return "HTTP: Error on QPACK encoder stream";
    case ApplicationErrorCode::HTTP_GENERAL_PROTOCOL_ERROR:
      return "HTTP: General protocol error";
    case ApplicationErrorCode::HTTP_MALFORMED_FRAME_DATA:
      return "HTTP: Malformed DATA frame";
    case ApplicationErrorCode::HTTP_MALFORMED_FRAME_HEADERS:
      return "HTTP: Malformed HEADERS frame";
    case ApplicationErrorCode::HTTP_MALFORMED_FRAME_PRIORITY:
      return "HTTP: Malformed PRIORITY frame";
    case ApplicationErrorCode::HTTP_MALFORMED_FRAME_CANCEL_PUSH:
      return "HTTP: Malformed CANCEL_PUSH frame";
    case ApplicationErrorCode::HTTP_MALFORMED_FRAME_SETTINGS:
      return "HTTP: Malformed SETTINGS frame";
    case ApplicationErrorCode::HTTP_MALFORMED_FRAME_PUSH_PROMISE:
      return "HTTP: Malformed PUSH_PROMISE frame";
    case ApplicationErrorCode::HTTP_MALFORMED_FRAME_GOAWAY:
      return "HTTP: Malformed GOAWAY frame";
    case ApplicationErrorCode::HTTP_MALFORMED_FRAME_MAX_PUSH_ID:
      return "HTTP: Malformed MAX_PUSH_ID frame";
    case ApplicationErrorCode::HTTP_MALFORMED_FRAME:
      return "HTTP: Malformed frame";
    case ApplicationErrorCode::INTERNAL_ERROR:
      return "Internal error";
    case ApplicationErrorCode::GIVEUP_ZERO_RTT:
      return "Give up Zero RTT";
  }
  LOG(WARNING) << "toString has unhandled ErrorCode";
  return "Unknown error";
}

std::string toString(QuicErrorCode code) {
  return folly::variant_match(
      code,
      [](ApplicationErrorCode errorCode) { return toString(errorCode); },
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
