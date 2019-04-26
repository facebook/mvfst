/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.
#pragma once

#include <stdexcept>
#include <string>

#include <quic/QuicConstants.h>

namespace quic {
class QuicTransportException : public std::runtime_error {
 public:
  explicit QuicTransportException(
      const std::string& msg,
      TransportErrorCode errCode);

  explicit QuicTransportException(const char* msg, TransportErrorCode errCode);

  explicit QuicTransportException(
      const std::string& msg,
      TransportErrorCode errCode,
      FrameType frameType);

  explicit QuicTransportException(
      const char* msg,
      TransportErrorCode errCode,
      FrameType frameType);

  TransportErrorCode errorCode() const noexcept {
    return errCode_;
  }

  folly::Optional<FrameType> frameType() const noexcept {
    return frameType_;
  }

 private:
  TransportErrorCode errCode_;
  folly::Optional<FrameType> frameType_;
};

class QuicInternalException : public std::runtime_error {
 public:
  explicit QuicInternalException(
      const std::string& msg,
      LocalErrorCode errorCode);
  explicit QuicInternalException(const char* msg, LocalErrorCode errCode);

  LocalErrorCode errorCode() const noexcept {
    return errorCode_;
  }

 private:
  LocalErrorCode errorCode_;
};

class QuicApplicationException : public std::runtime_error {
 public:
  explicit QuicApplicationException(
      const std::string& msg,
      ApplicationErrorCode errorCode);
  explicit QuicApplicationException(
      const char* msg,
      ApplicationErrorCode errorCode);

  ApplicationErrorCode errorCode() const noexcept {
    return errorCode_;
  }

 private:
  ApplicationErrorCode errorCode_;
};

/**
 * Convert the error code to a string.
 */
std::string toString(TransportErrorCode code);
std::string toString(LocalErrorCode code);
std::string toString(QuicErrorCode code);
std::string toString(
    const std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>& error);

inline std::ostream& operator<<(std::ostream& os, const QuicErrorCode& error) {
  os << toString(error);
  return os;
}

inline std::ostream& operator<<(
    std::ostream& os,
    const std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>&
        error) {
  os << toString(error);
  return os;
}

} // namespace quic
