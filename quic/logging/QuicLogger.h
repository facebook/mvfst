/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/tracing/StaticTracepoint.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/state/StateData.h>

namespace quic {

class Logger {
 public:
  virtual ~Logger() = default;

  virtual void logTrace(
      const std::string& name,
      const QuicConnectionStateBase& conn,
      std::chrono::steady_clock::time_point time,
      const std::string& value) = 0;
};

template <class T>
void quicTraceStream(std::string& value, T&& t) {
  value += folly::to<std::string>(t);
}

template <class T, class... Args>
void quicTraceStream(std::string& value, T&& t, Args&&... args) {
  value += folly::to<std::string>(t, ", ");
  quicTraceStream(value, std::forward<Args>(args)...);
}

template <class T, class... Args>
void quicTraceLogger(std::string name, const T& conn, Args&&... args) {
  std::string value;
  quicTraceStream(value, std::forward<Args>(args)...);

  VLOG(20) << name << " [" << conn << "] " << value;

  if (conn.logger) {
    conn.logger->logTrace(name, conn, std::chrono::steady_clock::now(), value);
  }
}

#if FOLLY_MOBILE
#define QUIC_LOGGER(name, conn, ...) (void)conn;
#else
#define QUIC_LOGGER(name, connmacro, ...)           \
  if ((connmacro).logger || VLOG_IS_ON(20)) {       \
    quicTraceLogger(#name, connmacro, __VA_ARGS__); \
  }
#endif

#if QUIC_TPERF
#define QUIC_TRACE(name, conn, ...) ;
#else
#define QUIC_TRACE(name, conn, ...)      \
  do {                                   \
    QUIC_LOGGER(name, conn, __VA_ARGS__) \
  } while (false);
#endif

#define QUIC_TRACE_SOCK(name, sock, ...)                \
  if (sock && sock->getState()) {                       \
    QUIC_TRACE(name, *(sock)->getState(), __VA_ARGS__); \
  }

} // namespace quic
