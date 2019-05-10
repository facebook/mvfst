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
  if (!conn.logger && !VLOG_IS_ON(20)) {
    return;
  }

  std::string value;
  quicTraceStream(value, std::forward<Args>(args)...);

  VLOG(20) << name << " [" << conn << "] " << value;

  if (conn.logger) {
    conn.logger->logTrace(name, conn, std::chrono::steady_clock::now(), value);
  }
}

// We support 11 paramster after name and conn in QUIC_TRACE function, of which
// 8 will be passed to FOLLY_SDT. Expand the following macros if you need to
// support more params.
#define TAKE_1(N1) N1
#define TAKE_2(N1, N2) N1, N2
#define TAKE_3(N1, N2, N3) N1, N2, N3
#define TAKE_4(N1, N2, N3, N4) N1, N2, N3, N4
#define TAKE_5(N1, N2, N3, N4, N5) N1, N2, N3, N4, N5
#define TAKE_6(N1, N2, N3, N4, N5, N6) N1, N2, N3, N4, N5, N6
#define TAKE_7(N1, N2, N3, N4, N5, N6, N7) N1, N2, N3, N4, N5, N6, N7
#define TAKE_8(N1, N2, N3, N4, N5, N6, N7, N8) N1, N2, N3, N4, N5, N6, N7, N8
#define TAKE_8_FROM_MORE(N1, N2, N3, N4, N5, N6, N7, N8, ...) \
  N1, N2, N3, N4, N5, N6, N7, N8

#define PARAM_TAKE_HELPER(                                     \
    _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, CHOSEN, ...) \
  CHOSEN

#define TAKE_ATMOST_8(...) \
  PARAM_TAKE_HELPER(       \
      __VA_ARGS__,         \
      TAKE_8_FROM_MORE,    \
      TAKE_8_FROM_MORE,    \
      TAKE_8_FROM_MORE,    \
      TAKE_8,              \
      TAKE_7,              \
      TAKE_6,              \
      TAKE_5,              \
      TAKE_4,              \
      TAKE_3,              \
      TAKE_2,              \
      TAKE_1)              \
  (__VA_ARGS__)

#if FOLLY_MOBILE
#define QUIC_LOGGER(name, conn, ...) (void)conn;
#else
#define QUIC_LOGGER(name, conn, ...) quicTraceLogger(#name, conn, __VA_ARGS__);
#endif

#define QUIC_TRACE(name, conn, ...)                                           \
  do {                                                                        \
    QUIC_LOGGER(name, conn, __VA_ARGS__)                                      \
    FOLLY_SDT(                                                                \
        quic,                                                                 \
        name,                                                                 \
        (conn).clientConnectionId.value_or(quic::ConnectionId{{0, 0, 0, 0}}), \
        TAKE_ATMOST_8(__VA_ARGS__));                                          \
  } while (false);

#define QUIC_TRACE_SOCK(name, sock, ...)                \
  if (sock && sock->getState()) {                       \
    QUIC_TRACE(name, *(sock)->getState(), __VA_ARGS__); \
  }

} // namespace quic
