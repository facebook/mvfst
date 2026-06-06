/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/quic-logging-config.h>

/**
 * quic/common/MvfstCheck.h defines the MVCHECK / MVDCHECK family of macros.
 *
 * Backend selected by exactly one of MVFST_LOGGING_GLOG, MVFST_LOGGING_XLOG,
 * MVFST_LOGGING_DISABLED in <quic/quic-logging-config.h>. See MvfstLogging.h
 * for the full design notes.
 *
 * Usage:
 *   MVCHECK(cond);                          // No message
 *   MVCHECK(cond, "message");               // Simple message
 *   MVCHECK(cond, "x=" << x << " y=" << y); // Complex streamed message
 *   MVDCHECK(cond, "debug message");        // Debug-only check
 *
 * On server: messages are preserved in the binary and logged on failure
 * On mobile: messages are completely stripped (not even in binary)
 */

// Detect __VA_OPT__ support:
// - GCC 8+ and Clang 6+ support it as extension even in C++17 mode
// - MSVC requires BOTH:
//   1. /Zc:preprocessor flag (conforming preprocessor, _MSVC_TRADITIONAL == 0)
//   2. C++20 or later (_MSVC_LANG >= 202002L)
#ifdef _MSC_VER
#if defined(_MSVC_TRADITIONAL) && _MSVC_TRADITIONAL == 0 && \
    defined(_MSVC_LANG) && _MSVC_LANG >= 202002L
// MSVC with conforming preprocessor AND C++20
#define MVFST_HAS_VA_OPT 1
#else
// MSVC without full __VA_OPT__ support
#define MVFST_HAS_VA_OPT 0
#endif
#else
// GCC/Clang: __VA_OPT__ works as extension in C++17 mode
#define MVFST_HAS_VA_OPT 1
#endif

#if MVFST_LOGGING_GLOG

#include <glog/logging.h>

#if MVFST_HAS_VA_OPT
#define MVCHECK(cond, ...) CHECK(cond) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_EQ(a, b, ...) CHECK_EQ(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_NE(a, b, ...) CHECK_NE(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_LT(a, b, ...) CHECK_LT(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_GT(a, b, ...) CHECK_GT(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_LE(a, b, ...) CHECK_LE(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_GE(a, b, ...) CHECK_GE(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_NOTNULL(ptr) CHECK_NOTNULL(ptr)

#define MVDCHECK(cond, ...) DCHECK(cond) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_EQ(a, b, ...) DCHECK_EQ(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_NE(a, b, ...) DCHECK_NE(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_LT(a, b, ...) DCHECK_LT(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_GT(a, b, ...) DCHECK_GT(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_LE(a, b, ...) DCHECK_LE(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_GE(a, b, ...) DCHECK_GE(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_NOTNULL(ptr) DCHECK_NOTNULL(ptr)

#else
// MSVC C++17: Messages are not supported, just use basic CHECK/DCHECK
// The variadic args are accepted but ignored
#define MVCHECK(cond, ...) CHECK(cond)
#define MVCHECK_EQ(a, b, ...) CHECK_EQ(a, b)
#define MVCHECK_NE(a, b, ...) CHECK_NE(a, b)
#define MVCHECK_LT(a, b, ...) CHECK_LT(a, b)
#define MVCHECK_GT(a, b, ...) CHECK_GT(a, b)
#define MVCHECK_LE(a, b, ...) CHECK_LE(a, b)
#define MVCHECK_GE(a, b, ...) CHECK_GE(a, b)
#define MVCHECK_NOTNULL(ptr) CHECK_NOTNULL(ptr)

#define MVDCHECK(cond, ...) DCHECK(cond)
#define MVDCHECK_EQ(a, b, ...) DCHECK_EQ(a, b)
#define MVDCHECK_NE(a, b, ...) DCHECK_NE(a, b)
#define MVDCHECK_LT(a, b, ...) DCHECK_LT(a, b)
#define MVDCHECK_GT(a, b, ...) DCHECK_GT(a, b)
#define MVDCHECK_LE(a, b, ...) DCHECK_LE(a, b)
#define MVDCHECK_GE(a, b, ...) DCHECK_GE(a, b)
#define MVDCHECK_NOTNULL(ptr) DCHECK_NOTNULL(ptr)
#endif

#elif MVFST_LOGGING_XLOG

#include <folly/logging/xlog.h>
#include <utility>

#if MVFST_HAS_VA_OPT
#define MVCHECK(cond, ...) XCHECK(cond) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_EQ(a, b, ...) XCHECK_EQ(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_NE(a, b, ...) XCHECK_NE(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_LT(a, b, ...) XCHECK_LT(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_GT(a, b, ...) XCHECK_GT(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_LE(a, b, ...) XCHECK_LE(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_GE(a, b, ...) XCHECK_GE(a, b) __VA_OPT__(<< __VA_ARGS__)

#define MVDCHECK(cond, ...) XDCHECK(cond) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_EQ(a, b, ...) XDCHECK_EQ(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_NE(a, b, ...) XDCHECK_NE(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_LT(a, b, ...) XDCHECK_LT(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_GT(a, b, ...) XDCHECK_GT(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_LE(a, b, ...) XDCHECK_LE(a, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_GE(a, b, ...) XDCHECK_GE(a, b) __VA_OPT__(<< __VA_ARGS__)

#else
#define MVCHECK(cond, ...) XCHECK(cond)
#define MVCHECK_EQ(a, b, ...) XCHECK_EQ(a, b)
#define MVCHECK_NE(a, b, ...) XCHECK_NE(a, b)
#define MVCHECK_LT(a, b, ...) XCHECK_LT(a, b)
#define MVCHECK_GT(a, b, ...) XCHECK_GT(a, b)
#define MVCHECK_LE(a, b, ...) XCHECK_LE(a, b)
#define MVCHECK_GE(a, b, ...) XCHECK_GE(a, b)

#define MVDCHECK(cond, ...) XDCHECK(cond)
#define MVDCHECK_EQ(a, b, ...) XDCHECK_EQ(a, b)
#define MVDCHECK_NE(a, b, ...) XDCHECK_NE(a, b)
#define MVDCHECK_LT(a, b, ...) XDCHECK_LT(a, b)
#define MVDCHECK_GT(a, b, ...) XDCHECK_GT(a, b)
#define MVDCHECK_LE(a, b, ...) XDCHECK_LE(a, b)
#define MVDCHECK_GE(a, b, ...) XDCHECK_GE(a, b)
#endif

// folly does not provide XCHECK_NOTNULL / XDCHECK_NOTNULL; emulate via a
// generic lambda that asserts non-null and returns the original (possibly
// rvalue) pointer so call sites like `auto p = MVCHECK_NOTNULL(expr);` keep
// working.
#define MVCHECK_NOTNULL(ptr)                           \
  ([](auto&& _mvfst_p) -> decltype(auto) {             \
    XCHECK(_mvfst_p != nullptr);                       \
    return std::forward<decltype(_mvfst_p)>(_mvfst_p); \
  }(ptr))
#define MVDCHECK_NOTNULL(ptr)                          \
  ([](auto&& _mvfst_p) -> decltype(auto) {             \
    XDCHECK(_mvfst_p != nullptr);                      \
    return std::forward<decltype(_mvfst_p)>(_mvfst_p); \
  }(ptr))

#elif MVFST_LOGGING_DISABLED

// mvfst logging disabled
//
// MVDCHECK()s are mapped to assert(...)
// MVCHECK()s are mapped to if (!(expr)) { std::abort(); }
// All log output is silently dropped.
//
// The macros still return a NoopStream so call-site `<< "msg"` chains and the
// __VA_OPT__ variadic message tail keep compiling.

#include <cassert>
#include <cstdlib>
#include <utility>

namespace quic::logging::detail {
struct NoopStream {};

template <class T>
inline NoopStream operator<<(NoopStream stream, T&&) {
  return stream;
}

} // namespace quic::logging::detail

#define MVFST_DCHECK_BINOP_(a, op, b)             \
  ([&] {                                          \
    assert((a)op(b));                             \
    return ::quic::logging::detail::NoopStream{}; \
  }())
#define MVFST_CHECK_BINOP_(a, op, b)              \
  ([&] {                                          \
    if (!((a)op(b))) {                            \
      std::abort();                               \
    }                                             \
    return ::quic::logging::detail::NoopStream{}; \
  }())
#define MVFST_CHECK_EXPR_(expr)                   \
  ([&] {                                          \
    if (!(expr)) {                                \
      std::abort();                               \
    }                                             \
    return ::quic::logging::detail::NoopStream{}; \
  }())
#define MVFST_DCHECK_EXPR_(expr)                  \
  ([&] {                                          \
    assert((expr));                               \
    return ::quic::logging::detail::NoopStream{}; \
  }())

#if MVFST_HAS_VA_OPT
#define MVCHECK(cond, ...) MVFST_CHECK_EXPR_(cond) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_EQ(a, b, ...) \
  MVFST_CHECK_BINOP_(a, ==, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_NE(a, b, ...) \
  MVFST_CHECK_BINOP_(a, !=, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_LT(a, b, ...) \
  MVFST_CHECK_BINOP_(a, <, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_GT(a, b, ...) \
  MVFST_CHECK_BINOP_(a, >, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_LE(a, b, ...) \
  MVFST_CHECK_BINOP_(a, <=, b) __VA_OPT__(<< __VA_ARGS__)
#define MVCHECK_GE(a, b, ...) \
  MVFST_CHECK_BINOP_(a, >=, b) __VA_OPT__(<< __VA_ARGS__)

#define MVDCHECK(cond, ...) MVFST_DCHECK_EXPR_(cond) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_EQ(a, b, ...) \
  MVFST_DCHECK_BINOP_(a, ==, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_NE(a, b, ...) \
  MVFST_DCHECK_BINOP_(a, !=, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_LT(a, b, ...) \
  MVFST_DCHECK_BINOP_(a, <, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_GT(a, b, ...) \
  MVFST_DCHECK_BINOP_(a, >, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_LE(a, b, ...) \
  MVFST_DCHECK_BINOP_(a, <=, b) __VA_OPT__(<< __VA_ARGS__)
#define MVDCHECK_GE(a, b, ...) \
  MVFST_DCHECK_BINOP_(a, >=, b) __VA_OPT__(<< __VA_ARGS__)
#else
#define MVCHECK(cond, ...) MVFST_CHECK_EXPR_(cond)
#define MVCHECK_EQ(a, b, ...) MVFST_CHECK_BINOP_(a, ==, b)
#define MVCHECK_NE(a, b, ...) MVFST_CHECK_BINOP_(a, !=, b)
#define MVCHECK_LT(a, b, ...) MVFST_CHECK_BINOP_(a, <, b)
#define MVCHECK_GT(a, b, ...) MVFST_CHECK_BINOP_(a, >, b)
#define MVCHECK_LE(a, b, ...) MVFST_CHECK_BINOP_(a, <=, b)
#define MVCHECK_GE(a, b, ...) MVFST_CHECK_BINOP_(a, >=, b)

#define MVDCHECK(cond, ...) MVFST_DCHECK_EXPR_(cond)
#define MVDCHECK_EQ(a, b, ...) MVFST_DCHECK_BINOP_(a, ==, b)
#define MVDCHECK_NE(a, b, ...) MVFST_DCHECK_BINOP_(a, !=, b)
#define MVDCHECK_LT(a, b, ...) MVFST_DCHECK_BINOP_(a, <, b)
#define MVDCHECK_GT(a, b, ...) MVFST_DCHECK_BINOP_(a, >, b)
#define MVDCHECK_LE(a, b, ...) MVFST_DCHECK_BINOP_(a, <=, b)
#define MVDCHECK_GE(a, b, ...) MVFST_DCHECK_BINOP_(a, >=, b)
#endif

#define MVCHECK_NOTNULL(ptr)                           \
  ([](auto&& _mvfst_p) -> decltype(auto) {             \
    if (_mvfst_p == nullptr) {                         \
      std::abort();                                    \
    }                                                  \
    return std::forward<decltype(_mvfst_p)>(_mvfst_p); \
  }(ptr))
#define MVDCHECK_NOTNULL(ptr) (ptr)

#else
#error \
    "Exactly one of MVFST_LOGGING_GLOG, MVFST_LOGGING_XLOG, MVFST_LOGGING_DISABLED must be defined to 1 in <quic/quic-logging-config.h>"
#endif
