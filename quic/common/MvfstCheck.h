/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <glog/logging.h>

// Server/Desktop version - full CHECK/DCHECK macros with message support.
// Mobile builds use MvfstCheck-mobile.h instead (via BUCK select()).
//
// Usage:
//   MVCHECK(cond);                          // No message
//   MVCHECK(cond, "message");               // Simple message
//   MVCHECK(cond, "x=" << x << " y=" << y); // Complex message with values
//   MVDCHECK(cond, "debug message");        // Debug-only check
//
// On server: messages are preserved in binary and logged on failure
// On mobile: messages are completely stripped (not even in binary)

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

#if MVFST_HAS_VA_OPT
// Use __VA_OPT__ for optional message support
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
