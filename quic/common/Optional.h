/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <folly/Optional.h>

#define TINY_OPTIONAL_USE_SEPARATE_BOOL_INSTEAD_OF_UB_TRICKS 1
#include <quic/common/third-party/optional.h>

#include <chrono>

namespace quic {
template <class T>
using Optional = folly::Optional<T>;

constexpr folly::None none{folly::None::_secret::_token};

template <class T>
using OptionalIntegral = tiny::optional_aip<T>;

struct MicrosecondsFlagManipulator {
  static bool is_empty(const std::chrono::microseconds& t) noexcept {
    return t == std::chrono::microseconds::min();
  }

  static void init_empty_flag(std::chrono::microseconds& t) noexcept {
    ::new (&t) std::chrono::microseconds(std::chrono::microseconds::min());
  }

  static void invalidate_empty_flag(std::chrono::microseconds& t) noexcept {
    std::destroy_at(&t);
  }
};

using OptionalMicros = tiny::
    optional_inplace<std::chrono::microseconds, MicrosecondsFlagManipulator>;

} // namespace quic
