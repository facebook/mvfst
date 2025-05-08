/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#define QUIC_TINY_OPTIONAL_USE_SEPARATE_BOOL_INSTEAD_OF_UB_TRICKS 1

#include <quic/common/third-party/optional.h>

#include <chrono>
#include <memory>

namespace quic {

template <class PayloadType>
[[nodiscard]] inline auto make_optional(PayloadType&& v) {
  return ::quic::detail::tiny::make_optional(std::forward<PayloadType>(v));
}

template <class PayloadType, class... ArgsT>
[[nodiscard]] inline auto make_optional(ArgsT&&... args) {
  return ::quic::detail::tiny::make_optional<PayloadType>(
      std::forward<ArgsT>(args)...);
}

template <class PayloadType, class U, class... ArgsT>
[[nodiscard]] inline auto make_optional(
    std::initializer_list<U> il,
    ArgsT&&... args) {
  return ::quic::detail::tiny::make_optional<PayloadType>(
      il, std::forward<ArgsT>(args)...);
}

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

namespace detail {

template <>
struct tiny::optional_flag_manipulator<std::chrono::microseconds>
    : ::quic::MicrosecondsFlagManipulator {};

} // namespace detail

template <class T>
using Optional = ::quic::detail::tiny::optional<T>;

template <class T>
using OptionalIntegral = ::quic::detail::tiny::optional_aip<T>;

using OptionalMicros = ::quic::detail::tiny::
    optional_inplace<std::chrono::microseconds, MicrosecondsFlagManipulator>;

} // namespace quic
