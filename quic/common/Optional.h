/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/mvfst-config.h>

#include <optional>

namespace quic {

template <class PayloadType>
[[nodiscard]] inline auto make_optional(PayloadType&& v) {
  return Optional<std::decay_t<PayloadType>>(std::forward<PayloadType>(v));
}

template <class PayloadType, class... ArgsT>
[[nodiscard]] inline auto make_optional(ArgsT&&... args) {
  return Optional<PayloadType>(std::in_place, std::forward<ArgsT>(args)...);
}

template <class PayloadType, class U, class... ArgsT>
[[nodiscard]] inline auto make_optional(
    std::initializer_list<U> il,
    ArgsT&&... args) {
  return Optional<PayloadType>(std::in_place, il, std::forward<ArgsT>(args)...);
}

} // namespace quic
