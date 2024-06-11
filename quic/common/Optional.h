/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <folly/Optional.h>

namespace quic {
template <class T>
using Optional = folly::Optional<T>;

constexpr folly::None none{folly::None::_secret::_token};
} // namespace quic
