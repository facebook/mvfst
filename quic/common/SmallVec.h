/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/small_vector.h>

namespace quic {

#if !FOLLY_MOBILE
template <
    class T,
    std::size_t N,
    class PolicyA = void,
    class PolicyB = void,
    class PolicyC = void>
using SmallVec = folly::small_vector<T, N, PolicyA, PolicyB, PolicyC>;
#else
template <
    class T,
    std::size_t N,
    class PolicyA = void,
    class PolicyB = void,
    class PolicyC = void>
using SmallVec = std::vector<T>;
#endif

} // namespace quic
