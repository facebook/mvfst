/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/container/heap_vector_types.h>
#include <folly/small_vector.h>

namespace quic {

#if !FOLLY_MOBILE || _WIN32
template <class T, std::size_t N, class... Policy>
using SmallVec = folly::small_vector<T, N, Policy...>;
#else
template <class T, std::size_t N, class... Policy>
using SmallVec = std::vector<T>;
#endif

template <class T, size_t N>
using InlineMapVec = folly::small_vector<T, N>;

template <
    typename Key,
    typename Value,
    size_t N,
    class Container = InlineMapVec<std::pair<Key, Value>, N>,
    typename = std::enable_if_t<std::is_integral<Key>::value>>
using InlineMap = folly::heap_vector_map<
    Key,
    Value,
    std::less<Key>,
    typename Container::allocator_type,
    void,
    Container>;

} // namespace quic
