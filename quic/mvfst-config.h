/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/container/F14Map.h>
#include <folly/container/F14Set.h>

namespace quic {
template <class... Args>
struct UnorderedMap : folly::F14FastMap<Args...> {};

template <class... Args>
struct ValueMap : folly::F14ValueMap<Args...> {};

template <class... Args>
struct UnorderedSet : folly::F14FastSet<Args...> {};
} // namespace quic
