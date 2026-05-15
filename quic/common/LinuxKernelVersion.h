/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/Optional.h>
#include <utility>

namespace quic {

/**
 * Returns the running Linux kernel's (major, minor) version pair.
 *
 * On non-Linux platforms, or if uname() fails or returns an unparseable
 * release string, returns std::nullopt. Callers should fail-closed when the
 * result is empty (i.e. assume the feature is not supported).
 *
 * The result is cached on the first successful call.
 */
Optional<std::pair<int, int>> getLinuxKernelVersion();

/**
 * Returns true iff the running kernel is at least the given (major, minor)
 * version. Returns false on non-Linux platforms or if the version cannot be
 * determined.
 *
 * Takes a pair (rather than two positional ints) so callsites read as
 * `isLinuxKernelAtLeast({6, 8})` and the two ints can't be transposed.
 */
bool isLinuxKernelAtLeast(std::pair<int, int> minVersion);

namespace detail {

/**
 * Parses a Linux kernel release string (as returned by uname()) into a
 * (major, minor) pair. Exposed for testing.
 *
 * Accepts strings like "6.4.0", "6.16.1-0_custom_hardened_0_a1b2...",
 * "6.4-rc7". Returns std::nullopt for empty/unparseable input.
 */
Optional<std::pair<int, int>> parseLinuxKernelRelease(const char* release);

} // namespace detail

} // namespace quic
