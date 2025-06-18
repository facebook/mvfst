/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * quic/common/Expected.h - wrapper aliases for quic::Expected
 */
#pragma once

#include <utility>

// Forward-declare nonstd::expected_lite first, then create the compatibility
// alias *before* including the vendor header, so its hash specializations can
// resolve.
namespace nonstd {
namespace expected_lite {}
} // namespace nonstd

namespace quic {
namespace detail_expected_lite {
namespace nonstd {
namespace expected_lite = ::nonstd::expected_lite;
} // namespace nonstd
} // namespace detail_expected_lite
} // namespace quic

#include <quic/common/third-party/expected.hpp>

// Expose the vendor implementation in the global namespace symbols that
// some internal expected-lite helpers still reference.  We do this by just
// importing the wrapped namespace into the global nonstd::expected_lite name.
// This avoids touching any of the vendor code again while keeping everything
// safely under the quic namespace for ODR-safety.
// Bring vendor namespace into global nonstd as provided by vendor header.
// Already included by the header above, nothing to do.

// Legacy path mapping is now handled above before vendor header inclusion.

// Provide aliases so that legacy references like
// quic::detail_expected_lite::nonstd::expected_lite::expected<...>
// continue to compile even though the vendor code now lives in the global
// nonstd::expected_lite namespace only.
namespace quic {

// The vendor header already provides:
//   quic::Expected            alias for
//   detail_expected_lite::nonstd::expected_lite::expected

// We only need to expose make_expected / make_unexpected helpers so that
// existing call-sites can switch from folly::make_expected/unexpected with
// a simple namespace replacement.

template <class T>
constexpr Expected<typename std::decay<T>::type, int> make_expected(T&& value) {
  return Expected<typename std::decay<T>::type, int>(std::forward<T>(value));
}

template <class E>
constexpr auto make_unexpected(E&& err) {
  return ::nonstd::expected_lite::make_unexpected(std::forward<E>(err));
}
} // namespace quic
