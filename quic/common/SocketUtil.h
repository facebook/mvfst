/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/SocketOptionMap.h>
#include <folly/net/NetOps.h>

namespace quic {

inline bool isNetworkUnreachable(int err) {
  return err == EHOSTUNREACH || err == ENETUNREACH;
}

// T should have this method:
// applyOptions(
//      const folly::SocketOptionMap& /* options */,
//      folly::SocketOptionKey::ApplyPos /* pos */)
template <class T>
void applySocketOptions(
    T& sock,
    const folly::SocketOptionMap& options,
    sa_family_t family,
    folly::SocketOptionKey::ApplyPos pos) noexcept {
  folly::SocketOptionMap validOptions;

  for (const auto& option : options) {
    if (pos != option.first.applyPos_) {
      continue;
    }
    if ((family == AF_INET && option.first.level == IPPROTO_IP) ||
        (family == AF_INET6 && option.first.level == IPPROTO_IPV6) ||
#ifdef IP_BIND_ADDRESS_NO_PORT
        (option.first.level == IPPROTO_IP &&
         option.first.optname == IP_BIND_ADDRESS_NO_PORT) ||
#endif
        option.first.level == IPPROTO_UDP || option.first.level == SOL_SOCKET ||
        option.first.level == SOL_UDP) {
      validOptions.insert(option);
    }
  }
  sock.applyOptions(validOptions, pos);
}

} // namespace quic
