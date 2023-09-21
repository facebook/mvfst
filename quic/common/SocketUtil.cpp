/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/SocketUtil.h>

namespace quic {

bool isNetworkUnreachable(int err) {
  return err == EHOSTUNREACH || err == ENETUNREACH;
}

void applySocketOptions(
    QuicAsyncUDPSocketWrapper& sock,
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
        option.first.level == IPPROTO_UDP || option.first.level == SOL_SOCKET ||
        option.first.level == SOL_UDP) {
      validOptions.insert(option);
    }
  }
  sock.applyOptions(validOptions, pos);
}

} // namespace quic
