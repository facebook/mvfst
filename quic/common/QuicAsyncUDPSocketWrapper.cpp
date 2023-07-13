/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/QuicAsyncUDPSocketWrapper.h>

namespace quic {

#ifdef MVFST_USE_LIBEV
int getSocketFd(const QuicAsyncUDPSocketType& /* s */) {
  return -1;
}
NetworkFdType toNetworkFdType(int fd) {
  return fd;
}
#else
int getSocketFd(const QuicAsyncUDPSocketType& s) {
  return s.getNetworkSocket().toFd();
}
NetworkFdType toNetworkFdType(int fd) {
  return folly::NetworkSocket(fd);
}
#endif

} // namespace quic
