/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>

namespace quic {

class QuicAsyncUDPSocketImpl : public QuicAsyncUDPSocket {
 public:
  QuicAsyncUDPSocket::RecvResult recvmmsgNetworkData(
      uint64_t readBufferSize,
      uint16_t numPackets,
      NetworkData& networkData,
      Optional<folly::SocketAddress>& peerAddress,
      size_t& totalData) override;

 private:
  struct RecvmmsgStorage {
    struct impl_ {
      struct sockaddr_storage addr;
      struct iovec iovec;
      // Buffers we pass to recvmmsg.
      Buf readBuffer;
    };

    // Storage for the recvmmsg system call.
    std::vector<struct mmsghdr> msgs;
    std::vector<struct impl_> impl_;
    void resize(size_t numPackets);
  };

  RecvmmsgStorage recvmmsgStorage_;
};
} // namespace quic
