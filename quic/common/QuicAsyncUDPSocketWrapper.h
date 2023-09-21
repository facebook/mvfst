/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/NetworkData.h>
#include <quic/common/QuicEventBase.h>

#ifdef MVFST_USE_LIBEV
#include <quic/common/QuicAsyncUDPSocketImpl.h>
#else
#include <folly/io/async/AsyncUDPSocket.h>
#endif

namespace quic {

#ifdef MVFST_USE_LIBEV
using QuicAsyncUDPSocketType = QuicAsyncUDPSocketImpl;
#else
using QuicAsyncUDPSocketType = folly::AsyncUDPSocket;
using NetworkFdType = folly::NetworkSocket;
#endif

class QuicAsyncUDPSocketWrapper : public QuicAsyncUDPSocketType {
 public:
  using QuicAsyncUDPSocketType::QuicAsyncUDPSocketType;
  ~QuicAsyncUDPSocketWrapper() override = default;

  class ReadCallback : public QuicAsyncUDPSocketType::ReadCallback {
   public:
    ~ReadCallback() override = default;

    virtual void onNotifyDataAvailable(
        QuicAsyncUDPSocketWrapper& /* sock */) noexcept {}

   private:
    void onNotifyDataAvailable(QuicAsyncUDPSocketType& sock) noexcept final {
      onNotifyDataAvailable(static_cast<QuicAsyncUDPSocketWrapper&>(sock));
    }
  };

  using ErrMessageCallback = QuicAsyncUDPSocketType::ErrMessageCallback;

  /**
   * recv() result structure.
   */
  struct RecvResult {
    RecvResult() = default;
    explicit RecvResult(NoReadReason noReadReason)
        : maybeNoReadReason(noReadReason) {}

    folly::Optional<NoReadReason> maybeNoReadReason;
  };

  /**
   * Receive packets from the socket.
   *
   * Can be called after onNotifyDataAvailable().
   *
   * @param readBufferSize     Size of ReadBuffer to allocate in bytes.
   * @param numPackets         Max number of packets to try to receive.
   * @param networkData        Object to populate with received packets.
   * @param peerAddress        Object to populate with peer IP address.
   * @param totalData          Total bytes read from the socket.
   */
  virtual RecvResult recvMmsg(
      uint64_t readBufferSize,
      uint16_t numPackets,
      NetworkData& networkData,
      folly::Optional<folly::SocketAddress>& peerAddress,
      size_t& totalData) = 0;
};

class QuicAsyncUDPSocketWrapperImpl : public QuicAsyncUDPSocketWrapper {
 public:
  using QuicAsyncUDPSocketWrapper::QuicAsyncUDPSocketWrapper;
  ~QuicAsyncUDPSocketWrapperImpl() override = default;

  RecvResult recvMmsg(
      uint64_t readBufferSize,
      uint16_t numPackets,
      NetworkData& networkData,
      folly::Optional<folly::SocketAddress>& peerAddress,
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

int getSocketFd(const QuicAsyncUDPSocketWrapper& s);
NetworkFdType toNetworkFdType(int fd);

} // namespace quic
