/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/NetworkData.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocketImpl.h>

#include <folly/Expected.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/net/NetworkSocket.h>
#include <cstddef>
#include <memory>

namespace quic {

// This alias is used by the server components that need functionality not yet
// exposed in the QuicAsyncUDPSocket interface.
// The alias was created to make it easier to find the occurences of
// folly::AsyncUDPSocket in the QUIC code.
using FollyAsyncUDPSocketAlias = folly::AsyncUDPSocket;

class FollyQuicAsyncUDPSocket : public QuicAsyncUDPSocketImpl {
 public:
  socklen_t kAddrLen = sizeof(sockaddr_storage);

  FollyQuicAsyncUDPSocket(
      std::shared_ptr<FollyQuicEventBase> qEvb,
      folly::AsyncUDPSocket& socketToWrap)
      : evb_(std::move(qEvb)), follySocket_(socketToWrap) {
    CHECK_EQ(evb_->getBackingEventBase(), follySocket_.getEventBase());
  }

  FollyQuicAsyncUDPSocket(
      std::shared_ptr<FollyQuicEventBase> qEvb,
      std::unique_ptr<folly::AsyncUDPSocket> socketToWrap)
      : evb_(std::move(qEvb)),
        follySocketPtr(std::move(socketToWrap)),
        follySocket_(*follySocketPtr) {
    CHECK_EQ(evb_->getBackingEventBase(), follySocket_.getEventBase());
  }

  explicit FollyQuicAsyncUDPSocket(std::shared_ptr<FollyQuicEventBase> qEvb)
      : evb_(std::move(qEvb)),
        follySocketPtr(std::make_unique<folly::AsyncUDPSocket>(
            evb_ ? evb_->getBackingEventBase() : nullptr)),
        follySocket_(*follySocketPtr) {
    if (evb_) {
      CHECK_EQ(evb_->getBackingEventBase(), follySocket_.getEventBase());
    }
  }

  [[nodiscard]] folly::Expected<folly::Unit, QuicError> init(
      sa_family_t family) override;

  [[nodiscard]] folly::Expected<folly::Unit, QuicError> bind(
      const folly::SocketAddress& address) override;
  // TODO: bind should return Expected

  [[nodiscard]] bool isBound() const override;

  folly::Expected<folly::Unit, QuicError> connect(
      const folly::SocketAddress& address) override;

  folly::Expected<folly::Unit, QuicError> close() override;

  void resumeRead(ReadCallback* callback) override;
  // TODO: resumeRead should return Expected

  void pauseRead() override;

  ssize_t write(
      const folly::SocketAddress& address,
      const struct iovec* vec,
      size_t iovec_len) override;

  int writem(
      folly::Range<folly::SocketAddress const*> addrs,
      iovec* iov,
      size_t* numIovecsInBuffer,
      size_t count) override;

  ssize_t writeGSO(
      const folly::SocketAddress& address,
      const struct iovec* vec,
      size_t iovec_len,
      WriteOptions options) override;

  /**
   * Send the data in buffers to destination. Returns the return code from
   * ::sendmmsg.
   * bufs is an array of Buf
   * of size num
   * options is an array of WriteOptions or nullptr
   *  Before calling writeGSO with a positive value
   *  verify GSO is supported on this platform by calling getGSO
   */
  int writemGSO(
      folly::Range<folly::SocketAddress const*> addrs,
      const Buf* bufs,
      size_t count,
      const WriteOptions* options) override;

  int writemGSO(
      folly::Range<folly::SocketAddress const*> addrs,
      iovec* iov,
      size_t* numIovecsInBuffer,
      size_t count,
      const WriteOptions* options) override;

  ssize_t recvmsg(struct msghdr* msg, int flags) override;

  int recvmmsg(
      struct mmsghdr* msgvec,
      unsigned int vlen,
      unsigned int flags,
      struct timespec* timeout) override;

  // generic segmentation offload get/set
  // negative return value means GSO is not available
  folly::Expected<int, QuicError> getGSO() override;

  // generic receive offload get/set
  // negative return value means GRO is not available
  folly::Expected<int, QuicError> getGRO() override;
  folly::Expected<folly::Unit, QuicError> setGRO(bool bVal) override;

  // receive tos cmsgs
  // if true, the IPv6 Traffic Class/IPv4 Type of Service field should be
  // populated in OnDataAvailableParams.
  folly::Expected<folly::Unit, QuicError> setRecvTos(bool recvTos) override;
  folly::Expected<bool, QuicError> getRecvTos() override;

  folly::Expected<folly::Unit, QuicError> setTosOrTrafficClass(
      uint8_t tos) override;

  /**
   * Returns the socket address this socket is bound to and error otherwise.
   */
  [[nodiscard]] folly::Expected<folly::SocketAddress, QuicError> address()
      const override;

  /**
   * Returns the socket address this socket is bound to and crashes otherwise.
   */
  [[nodiscard]] virtual const folly::SocketAddress& addressRef() const override;

  /**
   * Manage the eventbase driving this socket
   */
  void attachEventBase(std::shared_ptr<QuicEventBase> evb) override;
  void detachEventBase() override;
  [[nodiscard]] std::shared_ptr<QuicEventBase> getEventBase() const override;

  /**
   * Set extra control messages to send
   */
  folly::Expected<folly::Unit, QuicError> setCmsgs(
      const folly::SocketCmsgMap& cmsgs) override;
  folly::Expected<folly::Unit, QuicError> appendCmsgs(
      const folly::SocketCmsgMap& cmsgs) override;
  folly::Expected<folly::Unit, QuicError> setAdditionalCmsgsFunc(
      folly::Function<Optional<folly::SocketCmsgMap>()>&& additionalCmsgsFunc)
      override;

  /*
   * Packet timestamping is currentl not supported.
   */
  folly::Expected<int, QuicError> getTimestamping() override;

  /**
   * Set SO_REUSEADDR flag on the socket. Default is OFF.
   */
  folly::Expected<folly::Unit, QuicError> setReuseAddr(bool reuseAddr) override;

  /**
   * Set Dont-Fragment (DF) but ignore Path MTU.
   *
   * On Linux, this sets  IP(V6)_MTU_DISCOVER to IP(V6)_PMTUDISC_PROBE.
   * This essentially sets DF but ignores Path MTU for this socket.
   * This may be desirable for apps that has its own PMTU Discovery mechanism.
   * See http://man7.org/linux/man-pages/man7/ip.7.html for more info.
   */
  folly::Expected<folly::Unit, QuicError> setDFAndTurnOffPMTU() override;

  /**
   * Callback for receiving errors on the UDP sockets
   */
  folly::Expected<folly::Unit, QuicError> setErrMessageCallback(
      ErrMessageCallback* /* errMessageCallback */) override;

  folly::Expected<folly::Unit, QuicError> applyOptions(
      const folly::SocketOptionMap& options,
      folly::SocketOptionKey::ApplyPos pos) override;

  /**
   * Set reuse port mode to call bind() on the same address multiple times
   */
  folly::Expected<folly::Unit, QuicError> setReusePort(bool reusePort) override;

  /**
   * Set SO_RCVBUF option on the socket, if not zero. Default is zero.
   */
  folly::Expected<folly::Unit, QuicError> setRcvBuf(int rcvBuf) override;

  /**
   * Set SO_SNDBUF option on the socket, if not zero. Default is zero.
   */
  folly::Expected<folly::Unit, QuicError> setSndBuf(int sndBuf) override;

  /**
   * Use an already bound file descriptor. You can either transfer ownership
   * of this FD by using ownership = FDOwnership::OWNS or share it using
   * FDOwnership::SHARED. In case FD is shared, it will not be `close`d in
   * destructor.
   */
  folly::Expected<folly::Unit, QuicError> setFD(int fd, FDOwnership ownership)
      override;

  int getFD() override;

  folly::AsyncUDPSocket& getFollySocket();

 private:
  class FollyReadCallbackWrapper : public folly::AsyncUDPSocket::ReadCallback {
   public:
    FollyReadCallbackWrapper(
        QuicAsyncUDPSocket::ReadCallback* readCallback,
        FollyQuicAsyncUDPSocket* parentSocket) {
      CHECK(readCallback != nullptr);
      CHECK(parentSocket != nullptr);
      wrappedReadCallback_ = readCallback;
      parentSocket_ = parentSocket;
    }

    void getReadBuffer(void** buf, size_t* len) noexcept override;

    void onDataAvailable(
        const folly::SocketAddress& client,
        size_t len,
        bool truncated,
        folly::AsyncUDPSocket::ReadCallback::OnDataAvailableParams
            params) noexcept override;

    void onNotifyDataAvailable(folly::AsyncUDPSocket& socket) noexcept override;

    bool shouldOnlyNotify() override;

    void onReadError(const folly::AsyncSocketException& ex) noexcept override;

    void onReadClosed() noexcept override;

   private:
    FollyQuicAsyncUDPSocket* parentSocket_ = nullptr;
    QuicAsyncUDPSocket::ReadCallback* wrappedReadCallback_ = nullptr;
  };

  class FollyErrCallbackWrapper
      : public folly::AsyncUDPSocket::ErrMessageCallback {
   public:
    explicit FollyErrCallbackWrapper(
        QuicAsyncUDPSocket::ErrMessageCallback* errorCallback) {
      CHECK(errorCallback != nullptr);
      wrappedErrorCallback_ = errorCallback;
    }

    void errMessage(const cmsghdr& cmsg) noexcept override;

    void errMessageError(
        const folly::AsyncSocketException& ex) noexcept override;

    QuicAsyncUDPSocket::ErrMessageCallback* wrappedErrorCallback_ = nullptr;
  };

  std::shared_ptr<FollyQuicEventBase> evb_{nullptr};

  std::unique_ptr<FollyReadCallbackWrapper> readCallbackWrapper_{nullptr};
  std::unique_ptr<FollyErrCallbackWrapper> errCallbackWrapper_{nullptr};
  std::unique_ptr<folly::AsyncUDPSocket> follySocketPtr;
  folly::AsyncUDPSocket& follySocket_;
};
} // namespace quic
