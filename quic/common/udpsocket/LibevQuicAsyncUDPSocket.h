/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/NetworkData.h>
#include <quic/common/events/LibevQuicEventBase.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocketImpl.h>

namespace quic {

class LibevQuicAsyncUDPSocket : public QuicAsyncUDPSocketImpl {
 public:
  socklen_t kAddrLen = sizeof(sockaddr_storage);

  explicit LibevQuicAsyncUDPSocket(std::shared_ptr<LibevQuicEventBase> qEvb);
  ~LibevQuicAsyncUDPSocket() override;

  void init(sa_family_t family) override;

  void bind(const folly::SocketAddress& address) override;

  [[nodiscard]] bool isBound() const override;

  void connect(const folly::SocketAddress& address) override;

  void close() override;

  void resumeRead(ReadCallback* callback) override;

  void pauseRead() override;

  ssize_t write(
      const folly::SocketAddress& address,
      const std::unique_ptr<folly::IOBuf>& buf) override;

  int writem(
      folly::Range<folly::SocketAddress const*> addrs,
      const std::unique_ptr<folly::IOBuf>* bufs,
      size_t count) override;

  ssize_t writeGSO(
      const folly::SocketAddress& /*address*/,
      const std::unique_ptr<folly::IOBuf>& /*buf*/,
      WriteOptions /*options*/) override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicAsyncUDPSocket";
  }

  /**
   * Send the data in buffers to destination. Returns the return code from
   * ::sendmmsg.
   * bufs is an array of std::unique_ptr<folly::IOBuf>
   * of size num
   * options is an array of WriteOptions or nullptr
   *  Before calling writeGSO with a positive value
   *  verify GSO is supported on this platform by calling getGSO
   */
  int writemGSO(
      folly::Range<folly::SocketAddress const*> /*addrs*/,
      const std::unique_ptr<folly::IOBuf>* /*bufs*/,
      size_t /*count*/,
      const WriteOptions* /*options*/) override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicAsyncUDPSocket";
  }

  ssize_t recvmsg(struct msghdr* msg, int flags) override;

  int recvmmsg(
      struct mmsghdr* msgvec,
      unsigned int vlen,
      unsigned int flags,
      struct timespec* timeout) override;

  // generic segmentation offload get/set
  // negative return value means GSO is not available
  int getGSO() override;

  // generic receive offload get/set
  // negative return value means GRO is not available
  int getGRO() override;
  bool setGRO(bool bVal) override;

  // receive tos cmsgs
  // if true, the IPv6 Traffic Class/IPv4 Type of Service field should be
  // populated in OnDataAvailableParams.
  void setRecvTos(bool /*recvTos*/) override {
    LOG(WARNING) << __func__ << " not implemented in LibevQuicAsyncUDPSocket";
  }

  bool getRecvTos() override {
    return false;
  }

  void setTosOrTrafficClass(uint8_t /*tos*/) override {
    LOG(WARNING) << __func__ << " not implemented in LibevQuicAsyncUDPSocket";
  }

  /**
   * Returns the socket server is bound to
   */
  [[nodiscard]] const folly::SocketAddress& address() const override;

  /**
   * Manage the eventbase driving this socket
   */
  void attachEventBase(std::shared_ptr<QuicEventBase> evb) override;
  void detachEventBase() override;
  [[nodiscard]] std::shared_ptr<QuicEventBase> getEventBase() const override;

  /**
   * Set extra control messages to send
   */
  void setCmsgs(const folly::SocketCmsgMap& cmsgs) override;
  void appendCmsgs(const folly::SocketCmsgMap& cmsgs) override;
  void setAdditionalCmsgsFunc(
      folly::Function<folly::Optional<folly::SocketCmsgMap>()>&&
          additionalCmsgsFunc) override;

  /*
   * Packet timestamping is currently not supported.
   */
  int getTimestamping() override {
    return -1;
  }

  /**
   * Set SO_REUSEADDR flag on the socket. Default is OFF.
   */
  void setReuseAddr(bool /*reuseAddr*/) override {
    LOG(WARNING) << __func__ << " not implemented in LibevQuicAsyncUDPSocket";
  }

  /**
   * Set SO_RCVBUF option on the socket, if not zero. Default is zero.
   */
  void setRcvBuf(int rcvBuf) override;

  /**
   * Set SO_SNDBUF option on the socket, if not zero. Default is zero.
   */
  void setSndBuf(int sndBuf) override;
  /**
   * Set Dont-Fragment (DF) but ignore Path MTU.
   *
   * On Linux, this sets  IP(V6)_MTU_DISCOVER to IP(V6)_PMTUDISC_PROBE.
   * This essentially sets DF but ignores Path MTU for this socket.
   * This may be desirable for apps that has its own PMTU Discovery mechanism.
   * See http://man7.org/linux/man-pages/man7/ip.7.html for more info.
   */
  void setDFAndTurnOffPMTU() override;

  /**
   * Callback for receiving errors on the UDP sockets
   */
  void setErrMessageCallback(
      ErrMessageCallback* /* errMessageCallback */) override;

  void applyOptions(
      const folly::SocketOptionMap& options,
      folly::SocketOptionKey::ApplyPos pos) override;

  /**
   * Set reuse port mode to call bind() on the same address multiple times
   */
  void setReusePort(bool /*reusePort*/) override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicAsyncUDPSocket";
  }

  /**
   * Use an already bound file descriptor. You can either transfer ownership
   * of this FD by using ownership = FDOwnership::OWNS or share it using
   * FDOwnership::SHARED. In case FD is shared, it will not be `close`d in
   * destructor.
   */
  void setFD(int fd, FDOwnership ownership) override;

  int getFD() override;

 private:
  static void readWatcherCallback(struct ev_loop* loop, ev_io* w, int revents);

  void updateReadWatcher();
  void evHandleSocketRead();
  size_t handleSocketErrors();

  int fd_{-1};
  folly::SocketAddress localAddress_;
  folly::SocketAddress connectedAddress_;
  FDOwnership ownership_;

  std::shared_ptr<LibevQuicEventBase> evb_{nullptr};
  ev_io readWatcher_;

  bool bound_{false};
  bool connected_{false};
  bool reuseAddr_{false};
  bool reusePort_{false};
  int rcvBuf_{0};
  int sndBuf_{0};

  ReadCallback* readCallback_{nullptr};
  ErrMessageCallback* errMessageCallback_{nullptr};
};
} // namespace quic
