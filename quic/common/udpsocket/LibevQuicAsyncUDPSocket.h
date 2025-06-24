/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Expected.h>
#include <quic/QuicException.h> // For QuicError
#include <quic/common/NetworkData.h>
#include <quic/common/events/LibevQuicEventBase.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocketImpl.h>

namespace quic {

class LibevQuicAsyncUDPSocket : public QuicAsyncUDPSocketImpl {
 public:
  socklen_t kAddrLen = sizeof(sockaddr_storage);

  explicit LibevQuicAsyncUDPSocket(std::shared_ptr<LibevQuicEventBase> qEvb);
  ~LibevQuicAsyncUDPSocket() override;
  [[nodiscard]] folly::Expected<folly::Unit, QuicError> init(
      sa_family_t family) override;

  [[nodiscard]] folly::Expected<folly::Unit, QuicError> bind(
      const folly::SocketAddress& address) override;

  [[nodiscard]] bool isBound() const override;

  folly::Expected<folly::Unit, QuicError> connect(
      const folly::SocketAddress& address) override;

  folly::Expected<folly::Unit, QuicError> close() override;

  void resumeRead(ReadCallback* callback) override;
  // TODO: resumeRead should return Expected

  void pauseRead() override;

  [[nodiscard]] bool isReadPaused() const override;

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
      const folly::SocketAddress& /*address*/,
      const struct iovec* /* vec */,
      size_t /* iovec_len */,
      WriteOptions /*options*/) override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicAsyncUDPSocket";
  }

  /**
   * Send the data in buffers to destination. Returns the return code from
   * ::sendmmsg.
   * bufs is an array of BufPtr
   * of size num
   * options is an array of WriteOptions or nullptr
   *  Before calling writeGSO with a positive value
   *  verify GSO is supported on this platform by calling getGSO
   */
  int writemGSO(
      folly::Range<folly::SocketAddress const*> /*addrs*/,
      const BufPtr* /*bufs*/,
      size_t /*count*/,
      const WriteOptions* /*options*/) override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicAsyncUDPSocket";
  }

  int writemGSO(
      folly::Range<folly::SocketAddress const*> /* addrs */,
      iovec* /* iov */,
      size_t* /* numIovecsInBuffer */,
      size_t /* count */,
      const WriteOptions* /* options */) override {
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
  folly::Expected<int, QuicError> getGSO() override;

  // generic receive offload get/set
  // negative return value means GRO is not available
  folly::Expected<int, QuicError> getGRO() override;
  folly::Expected<folly::Unit, QuicError> setGRO(bool bVal) override;

  // receive tos cmsgs
  // if true, the IPv6 Traffic Class/IPv4 Type of Service field should be
  // populated in OnDataAvailableParams.
  folly::Expected<folly::Unit, QuicError> setRecvTos(
      bool /*recvTos*/) override {
    LOG(WARNING) << __func__ << " not implemented in LibevQuicAsyncUDPSocket";
    return folly::unit; // Or return error if strictness needed
  }

  folly::Expected<bool, QuicError> getRecvTos() override {
    return false; // Not implemented, return default/false
  }

  folly::Expected<folly::Unit, QuicError> setTosOrTrafficClass(
      uint8_t /*tos*/) override {
    LOG(WARNING) << __func__ << " not implemented in LibevQuicAsyncUDPSocket";
    return folly::unit; // Or return error if strictness needed
  }

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
      std::function<Optional<folly::SocketCmsgMap>()>&& additionalCmsgsFunc)
      override;

  /*
   * Packet timestamping is currently not supported.
   */
  folly::Expected<int, QuicError> getTimestamping() override {
    return -1; // Keep returning -1 for not supported
  }

  /**
   * Set SO_REUSEADDR flag on the socket. Default is OFF.
   */
  folly::Expected<folly::Unit, QuicError> setReuseAddr(bool reuseAddr) override;

  /**
   * Set SO_RCVBUF option on the socket, if not zero. Default is zero.
   */
  folly::Expected<folly::Unit, QuicError> setRcvBuf(int rcvBuf) override;

  /**
   * Set SO_SNDBUF option on the socket, if not zero. Default is zero.
   */
  folly::Expected<folly::Unit, QuicError> setSndBuf(int sndBuf) override;
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
  folly::Expected<folly::Unit, QuicError> setReusePort(bool) override {
    LOG(FATAL) << __func__ << " not implemented in LibevQuicAsyncUDPSocket";
    // Return success as it's just a warning, or error if strictness needed
    return folly::unit;
  }

  /**
   * Use an already bound file descriptor. You can either transfer ownership
   * of this FD by using ownership = FDOwnership::OWNS or share it using
   * FDOwnership::SHARED. In case FD is shared, it will not be `close`d in
   * destructor.
   */
  folly::Expected<folly::Unit, QuicError> setFD(int fd, FDOwnership ownership)
      override;

  int getFD() override;

  /**
   * Start listening to writable events on the socket.
   */
  folly::Expected<folly::Unit, QuicError> resumeWrite(
      WriteCallback* /* cob */) override;

  /**
   * Pause writable events.
   */
  void pauseWrite() override;

  [[nodiscard]] bool isWritableCallbackSet() const override;

 private:
  static void
  sockEventsWatcherCallback(struct ev_loop* loop, ev_io* w, int revents);

  void addEvent(int event);
  void removeEvent(int event);
  void evHandleSocketRead();
  void evHandleSocketWritable();
  size_t handleSocketErrors();

  int fd_{-1};
  folly::SocketAddress localAddress_;
  folly::SocketAddress connectedAddress_;
  FDOwnership ownership_;

  std::shared_ptr<LibevQuicEventBase> evb_{nullptr};
  ev_io readWatcher_;
  ev_io writeWatcher_;

  bool bound_{false};
  bool connected_{false};
  bool reuseAddr_{false};
  bool reusePort_{false};
  int rcvBuf_{0};
  int sndBuf_{0};

  ReadCallback* readCallback_{nullptr};
  WriteCallback* writeCallback_{nullptr};
  ErrMessageCallback* errMessageCallback_{nullptr};
};
} // namespace quic
