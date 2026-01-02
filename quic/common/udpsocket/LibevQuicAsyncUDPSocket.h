/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicException.h>
#include <quic/common/Expected.h>
#include <quic/common/MvfstLogging.h> // For QuicError
#include <quic/common/NetworkData.h>
#include <quic/common/events/LibevQuicEventBase.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocketImpl.h>

namespace quic {

class LibevQuicAsyncUDPSocket : public QuicAsyncUDPSocketImpl {
 public:
  socklen_t kAddrLen = sizeof(sockaddr_storage);

  explicit LibevQuicAsyncUDPSocket(std::shared_ptr<LibevQuicEventBase> qEvb);
  ~LibevQuicAsyncUDPSocket() override;
  [[nodiscard]] quic::Expected<void, QuicError> init(
      sa_family_t family) override;

  [[nodiscard]] quic::Expected<void, QuicError> bind(
      const folly::SocketAddress& address) override;

  [[nodiscard]] bool isBound() const override;

  quic::Expected<void, QuicError> connect(
      const folly::SocketAddress& address) override;

  quic::Expected<void, QuicError> close() override;

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
    MVLOG_FATAL << __func__ << " not supported in LibevQuicAsyncUDPSocket";
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
    MVLOG_FATAL << __func__ << " not supported in LibevQuicAsyncUDPSocket";
  }

  int writemGSO(
      folly::Range<folly::SocketAddress const*> /* addrs */,
      iovec* /* iov */,
      size_t* /* numIovecsInBuffer */,
      size_t /* count */,
      const WriteOptions* /* options */) override {
    MVLOG_FATAL << __func__ << " not supported in LibevQuicAsyncUDPSocket";
  }

  ssize_t recvmsg(struct msghdr* msg, int flags) override;

  int recvmmsg(
      struct mmsghdr* msgvec,
      unsigned int vlen,
      unsigned int flags,
      struct timespec* timeout) override;

  // generic segmentation offload get/set
  // negative return value means GSO is not available
  quic::Expected<int, QuicError> getGSO() override;

  // generic receive offload get/set
  // negative return value means GRO is not available
  quic::Expected<int, QuicError> getGRO() override;
  quic::Expected<void, QuicError> setGRO(bool bVal) override;

  // receive tos cmsgs
  // if true, the IPv6 Traffic Class/IPv4 Type of Service field should be
  // populated in OnDataAvailableParams.
  quic::Expected<void, QuicError> setRecvTos(bool /*recvTos*/) override {
    MVLOG_WARNING << __func__ << " not implemented in LibevQuicAsyncUDPSocket";
    return {}; // Or return error if strictness needed
  }

  quic::Expected<bool, QuicError> getRecvTos() override {
    return false; // Not implemented, return default/false
  }

  quic::Expected<void, QuicError> setTosOrTrafficClass(
      uint8_t /*tos*/) override {
    MVLOG_WARNING << __func__ << " not implemented in LibevQuicAsyncUDPSocket";
    return {}; // Or return error if strictness needed
  }

  /**
   * Returns the socket address this socket is bound to and error otherwise.
   */
  [[nodiscard]] quic::Expected<folly::SocketAddress, QuicError> address()
      const override;

  /**
   * Returns the socket address this socket is bound to and crashes otherwise.
   */
  [[nodiscard]] const folly::SocketAddress& addressRef() const override;

  /**
   * Manage the eventbase driving this socket
   */
  void attachEventBase(std::shared_ptr<QuicEventBase> evb) override;
  void detachEventBase() override;
  [[nodiscard]] std::shared_ptr<QuicEventBase> getEventBase() const override;

  /**
   * Set extra control messages to send
   */
  quic::Expected<void, QuicError> setCmsgs(
      const folly::SocketCmsgMap& cmsgs) override;
  quic::Expected<void, QuicError> appendCmsgs(
      const folly::SocketCmsgMap& cmsgs) override;
  quic::Expected<void, QuicError> setAdditionalCmsgsFunc(
      std::function<Optional<folly::SocketCmsgMap>()>&& additionalCmsgsFunc)
      override;

  /*
   * Packet timestamping is currently not supported.
   */
  quic::Expected<int, QuicError> getTimestamping() override {
    return -1; // Keep returning -1 for not supported
  }

  /**
   * Set SO_REUSEADDR flag on the socket. Default is OFF.
   */
  quic::Expected<void, QuicError> setReuseAddr(bool reuseAddr) override;

  /**
   * Set SO_RCVBUF option on the socket, if not zero. Default is zero.
   */
  quic::Expected<void, QuicError> setRcvBuf(int rcvBuf) override;

  /**
   * Set SO_SNDBUF option on the socket, if not zero. Default is zero.
   */
  quic::Expected<void, QuicError> setSndBuf(int sndBuf) override;
  /**
   * Set Dont-Fragment (DF) but ignore Path MTU.
   *
   * On Linux, this sets  IP(V6)_MTU_DISCOVER to IP(V6)_PMTUDISC_PROBE.
   * This essentially sets DF but ignores Path MTU for this socket.
   * This may be desirable for apps that has its own PMTU Discovery mechanism.
   * See http://man7.org/linux/man-pages/man7/ip.7.html for more info.
   */
  quic::Expected<void, QuicError> setDFAndTurnOffPMTU() override;

  /**
   * Callback for receiving errors on the UDP sockets
   */
  quic::Expected<void, QuicError> setErrMessageCallback(
      ErrMessageCallback* /* errMessageCallback */) override;

  quic::Expected<void, QuicError> applyOptions(
      const folly::SocketOptionMap& options,
      folly::SocketOptionKey::ApplyPos pos) override;

  /**
   * Set reuse port mode to call bind() on the same address multiple times
   */
  quic::Expected<void, QuicError> setReusePort(bool) override {
    MVLOG_FATAL << __func__ << " not implemented in LibevQuicAsyncUDPSocket";
    // Return success as it's just a warning, or error if strictness needed
    return {};
  }

  /**
   * Use an already bound file descriptor. You can either transfer ownership
   * of this FD by using ownership = FDOwnership::OWNS or share it using
   * FDOwnership::SHARED. In case FD is shared, it will not be `close`d in
   * destructor.
   */
  quic::Expected<void, QuicError> setFD(int fd, FDOwnership ownership) override;

  int getFD() override;

  /**
   * Start listening to writable events on the socket.
   */
  quic::Expected<void, QuicError> resumeWrite(
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
