/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Range.h>
#include <folly/SocketAddress.h>
#include <folly/io/IOBuf.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncSocketException.h>
#include <folly/portability/Sockets.h>
#include <quic/common/QuicEventBase.h>

namespace quic {

using NetworkFdType = int;

class QuicAsyncUDPSocketException : public std::runtime_error {
 public:
  explicit QuicAsyncUDPSocketException(
      const std::string& message,
      int errnoCopy = 0)
      : std::runtime_error(getMessage(message, errnoCopy)), errno_(errnoCopy) {}

  [[nodiscard]] int getErrno() const noexcept {
    return errno_;
  }

 protected:
  static std::string getMessage(const std::string& message, int errnoCopy);

  /** A copy of the errno. */
  int errno_;
};

class QuicAsyncUDPSocketImpl {
 public:
  class ReadCallback {
   public:
    struct OnDataAvailableParams {
      int gro = -1;
      // RX timestamp if available
      using Timestamp = std::array<struct timespec, 3>;
      std::optional<Timestamp> ts;
      uint8_t tos = 0;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
      static constexpr size_t kCmsgSpace = CMSG_SPACE(sizeof(uint16_t)) +
          CMSG_SPACE(sizeof(Timestamp)) + CMSG_SPACE(sizeof(uint8_t));
#endif
    };
    virtual ~ReadCallback() = default;
    virtual void onReadClosed() noexcept = 0;
    virtual void onReadError(const folly::AsyncSocketException&) noexcept = 0;
    virtual void getReadBuffer(void**, size_t*) noexcept = 0;
    virtual void onDataAvailable(
        const folly::SocketAddress&,
        size_t,
        bool,
        OnDataAvailableParams) noexcept = 0;
    virtual bool shouldOnlyNotify() = 0;
    virtual void onNotifyDataAvailable(
        QuicAsyncUDPSocketImpl& sock) noexcept = 0;
  };

  class ErrMessageCallback {
   public:
    virtual ~ErrMessageCallback() = default;
    virtual void errMessage(const cmsghdr&) noexcept = 0;
    virtual void errMessageError(
        const folly::AsyncSocketException&) noexcept = 0;
  };

  static void fromMsg(
      ReadCallback::OnDataAvailableParams& /* params */,
      struct msghdr& /* msg */);

  explicit QuicAsyncUDPSocketImpl(QuicBackingEventBase*);
  virtual ~QuicAsyncUDPSocketImpl();

  // Initializes underlying socket fd. This is called in bind() and connect()
  // internally if fd is not yet set at the time of the call. But if there is a
  // need to apply socket options pre-bind, one can call this function
  // explicitly before bind()/connect() and socket opts application.
  void init(sa_family_t /* family */);

  /**
   * Bind the socket to the following address. If port is not
   * set in the `address` an ephemeral port is chosen and you can
   * use `address()` method above to get it after this method successfully
   * returns.
   */
  void bind(const folly::SocketAddress& address);
  [[nodiscard]] bool isBound() const;

  /**
   * Connects the UDP socket to a remote destination address provided in
   * address. This can speed up UDP writes on linux because it will cache flow
   * state on connects.
   * Using connect has many quirks, and you should be aware of them before using
   * this API:
   * 1. If this is called before bind, the socket will be automatically bound to
   * the IP address of the current default network interface.
   * 2. Normally UDP can use the 2 tuple (src ip, src port) to steer packets
   * sent by the peer to the socket, however after connecting the socket, only
   * packets destined to the destination address specified in connect() will be
   * forwarded and others will be dropped. If the server can send a packet
   * from a different destination port / IP then you probably do not want to use
   * this API.
   * 3. It can be called repeatedly on either the client or server however it's
   * normally only useful on the client and not server.
   *
   * Returns the result of calling the connect syscall.
   */
  void connect(const folly::SocketAddress& /* address */);

  /**
   * Stop listening on the socket.
   */
  void close();

  /**
   * Start reading datagrams
   */
  void resumeRead(ReadCallback* /* cb */);

  /**
   * Pause reading datagrams
   */
  void pauseRead();

  /**
   * Send the data in buffer to destination. Returns the return code from
   * ::sendmsg.
   */
  ssize_t write(
      const folly::SocketAddress& /* address */,
      const std::unique_ptr<folly::IOBuf>& /* buf */);

  /**
   * Send the data in buffers to destination. Returns the return code from
   * ::sendmmsg.
   * bufs is an array of std::unique_ptr<folly::IOBuf>
   * of size num
   */
  int writem(
      folly::Range<folly::SocketAddress const*> /* addrs */,
      const std::unique_ptr<folly::IOBuf>* /* bufs */,
      size_t /* count */);

  ssize_t recvmsg(struct msghdr* /* msg */, int /* flags */);

  int recvmmsg(
      struct mmsghdr* /* msgvec */,
      unsigned int /* vlen */,
      unsigned int /* flags */,
      struct timespec* /* timeout */);

  // generic segmentation offload get/set
  // negative return value means GSO is not available
  int getGSO();

  // generic receive offload get/set
  // negative return value means GRO is not available
  int getGRO();
  bool setGRO(bool /* bVal */);

  /**
   * Returns the socket server is bound to
   */
  [[nodiscard]] const folly::SocketAddress& address() const;

  /**
   * Manage the eventbase driving this socket
   */
  void attachEventBase(QuicBackingEventBase* /* evb */);
  void detachEventBase();
  [[nodiscard]] QuicBackingEventBase* getEventBase() const;

  /**
   * Set extra control messages to send
   */
  void setCmsgs(const folly::SocketCmsgMap& /* cmsgs */);
  void appendCmsgs(const folly::SocketCmsgMap& /* cmsgs */);
  void setAdditionalCmsgsFunc(
      folly::Function<folly::Optional<folly::SocketCmsgMap>()>&&
      /* additionalCmsgsFunc */);

  /*
   * Packet timestamping is currentl not supported.
   */
  int getTimestamping() {
    // Not supported
    return -1;
  }

  /**
   * Set SO_REUSEADDR flag on the socket. Default is OFF.
   */
  void setReuseAddr(bool reuseAddr) {
    reuseAddr_ = reuseAddr;
  }

  /**
   * Set Dont-Fragment (DF) but ignore Path MTU.
   *
   * On Linux, this sets  IP(V6)_MTU_DISCOVER to IP(V6)_PMTUDISC_PROBE.
   * This essentially sets DF but ignores Path MTU for this socket.
   * This may be desirable for apps that has its own PMTU Discovery mechanism.
   * See http://man7.org/linux/man-pages/man7/ip.7.html for more info.
   */
  void setDFAndTurnOffPMTU();

  /**
   * Callback for receiving errors on the UDP sockets
   */
  void setErrMessageCallback(ErrMessageCallback* /* errMessageCallback */);

  void applyOptions(
      const folly::SocketOptionMap& /* options */,
      folly::SocketOptionKey::ApplyPos /* pos */);

  /**
   * Set reuse port mode to call bind() on the same address multiple times
   */
  void setReusePort(bool reusePort) {
    reusePort_ = reusePort;
  }

  enum class FDOwnership { OWNS, SHARED };

  /**
   * Use an already bound file descriptor. You can either transfer ownership
   * of this FD by using ownership = FDOwnership::OWNS or share it using
   * FDOwnership::SHARED. In case FD is shared, it will not be `close`d in
   * destructor.
   */
  void setFD(NetworkFdType /* fd */, FDOwnership /* ownership */);

 private:
  static void readWatcherCallback(struct ev_loop* loop, ev_io* w, int revents);

  void updateReadWatcher();
  void evHandleSocketRead();

  NetworkFdType fd_{-1};
  folly::SocketAddress localAddress_;
  folly::SocketAddress connectedAddress_;
  FDOwnership ownership_;

  QuicLibevEventBase* eventBase_{nullptr};
  ev_io readWatcher_;

  bool bound_{false};
  bool connected_{false};
  bool useGro_{false};
  bool reuseAddr_{false};
  bool reusePort_{false};

  ReadCallback* readCallback_{nullptr};
  ErrMessageCallback* errMessageCallback_ = nullptr;
};
} // namespace quic
