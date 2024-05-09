/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <type_traits>

#include <folly/Range.h>
#include <folly/SocketAddress.h>
#include <folly/io/IOBuf.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncSocketException.h>
#include <folly/portability/Sockets.h>

#include <quic/common/NetworkData.h>
#include <quic/common/events/QuicEventBase.h>

namespace quic {

/**
 * QuicAsyncUDPSocket is an abstract class that represents an UDP socket that
 * can be used by the QuicTransport (currently QuicTransportBase and
 * QuicClientTransport).
 *
 * Functions that contain behavior that will be common to all implementations is
 * implemented in QuicAsyncUDPSocketImpl.
 *
 * Two implementations of QuicAsyncUDPSocket are provided:
 *  - FollyQuicAsyncUDPSocket which wraps a folly::AsyncUDPSocket
 *  - LibevQuicAsyncUDPSocket which wraps a plain libc socket.
 */
class QuicAsyncUDPSocket {
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
    virtual void onNotifyDataAvailable(QuicAsyncUDPSocket& sock) noexcept = 0;
  };

  class ErrMessageCallback {
   public:
    virtual ~ErrMessageCallback() = default;
    virtual void errMessage(const cmsghdr&) noexcept = 0;
    virtual void errMessageError(
        const folly::AsyncSocketException&) noexcept = 0;
  };

  virtual ~QuicAsyncUDPSocket() = default;

  // Initializes underlying socket fd. This is called in bind() and connect()
  // internally if fd is not yet set at the time of the call. But if there is a
  // need to apply socket options pre-bind, one can call this function
  // explicitly before bind()/connect() and socket opts application.
  virtual void init(sa_family_t /* family */) = 0;

  /**
   * Bind the socket to the following address. If port is not
   * set in the `address` an ephemeral port is chosen and you can
   * use `address()` method above to get it after this method successfully
   * returns.
   */
  virtual void bind(const folly::SocketAddress& address) = 0;
  [[nodiscard]] virtual bool isBound() const = 0;

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
  virtual void connect(const folly::SocketAddress& /* address */) = 0;

  /**
   * Stop listening on the socket.
   */
  virtual void close() = 0;

  /**
   * Start reading datagrams
   */
  virtual void resumeRead(ReadCallback* /* cb */) = 0;

  /**
   * Pause reading datagrams
   */
  virtual void pauseRead() = 0;

  /**
   * Send the data in buffer to destination. Returns the return code from
   * ::sendmsg.
   */
  virtual ssize_t write(
      const folly::SocketAddress& /* address */,
      const std::unique_ptr<folly::IOBuf>& /* buf */) = 0;

  /**
   * Send the data in buffers to destination. Returns the return code from
   * ::sendmmsg.
   * bufs is an array of std::unique_ptr<folly::IOBuf>
   * of size num
   */
  virtual int writem(
      folly::Range<folly::SocketAddress const*> /* addrs */,
      const std::unique_ptr<folly::IOBuf>* /* bufs */,
      size_t /* count */) = 0;

  struct WriteOptions {
    WriteOptions() = default;
    WriteOptions(int gsoVal, bool zerocopyVal)
        : gso(gsoVal), zerocopy(zerocopyVal) {}
    int gso{0};
    bool zerocopy{false};
    std::chrono::microseconds txTime{0};
  };

  /**
   * Send the data in buffer to destination. Returns the return code from
   * ::sendmsg.
   *  gso is the generic segmentation offload value
   *  writeGSO will return -1 if
   *  buf->computeChainDataLength() <= gso
   *  Before calling writeGSO with a positive value
   *  verify GSO is supported on this platform by calling getGSO
   */
  virtual ssize_t writeGSO(
      const folly::SocketAddress& address,
      const std::unique_ptr<folly::IOBuf>& buf,
      WriteOptions options) = 0;

  /**
   * Send the data in buffers to destination. Returns the return code from
   * ::sendmmsg.
   * bufs is an array of std::unique_ptr<folly::IOBuf>
   * of size num
   * options is an array of WriteOptions or nullptr
   *  Before calling writeGSO with a positive value
   *  verify GSO is supported on this platform by calling getGSO
   */
  virtual int writemGSO(
      folly::Range<folly::SocketAddress const*> addrs,
      const std::unique_ptr<folly::IOBuf>* bufs,
      size_t count,
      const WriteOptions* options) = 0;

  virtual ssize_t recvmsg(struct msghdr* /* msg */, int /* flags */) = 0;

  virtual int recvmmsg(
      struct mmsghdr* /* msgvec */,
      unsigned int /* vlen */,
      unsigned int /* flags */,
      struct timespec* /* timeout */) = 0;

  /**
   * recv() result structure.
   */
  struct RecvResult {
    RecvResult() = default;
    explicit RecvResult(NoReadReason noReadReason)
        : maybeNoReadReason(noReadReason) {}

    folly::Optional<NoReadReason> maybeNoReadReason;
  };

  virtual RecvResult recvmmsgNetworkData(
      uint64_t readBufferSize,
      uint16_t numPackets,
      NetworkData& networkData,
      folly::Optional<folly::SocketAddress>& peerAddress,
      size_t& totalData) = 0;

  // generic segmentation offload get/set
  // negative return value means GSO is not available
  virtual int getGSO() = 0;

  // generic receive offload get/set
  // negative return value means GRO is not available
  virtual int getGRO() = 0;
  virtual bool setGRO(bool /* bVal */) = 0;

  // receive tos cmsgs
  // if true, the IPv6 Traffic Class/IPv4 Type of Service field should be
  // populated in OnDataAvailableParams.
  virtual void setRecvTos(bool recvTos) = 0;
  virtual bool getRecvTos() = 0;

  virtual void setTosOrTrafficClass(uint8_t tos) = 0;

  /**
   * Returns the socket server is bound to
   */
  [[nodiscard]] virtual const folly::SocketAddress& address() const = 0;

  /**
   * Manage the eventbase driving this socket
   */
  virtual void attachEventBase(std::shared_ptr<QuicEventBase> /* evb */) = 0;
  virtual void detachEventBase() = 0;
  [[nodiscard]] virtual std::shared_ptr<QuicEventBase> getEventBase() const = 0;

  /**
   * Set extra control messages to send
   */
  virtual void setCmsgs(const folly::SocketCmsgMap& /* cmsgs */) = 0;
  virtual void appendCmsgs(const folly::SocketCmsgMap& /* cmsgs */) = 0;
  virtual void setAdditionalCmsgsFunc(
      folly::Function<folly::Optional<folly::SocketCmsgMap>()>&&
      /* additionalCmsgsFunc */) = 0;

  /*
   * Packet timestamping is currentl not supported.
   */
  virtual int getTimestamping() = 0;

  /**
   * Set SO_REUSEADDR flag on the socket. Default is OFF.
   */
  virtual void setReuseAddr(bool reuseAddr) = 0;

  /**
   * Set Dont-Fragment (DF) but ignore Path MTU.
   *
   * On Linux, this sets  IP(V6)_MTU_DISCOVER to IP(V6)_PMTUDISC_PROBE.
   * This essentially sets DF but ignores Path MTU for this socket.
   * This may be desirable for apps that has its own PMTU Discovery mechanism.
   * See http://man7.org/linux/man-pages/man7/ip.7.html for more info.
   */
  virtual void setDFAndTurnOffPMTU() = 0;

  /**
   * Callback for receiving errors on the UDP sockets
   */
  virtual void setErrMessageCallback(
      ErrMessageCallback* /* errMessageCallback */) = 0;

  virtual void applyOptions(
      const folly::SocketOptionMap& /* options */,
      folly::SocketOptionKey::ApplyPos /* pos */) = 0;

  /**
   * Set reuse port mode to call bind() on the same address multiple times
   */
  virtual void setReusePort(bool reusePort) = 0;

  /**
   * Set SO_RCVBUF option on the socket, if not zero. Default is zero.
   */
  virtual void setRcvBuf(int rcvBuf) = 0;

  /**
   * Set SO_SNDBUF option on the socket, if not zero. Default is zero.
   */
  virtual void setSndBuf(int sndBuf) = 0;

  enum class FDOwnership { OWNS, SHARED };

  /**
   * Use an already bound file descriptor. You can either transfer ownership
   * of this FD by using ownership = FDOwnership::OWNS or share it using
   * FDOwnership::SHARED. In case FD is shared, it will not be `close`d in
   * destructor.
   */
  virtual void setFD(int /* fd */, FDOwnership /* ownership */) = 0;

  virtual int getFD() = 0;

  template <
      typename T,
      typename = std::enable_if_t<std::is_base_of_v<QuicAsyncUDPSocket, T>>>
  T* getTypedSocket() const;

  static void fromMsg(
      [[maybe_unused]] ReadCallback::OnDataAvailableParams& params,
      [[maybe_unused]] struct msghdr& msg);
};
} // namespace quic
