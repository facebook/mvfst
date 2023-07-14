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
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/portability/Sockets.h>
#include <quic/common/Events.h>

namespace quic {

#ifdef MVFST_USE_LIBEV
using NetworkFdType = int;
class QuicAsyncUDPSocketType {
 public:
  explicit QuicAsyncUDPSocketType(QuicBackingEventBase*) {}
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
        QuicAsyncUDPSocketType& sock) noexcept = 0;
  };

  class ErrMessageCallback {
   public:
    virtual ~ErrMessageCallback() = default;
    virtual void errMessage(const cmsghdr&) noexcept = 0;
    virtual void errMessageError(
        const folly::AsyncSocketException&) noexcept = 0;
  };

  struct BindOptions {
    BindOptions() noexcept {}
    // Whether IPV6_ONLY should be set on the socket.
    bool bindV6Only{true};
    std::string ifName;
  };

  void pauseRead() {}

  void resumeRead(ReadCallback* /* cb */) {}

  ssize_t write(
      const folly::SocketAddress& /* address */,
      const std::unique_ptr<folly::IOBuf>& /* buf */) {
    return -1;
  }

  int getGSO() {
    return -1;
  }

  int writem(
      folly::Range<folly::SocketAddress const*> /* addrs */,
      const std::unique_ptr<folly::IOBuf>* /* bufs */,
      size_t /* count */) {
    return -1;
  }

  void setAdditionalCmsgsFunc(
      folly::Function<folly::Optional<folly::SocketOptionMap>()>&&
      /* additionalCmsgsFunc */) {}

  bool isBound() const {
    return false;
  }

  const folly::SocketAddress& address() const {
    return address_;
  }

  void attachEventBase(QuicBackingEventBase* /* evb */) {}

  void close() {}

  void detachEventBase() {}

  void setCmsgs(const folly::SocketOptionMap& /* cmsgs */) {}

  void appendCmsgs(const folly::SocketOptionMap& /* cmsgs */) {}

  int getTimestamping() {
    return -1;
  }

  void setReuseAddr(bool /* reuseAddr */) {}

  void init(sa_family_t /* family */) {}

  void bind(
      const folly::SocketAddress& /* address */,
      BindOptions /* bindOptions */ = BindOptions()) {}

  void connect(const folly::SocketAddress& /* address */) {}

  void setDFAndTurnOffPMTU() {}

  void setErrMessageCallback(ErrMessageCallback* /* errMessageCallback */) {}

  int getGRO() {
    return -1;
  }

  ssize_t recvmsg(struct msghdr* /* msg */, int /* flags */) {
    return -1;
  }

  static void fromMsg(
      ReadCallback::OnDataAvailableParams& /* params */,
      struct msghdr& /* msg */) {}

  int recvmmsg(
      struct mmsghdr* /* msgvec */,
      unsigned int /* vlen */,
      unsigned int /* flags */,
      struct timespec* /* timeout */) {
    return -1;
  }

  bool setGRO(bool /* bVal */) {
    return false;
  }

  void applyOptions(
      const folly::SocketOptionMap& /* options */,
      folly::SocketOptionKey::ApplyPos /* pos */) {}

  QuicBackingEventBase* getEventBase() const {
    return nullptr;
  }

  void setReusePort(bool /* reusePort */) {}

  enum class FDOwnership { OWNS, SHARED };
  void setFD(NetworkFdType /* fd */, FDOwnership /* ownership */) {}

 private:
  folly::SocketAddress address_;
};
#else
using QuicAsyncUDPSocketType = folly::AsyncUDPSocket;
using NetworkFdType = folly::NetworkSocket;
#endif

int getSocketFd(const QuicAsyncUDPSocketType& s);
NetworkFdType toNetworkFdType(int fd);

class QuicAsyncUDPSocketWrapper {
 public:
  using ReadCallback = QuicAsyncUDPSocketType::ReadCallback;
  using ErrMessageCallback = QuicAsyncUDPSocketType::ErrMessageCallback;
};

} // namespace quic
