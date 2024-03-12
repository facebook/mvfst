/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/udpsocket/LibevQuicAsyncUDPSocket.h>

#include <cstring>

#include <stdexcept>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace quic {

LibevQuicAsyncUDPSocket::LibevQuicAsyncUDPSocket(
    std::shared_ptr<LibevQuicEventBase> evb) {
  evb_ = evb;
  CHECK(evb_) << "EventBase must be QuicLibevEventBase";
  CHECK(evb_->isInEventBaseThread());

  ev_init(&readWatcher_, LibevQuicAsyncUDPSocket::readWatcherCallback);
  readWatcher_.data = this;
}

LibevQuicAsyncUDPSocket::~LibevQuicAsyncUDPSocket() {
  if (fd_ != -1) {
    LibevQuicAsyncUDPSocket::close();
  }
  if (evb_) {
    ev_io_stop(evb_->getLibevLoop(), &readWatcher_);
  }
}

void LibevQuicAsyncUDPSocket::pauseRead() {
  readCallback_ = nullptr;

  updateReadWatcher();
}

void LibevQuicAsyncUDPSocket::resumeRead(ReadCallback* cb) {
  CHECK(!readCallback_) << "A read callback is already installed";
  CHECK_NE(fd_, -1)
      << "Socket must be initialized before a read callback is attached";
  CHECK(cb) << "A non-null callback is required to resume read";
  readCallback_ = cb;

  updateReadWatcher();
}

ssize_t LibevQuicAsyncUDPSocket::write(
    const folly::SocketAddress& address,
    const std::unique_ptr<folly::IOBuf>& buf) {
  if (fd_ == -1) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::NOT_OPEN, "socket is not initialized");
  }
  sockaddr_storage addrStorage;
  address.getAddress(&addrStorage);
  int msg_flags = 0;
  struct msghdr msg;

  if (!connected_) {
    msg.msg_name = reinterpret_cast<void*>(&addrStorage);
    msg.msg_namelen = address.getActualSize();
  } else {
    if (connectedAddress_ != address) {
      throw folly::AsyncSocketException(
          folly::AsyncSocketException::BAD_ARGS,
          "wrong destination address for connected socket");
    }
    msg.msg_name = nullptr;
    msg.msg_namelen = 0;
  }

  iovec vec[16];
  size_t iovec_len = buf->fillIov(vec, sizeof(vec) / sizeof(vec[0])).numIovecs;
  if (UNLIKELY(iovec_len == 0)) {
    buf->coalesce();
    vec[0].iov_base = const_cast<uint8_t*>(buf->data());
    vec[0].iov_len = buf->length();
    iovec_len = 1;
  }

  msg.msg_iov = const_cast<struct iovec*>(vec);
  msg.msg_iovlen = iovec_len;
  msg.msg_control = nullptr;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  return ::sendmsg(fd_, &msg, msg_flags);
}

int LibevQuicAsyncUDPSocket::getGSO() {
  // TODO: Implement GSO
  return -1;
}

int LibevQuicAsyncUDPSocket::writem(
    folly::Range<folly::SocketAddress const*> /* addrs */,
    const std::unique_ptr<folly::IOBuf>* /* bufs */,
    size_t /* count */) {
  LOG(FATAL) << __func__ << "is not implemented in LibevQuicAsyncUDPSocket";
  return -1;
}

void LibevQuicAsyncUDPSocket::setAdditionalCmsgsFunc(
    folly::Function<folly::Optional<folly::SocketCmsgMap>()>&&
    /* additionalCmsgsFunc */) {
  LOG(WARNING)
      << "Setting an additional cmsgs function is not implemented for LibevQuicAsyncUDPSocket";
}

bool LibevQuicAsyncUDPSocket::isBound() const {
  return bound_;
}

const folly::SocketAddress& LibevQuicAsyncUDPSocket::address() const {
  if (!bound_) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::NOT_OPEN, "socket is not bound");
  }
  return localAddress_;
}

void LibevQuicAsyncUDPSocket::attachEventBase(
    std::shared_ptr<QuicEventBase> /* evb */) {
  LOG(FATAL) << __func__ << "is not implemented in LibevQuicAsyncUDPSocket";
}

[[nodiscard]] std::shared_ptr<QuicEventBase>
LibevQuicAsyncUDPSocket::getEventBase() const {
  return evb_;
}

void LibevQuicAsyncUDPSocket::close() {
  CHECK(evb_->isInEventBaseThread());

  if (readCallback_) {
    auto cob = readCallback_;
    readCallback_ = nullptr;

    cob->onReadClosed();
  }

  updateReadWatcher();

  if (fd_ != -1 && ownership_ == FDOwnership::OWNS) {
    ::close(fd_);
  }

  fd_ = -1;
}

void LibevQuicAsyncUDPSocket::detachEventBase() {
  LOG(FATAL) << __func__ << "is not implemented in LibevQuicAsyncUDPSocket";
}

void LibevQuicAsyncUDPSocket::setCmsgs(
    const folly::SocketCmsgMap& /* cmsgs */) {
  throw std::runtime_error("setCmsgs is not implemented.");
}

void LibevQuicAsyncUDPSocket::appendCmsgs(
    const folly::SocketCmsgMap& /* cmsgs */) {
  throw std::runtime_error("appendCmsgs is not implemented.");
}

void LibevQuicAsyncUDPSocket::init(sa_family_t family) {
  if (fd_ != -1) {
    // Socket already initialized.
    return;
  }

  if (family != AF_INET && family != AF_INET6) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::NOT_SUPPORTED,
        "address family not supported");
  }

  int fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (fd == -1) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::NOT_OPEN, "error creating socket", errno);
  }

  SCOPE_FAIL {
    ::close(fd);
  };

  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::INTERNAL_ERROR,
        "error getting socket flags",
        errno);
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::INTERNAL_ERROR,
        "error setting socket nonblocking flag",
        errno);
  }

  int sockOptVal = 1;
  if (reuseAddr_ &&
      ::setsockopt(
          fd, SOL_SOCKET, SO_REUSEADDR, &sockOptVal, sizeof(sockOptVal)) != 0) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::INTERNAL_ERROR,
        "error setting reuse address on socket",
        errno);
  }
  if (reusePort_ &&
      ::setsockopt(
          fd, SOL_SOCKET, SO_REUSEPORT, &sockOptVal, sizeof(sockOptVal)) != 0) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::INTERNAL_ERROR,
        "error setting reuse port on socket",
        errno);
  }

  if (rcvBuf_ > 0) {
    // Set the size of the buffer for the received messages in rx_queues.
    int value = rcvBuf_;
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) != 0) {
      throw folly::AsyncSocketException(
          folly::AsyncSocketException::NOT_OPEN,
          "failed to set SO_RCVBUF on the socket",
          errno);
    }
  }

  if (sndBuf_ > 0) {
    // Set the size of the buffer for the sent messages in tx_queues.
    int value = sndBuf_;
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) != 0) {
      throw folly::AsyncSocketException(
          folly::AsyncSocketException::NOT_OPEN,
          "failed to set SO_SNDBUF on the socket",
          errno);
    }
  }

  fd_ = fd;
  ownership_ = FDOwnership::OWNS;
}

void LibevQuicAsyncUDPSocket::bind(const folly::SocketAddress& address) {
  // TODO: remove dependency on folly::SocketAdress since this pulls in
  // folly::portability and other headers which should be avoidable.
  if (fd_ == -1) {
    init(address.getFamily());
  }
  // bind to the address
  sockaddr_storage addrStorage;
  address.getAddress(&addrStorage);
  auto& saddr = reinterpret_cast<sockaddr&>(addrStorage);
  if (::bind(
          fd_,
          (struct sockaddr*)&saddr,
          saddr.sa_family == AF_INET6 ? sizeof(sockaddr_in6)
                                      : sizeof(sockaddr_in)) != 0) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::INTERNAL_ERROR,
        "error binding socket to " + address.describe(),
        errno);
  }

  memset(&saddr, 0, sizeof(saddr));
  socklen_t len = sizeof(saddr);
  if (::getsockname(fd_, &saddr, &len) != 0) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::INTERNAL_ERROR,
        "error retrieving local address",
        errno);
  }

  localAddress_.setFromSockaddr(&saddr, len);
  bound_ = true;
}

void LibevQuicAsyncUDPSocket::connect(const folly::SocketAddress& address) {
  if (fd_ == -1) {
    init(address.getFamily());
  }

  sockaddr_storage addrStorage;
  address.getAddress(&addrStorage);
  auto saddr = reinterpret_cast<sockaddr&>(addrStorage);
  if (::connect(fd_, &saddr, sizeof(saddr)) != 0) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::INTERNAL_ERROR,
        "error connecting UDP socket to " + address.describe(),
        errno);
  }

  connected_ = true;
  connectedAddress_ = address;

  if (!localAddress_.isInitialized()) {
    memset(&saddr, 0, sizeof(saddr));
    socklen_t len = sizeof(saddr);
    if (::getsockname(fd_, &saddr, &len) != 0) {
      throw folly::AsyncSocketException(
          folly::AsyncSocketException::INTERNAL_ERROR,
          "error retrieving local address",
          errno);
    }

    localAddress_.setFromSockaddr(&saddr, len);
  }
}

void LibevQuicAsyncUDPSocket::setDFAndTurnOffPMTU() {
  if (fd_ == -1) {
    throw folly::AsyncSocketException(
        folly::AsyncSocketException::NOT_OPEN, "socket is not initialized");
  }
  int optname4 = 0;
  int optval4 = 0;
  int optname6 = 0;
  int optval6 = 0;
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_PROBE)
  optname4 = IP_MTU_DISCOVER;
  optval4 = IP_PMTUDISC_PROBE;
#endif
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_PROBE)
  optname6 = IPV6_MTU_DISCOVER;
  optval6 = IPV6_PMTUDISC_PROBE;
#endif
  if (optname4 && optval4 && address().getFamily() == AF_INET) {
    if (::setsockopt(fd_, IPPROTO_IP, optname4, &optval4, sizeof(optval4))) {
      throw folly::AsyncSocketException(
          folly::AsyncSocketException::NOT_OPEN,
          "failed to turn off PMTU discovery (IPv4)",
          errno);
    }
  }
  if (optname6 && optval6 && address().getFamily() == AF_INET6) {
    if (::setsockopt(fd_, IPPROTO_IPV6, optname6, &optval6, sizeof(optval6))) {
      throw folly::AsyncSocketException(
          folly::AsyncSocketException::NOT_OPEN,
          "failed to turn off PMTU discovery (IPv6)",
          errno);
    }
  }
}

void LibevQuicAsyncUDPSocket::setErrMessageCallback(
    ErrMessageCallback* errMessageCallback) {
  errMessageCallback_ = errMessageCallback;
}

int LibevQuicAsyncUDPSocket::getGRO() {
  return -1;
}

ssize_t LibevQuicAsyncUDPSocket::recvmsg(struct msghdr* msg, int flags) {
  return ::recvmsg(fd_, msg, flags);
}

int LibevQuicAsyncUDPSocket::recvmmsg(
    struct mmsghdr* msgvec,
    unsigned int vlen,
    unsigned int flags,
    struct timespec* timeout) {
#ifdef FOLLY_HAVE_RECVMMSG
  return ::recvmmsg(fd_, msgvec, vlen, (int)flags, timeout);
#else
  // TODO: share cross-platform code with folly's AsyncUDPSocket.
  LOG(FATAL) << "no recvmmsg";
  return -1;
#endif
}

bool LibevQuicAsyncUDPSocket::setGRO(bool /* bVal */) {
  return false;
}

void LibevQuicAsyncUDPSocket::applyOptions(
    const folly::SocketOptionMap& options,
    folly::SocketOptionKey::ApplyPos pos) {
  for (const auto& opt : options) {
    if (opt.first.applyPos_ == pos) {
      if (::setsockopt(
              fd_,
              opt.first.level,
              opt.first.optname,
              &opt.second,
              sizeof(opt.second)) != 0) {
        throw folly::AsyncSocketException(
            folly::AsyncSocketException::INTERNAL_ERROR,
            "failed to apply socket options",
            errno);
      }
    }
  }
}

void LibevQuicAsyncUDPSocket::setFD(int fd, FDOwnership ownership) {
  fd_ = fd;
  ownership_ = ownership;

  updateReadWatcher();
}

int LibevQuicAsyncUDPSocket::getFD() {
  return fd_;
}

// PRIVATE
void LibevQuicAsyncUDPSocket::evHandleSocketRead() {
  CHECK(readCallback_);
  CHECK(readCallback_->shouldOnlyNotify());
  readCallback_->onNotifyDataAvailable(*this);
}

void LibevQuicAsyncUDPSocket::updateReadWatcher() {
  CHECK(evb_) << "EventBase not initialized";
  ev_io_stop(evb_->getLibevLoop(), &readWatcher_);

  if (readCallback_) {
    ev_io_set(&readWatcher_, fd_, EV_READ);
    ev_io_start(evb_->getLibevLoop(), &readWatcher_);
  }
}

// STATIC PRIVATE
void LibevQuicAsyncUDPSocket::readWatcherCallback(
    struct ev_loop* /*loop*/,
    ev_io* w,
    int /*revents*/) {
  auto sock = static_cast<LibevQuicAsyncUDPSocket*>(w->data);
  CHECK(sock)
      << "Watcher callback does not have a valid LibevQuicAsyncUDPSocket pointer";
  CHECK(sock->getEventBase()) << "Socket does not have an event base attached";
  CHECK(sock->getEventBase()->isInEventBaseThread())
      << "Watcher callback on wrong event base";
  sock->evHandleSocketRead();
}

void LibevQuicAsyncUDPSocket::setRcvBuf(int rcvBuf) {
  rcvBuf_ = rcvBuf;
}

void LibevQuicAsyncUDPSocket::setSndBuf(int sndBuf) {
  sndBuf_ = sndBuf;
}

} // namespace quic
