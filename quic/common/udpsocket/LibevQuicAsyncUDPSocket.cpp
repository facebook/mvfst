/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Expected.h>
#include <folly/String.h>
#include <folly/lang/Exception.h> // For folly::errnoStr
#include <quic/QuicException.h> // For QuicError, QuicErrorCode, TransportErrorCode
#include <quic/common/Optional.h>
#include <quic/common/udpsocket/LibevQuicAsyncUDPSocket.h>

#include <cstring>

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <unistd.h>

namespace quic {

LibevQuicAsyncUDPSocket::LibevQuicAsyncUDPSocket(
    std::shared_ptr<LibevQuicEventBase> evb) {
  evb_ = evb;
  CHECK(evb_) << "EventBase must be QuicLibevEventBase";
  CHECK(evb_->isInEventBaseThread());

  ev_init(&readWatcher_, LibevQuicAsyncUDPSocket::sockEventsWatcherCallback);
  readWatcher_.data = this;

  ev_init(&writeWatcher_, LibevQuicAsyncUDPSocket::sockEventsWatcherCallback);
  writeWatcher_.data = this;
}

LibevQuicAsyncUDPSocket::~LibevQuicAsyncUDPSocket() {
  if (fd_ != -1) {
    // Use folly::Expected result even in destructor? Best effort close.
    auto closeResult = LibevQuicAsyncUDPSocket::close();
    if (closeResult.hasError()) {
      LOG(ERROR) << "Error closing socket in destructor: "
                 << closeResult.error().message;
    }
  }
  if (evb_) {
    ev_io_stop(evb_->getLibevLoop(), &readWatcher_);
    ev_io_stop(evb_->getLibevLoop(), &writeWatcher_);
  }
}

void LibevQuicAsyncUDPSocket::pauseRead() {
  readCallback_ = nullptr;
  removeEvent(EV_READ);
}

bool LibevQuicAsyncUDPSocket::isReadPaused() const {
  return readCallback_ == nullptr;
}

void LibevQuicAsyncUDPSocket::resumeRead(ReadCallback* cb) {
  CHECK(!readCallback_) << "A read callback is already installed";
  CHECK_NE(fd_, -1)
      << "Socket must be initialized before a read callback is attached";
  CHECK(cb) << "A non-null callback is required to resume read";
  readCallback_ = cb;
  addEvent(EV_READ);
  // TODO: This should return Expected<Unit, QuicError>
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::resumeWrite(
    WriteCallback* cob) {
  CHECK(!writeCallback_) << "A write callback is already installed";
  CHECK_NE(fd_, -1)
      << "Socket must be initialized before a write callback is attached";
  CHECK(cob) << "A non-null callback is required to resume write";
  writeCallback_ = cob;
  addEvent(EV_WRITE);
  return folly::unit;
}

void LibevQuicAsyncUDPSocket::pauseWrite() {
  writeCallback_ = nullptr;
  removeEvent(EV_WRITE);
}

ssize_t LibevQuicAsyncUDPSocket::write(
    const folly::SocketAddress& address,
    const struct iovec* vec,
    size_t iovec_len) {
  if (fd_ == -1) {
    // Return error consistent with syscall failure on bad FD
    errno = EBADF;
    LOG(ERROR)
        << "LibevQuicAsyncUDPSocket::write failed: socket not initialized";
    return -1;
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
      // Return error consistent with syscall failure for wrong address on
      // connected socket
      errno = EINVAL; // Or maybe EISCONN? EINVAL seems appropriate.
      LOG(ERROR)
          << "LibevQuicAsyncUDPSocket::write failed: wrong destination for connected socket";
      return -1;
    }
    msg.msg_name = nullptr;
    msg.msg_namelen = 0;
  }

  msg.msg_iov = const_cast<struct iovec*>(vec);
  msg.msg_iovlen = iovec_len;
  msg.msg_control = nullptr;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  return ::sendmsg(fd_, &msg, msg_flags);
}

folly::Expected<int, QuicError> LibevQuicAsyncUDPSocket::getGSO() {
  // TODO: Implement GSO
  return -1;
}

int LibevQuicAsyncUDPSocket::writem(
    folly::Range<folly::SocketAddress const*> /*addrs*/,
    iovec* /*iov*/,
    size_t* /*numIovecsInBuffer*/,
    size_t /*count*/) {
  LOG(FATAL) << __func__ << "is not implemented in LibevQuicAsyncUDPSocket";
  return -1;
}

folly::Expected<folly::Unit, QuicError>
LibevQuicAsyncUDPSocket::setAdditionalCmsgsFunc(
    std::function<Optional<folly::SocketCmsgMap>()>&&
    /* additionalCmsgsFunc */) {
  LOG(WARNING)
      << "Setting an additional cmsgs function is not implemented for LibevQuicAsyncUDPSocket";
  // Return success despite warning, or error if strictness needed
  return folly::unit;
}

bool LibevQuicAsyncUDPSocket::isBound() const {
  return bound_;
}

folly::Expected<folly::SocketAddress, QuicError>
LibevQuicAsyncUDPSocket::address() const {
  if (!bound_) {
    // Return error if not bound
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "socket is not bound"));
  }
  return localAddress_;
}

const folly::SocketAddress& LibevQuicAsyncUDPSocket::addressRef() const {
  LOG_IF(FATAL, !bound_) << "socket is not bound";
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

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::close() {
  CHECK(evb_->isInEventBaseThread());

  if (readCallback_) {
    auto cob = readCallback_;
    readCallback_ = nullptr;

    cob->onReadClosed();
  }
  writeCallback_ = nullptr;
  removeEvent(EV_READ | EV_WRITE);

  if (fd_ != -1 && ownership_ == FDOwnership::OWNS) {
    if (::close(fd_) != 0) {
      int errnoCopy = errno;
      fd_ = -1; // Mark as closed even if error occurred
      std::string errorMsg =
          "Failed to close socket: " + folly::errnoStr(errnoCopy);
      return folly::makeUnexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }
  }

  fd_ = -1;
  bound_ = false; // Reset state
  connected_ = false;
  return folly::unit;
}

void LibevQuicAsyncUDPSocket::detachEventBase() {
  LOG(FATAL) << __func__ << "is not implemented in LibevQuicAsyncUDPSocket";
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::setCmsgs(
    const folly::SocketCmsgMap& /* cmsgs */) {
  return folly::makeUnexpected(QuicError(
      QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
      "setCmsgs is not implemented."));
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::appendCmsgs(
    const folly::SocketCmsgMap& /* cmsgs */) {
  return folly::makeUnexpected(QuicError(
      QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
      "appendCmsgs is not implemented."));
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::init(
    sa_family_t family) {
  if (fd_ != -1) {
    // Socket already initialized.
    return folly::unit;
  }

  if (family != AF_INET && family != AF_INET6) {
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "address family not supported"));
  }

  int fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
  if (fd == -1) {
    int errnoCopy = errno;
    std::string errorMsg =
        "error creating socket: " + folly::errnoStr(errnoCopy);
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }

  // Use RAII to ensure socket is closed on error
  auto fdGuard = folly::makeGuard([fd] { ::close(fd); });

  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    int errnoCopy = errno;
    std::string errorMsg =
        "error getting socket flags: " + folly::errnoStr(errnoCopy);
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
    int errnoCopy = errno;
    std::string errorMsg =
        "error setting socket nonblocking flag: " + folly::errnoStr(errnoCopy);
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }

  int sockOptVal = 1;
  if (reuseAddr_ &&
      ::setsockopt(
          fd, SOL_SOCKET, SO_REUSEADDR, &sockOptVal, sizeof(sockOptVal)) != 0) {
    int errnoCopy = errno;
    std::string errorMsg =
        "error setting reuse address on socket: " + folly::errnoStr(errnoCopy);
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
  if (reusePort_ &&
      ::setsockopt(
          fd, SOL_SOCKET, SO_REUSEPORT, &sockOptVal, sizeof(sockOptVal)) != 0) {
    int errnoCopy = errno;
    std::string errorMsg =
        "error setting reuse port on socket: " + folly::errnoStr(errnoCopy);
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }

  if (rcvBuf_ > 0) {
    // Set the size of the buffer for the received messages in rx_queues.
    int value = rcvBuf_;
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) != 0) {
      int errnoCopy = errno;
      std::string errorMsg = "failed to set SO_RCVBUF on the socket: " +
          folly::errnoStr(errnoCopy);
      return folly::makeUnexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }
  }

  if (sndBuf_ > 0) {
    // Set the size of the buffer for the sent messages in tx_queues.
    int value = sndBuf_;
    if (::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) != 0) {
      int errnoCopy = errno;
      std::string errorMsg = "failed to set SO_SNDBUF on the socket: " +
          folly::errnoStr(errnoCopy);
      return folly::makeUnexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }
  }

  fd_ = fd;
  ownership_ = FDOwnership::OWNS;
  fdGuard.dismiss(); // Don't close the fd now that we've stored it

  // Update the watchers
  removeEvent(EV_READ | EV_WRITE);
  ev_io_set(&readWatcher_, fd_, EV_READ);
  ev_io_set(&writeWatcher_, fd_, EV_WRITE);

  return folly::unit;
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::bind(
    const folly::SocketAddress& address) {
  // TODO: remove dependency on folly::SocketAdress since this pulls in
  // folly::portability and other headers which should be avoidable.
  if (fd_ == -1) {
    auto initResult = init(address.getFamily());
    if (initResult.hasError()) {
      return initResult;
    }
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
    int errnoCopy = errno;
    std::string errorMsg = "error binding socket to " + address.describe() +
        ": " + folly::errnoStr(errnoCopy);
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }

  memset(&saddr, 0, sizeof(saddr));
  socklen_t len = sizeof(saddr);
  if (::getsockname(fd_, &saddr, &len) != 0) {
    int errnoCopy = errno;
    std::string errorMsg =
        "error retrieving local address: " + folly::errnoStr(errnoCopy);
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }

  localAddress_.setFromSockaddr(&saddr, len);
  bound_ = true;

  return folly::unit;
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::connect(
    const folly::SocketAddress& address) {
  if (fd_ == -1) {
    auto initResult = init(address.getFamily());
    if (initResult.hasError()) {
      return initResult;
    }
  }

  sockaddr_storage addrStorage;
  address.getAddress(&addrStorage);
  auto saddr = reinterpret_cast<sockaddr&>(addrStorage);
  if (::connect(fd_, &saddr, sizeof(saddr)) != 0) {
    int errnoCopy = errno;
    std::string errorMsg = "Libev connect failed to " + address.describe();
    errorMsg += ": " + folly::errnoStr(errnoCopy);
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }

  connected_ = true;
  connectedAddress_ = address;

  if (!localAddress_.isInitialized()) {
    memset(&saddr, 0, sizeof(saddr));
    socklen_t len = sizeof(saddr);
    if (::getsockname(fd_, &saddr, &len) != 0) {
      int errnoCopy = errno;
      std::string errorMsg = "Libev getsockname failed after connect: " +
          folly::errnoStr(errnoCopy);
      // Connect succeeded, but getsockname failed.
      return folly::makeUnexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }

    localAddress_.setFromSockaddr(&saddr, len);
  }
  return folly::unit;
}

folly::Expected<folly::Unit, QuicError>
LibevQuicAsyncUDPSocket::setDFAndTurnOffPMTU() {
  if (fd_ == -1) {
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "socket is not initialized"));
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
  auto familyResult = address(); // address() now returns Expected
  if (familyResult.hasError()) {
    return folly::makeUnexpected(familyResult.error());
  }
  sa_family_t family = familyResult->getFamily();

  if (optname4 && optval4 && family == AF_INET) {
    if (::setsockopt(fd_, IPPROTO_IP, optname4, &optval4, sizeof(optval4))) {
      int errnoCopy = errno;
      std::string errorMsg = "failed to turn off PMTU discovery (IPv4): " +
          folly::errnoStr(errnoCopy);
      return folly::makeUnexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }
  }
  if (optname6 && optval6 && family == AF_INET6) {
    if (::setsockopt(fd_, IPPROTO_IPV6, optname6, &optval6, sizeof(optval6))) {
      int errnoCopy = errno;
      std::string errorMsg = "failed to turn off PMTU discovery (IPv6): " +
          folly::errnoStr(errnoCopy);
      return folly::makeUnexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }
  }
  // If options are not defined for the family, we succeed silently.
  return folly::unit;
}

folly::Expected<folly::Unit, QuicError>
LibevQuicAsyncUDPSocket::setErrMessageCallback(
    ErrMessageCallback* errMessageCallback) {
  if (fd_ == -1) {
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "socket not initialized for setErrMessageCallback"));
  }
  errMessageCallback_ = errMessageCallback;
  int optname4 = 0;
  int optname6 = 0;
#if defined(IP_RECVERR)
  optname4 = IP_RECVERR;
#endif
#if defined(IPV6_RECVERR)
  optname6 = IPV6_RECVERR;
#endif
  auto familyResult = address(); // address() now returns Expected
  if (familyResult.hasError()) {
    return folly::makeUnexpected(familyResult.error());
  }
  sa_family_t family = familyResult->getFamily();

  errMessageCallback_ = errMessageCallback;
  int err = (errMessageCallback_ != nullptr);
  if (optname4 && family == AF_INET &&
      ::setsockopt(fd_, IPPROTO_IP, optname4, &err, sizeof(err))) {
    int errnoCopy = errno;
    std::string errorMsg =
        "Failed to set IP_RECVERR: " + folly::errnoStr(errnoCopy);
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
  if (optname6 && family == AF_INET6 &&
      ::setsockopt(fd_, IPPROTO_IPV6, optname6, &err, sizeof(err))) {
    int errnoCopy = errno;
    std::string errorMsg =
        "Failed to set IPV6_RECVERR: " + folly::errnoStr(errnoCopy);
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
  return folly::unit;
}

folly::Expected<int, QuicError> LibevQuicAsyncUDPSocket::getGRO() {
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
#if !FOLLY_MOBILE
  if (reinterpret_cast<void*>(::recvmmsg) != nullptr) {
    return ::recvmmsg(fd_, msgvec, vlen, (int)flags, timeout);
  }
#endif
  // if recvmmsg is not supported, implement it using recvmsg
  for (unsigned int i = 0; i < vlen; i++) {
    ssize_t ret = ::recvmsg(fd_, &msgvec[i].msg_hdr, flags);
    // in case of an error
    // we return the number of msgs received if > 0
    // or an error if no msg was received
    if (ret < 0) {
      if (i) {
        return static_cast<int>(i);
      }
      return static_cast<int>(ret);
    } else {
      msgvec[i].msg_len = ret;
    }
  }
  return static_cast<int>(vlen);
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::setGRO(
    bool /* bVal */) {
  // Not supported, return error
  return folly::makeUnexpected(QuicError(
      QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
      "setGRO not supported"));
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::applyOptions(
    const folly::SocketOptionMap& options,
    folly::SocketOptionKey::ApplyPos pos) {
  if (fd_ == -1) {
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        "socket not initialized for applyOptions"));
  }
  for (const auto& opt : options) {
    if (opt.first.applyPos_ == pos) {
      if (::setsockopt(
              fd_,
              opt.first.level,
              opt.first.optname,
              &opt.second,
              sizeof(opt.second)) != 0) {
        int errnoCopy = errno;
        std::string errorMsg =
            "failed to apply socket options: " + folly::errnoStr(errnoCopy);
        return folly::makeUnexpected(QuicError(
            QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
            std::move(errorMsg)));
      }
    }
  }
  return folly::unit;
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::setFD(
    int fd,
    FDOwnership ownership) {
  // TODO: Check if fd is valid? setsockopt?
  // TODO: Close existing fd_ if owned?
  if (fd_ != -1 && ownership_ == FDOwnership::OWNS) {
    LOG(WARNING) << "Closing existing owned FD in setFD";
    auto closeRes = close(); // Close existing owned FD
    if (closeRes.hasError()) {
      // Log error but continue trying to set the new FD
      LOG(ERROR) << "Failed to close existing FD in setFD: "
                 << closeRes.error().message;
    }
  }

  fd_ = fd;
  ownership_ = ownership;
  bound_ = false; // Assume not bound until checked/bind called
  connected_ = false; // Assume not connected

  // Update the watchers
  removeEvent(EV_READ | EV_WRITE);
  ev_io_set(&readWatcher_, fd_, EV_READ);
  ev_io_set(&writeWatcher_, fd_, EV_WRITE);

  if (readCallback_) {
    addEvent(EV_READ);
  }
  if (writeCallback_) {
    addEvent(EV_WRITE);
  }
  // TODO: Check if the FD is actually usable? Maybe getsockopt?
  // For now, assume success if we reach here.
  return folly::unit;
}

int LibevQuicAsyncUDPSocket::getFD() {
  return fd_;
}

// PRIVATE
void LibevQuicAsyncUDPSocket::evHandleSocketRead() {
  CHECK(readCallback_);
  CHECK(readCallback_->shouldOnlyNotify());

  // Read any errors first. If there are errors, do not notify the read
  // callback.
  // Note: I don't see the motivation for returning here if the fd is not closed
  // but doing this to maintain consistent behavior with folly's AsyncUDPSocket
  if (handleSocketErrors()) {
    return;
  }

  // An error callback could close the socket, in which case we should not read
  // from it.
  if (fd_ == -1) {
    return;
  }

  // Let the callback read from the socket
  readCallback_->onNotifyDataAvailable(*this);
}

void LibevQuicAsyncUDPSocket::evHandleSocketWritable() {
  CHECK(writeCallback_);
  writeCallback_->onSocketWritable();
}

size_t LibevQuicAsyncUDPSocket::handleSocketErrors() {
#ifdef MSG_ERRQUEUE
  if (errMessageCallback_ == nullptr) {
    return 0;
  }
  std::array<uint8_t, 1024> ctrl;
  unsigned char data;
  struct msghdr msg;
  iovec entry;

  entry.iov_base = &data;
  entry.iov_len = sizeof(data);
  msg.msg_iov = &entry;
  msg.msg_iovlen = 1;
  msg.msg_name = nullptr;
  msg.msg_namelen = 0;
  msg.msg_control = ctrl.data();
  msg.msg_controllen = sizeof(ctrl);
  msg.msg_flags = 0;

  ssize_t ret;
  size_t num = 0;
  while (fd_ != -1) {
    ret = ::recvmsg(fd_, &msg, MSG_ERRQUEUE);
    VLOG(5)
        << "LibevQuicAsyncUDPSocket::handleSocketErrors(): recvmsg returned "
        << ret;

    if (ret < 0) {
      if (errno != EAGAIN) {
        auto errnoCopy = errno;
        LOG(ERROR) << "::recvmsg exited with code " << ret
                   << ", errno: " << errnoCopy;
        folly::AsyncSocketException ex(
            folly::AsyncSocketException::INTERNAL_ERROR,
            "MSG_ERRQUEUE recvmsg() failed",
            errnoCopy);
        // We can't receive errors so unset the callback.
        ErrMessageCallback* callback = errMessageCallback_;
        errMessageCallback_ = nullptr;
        callback->errMessageError(ex);
      }
      return num;
    }

    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != nullptr && cmsg->cmsg_len != 0;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      ++num;
      errMessageCallback_->errMessage(*cmsg);
      if (fd_ == -1) {
        // once the socket is closed there is no use for more read errors.
        return num;
      }
    }
  }
  return num;
#else
  return 0;
#endif
}

void LibevQuicAsyncUDPSocket::addEvent(int event) {
  CHECK(evb_) << "EventBase not initialized";
  if (event & EV_READ) {
    ev_io_start(evb_->getLibevLoop(), &readWatcher_);
  }
  if (event & EV_WRITE) {
    ev_io_start(evb_->getLibevLoop(), &writeWatcher_);
  }
}

void LibevQuicAsyncUDPSocket::removeEvent(int event) {
  CHECK(evb_) << "EventBase not initialized";

  if (event & EV_READ) {
    ev_io_stop(evb_->getLibevLoop(), &readWatcher_);
  }

  if (event & EV_WRITE) {
    ev_io_stop(evb_->getLibevLoop(), &writeWatcher_);
  }
}

// STATIC PRIVATE
void LibevQuicAsyncUDPSocket::sockEventsWatcherCallback(
    struct ev_loop* /*loop*/,
    ev_io* w,
    int events) {
  auto sock = static_cast<LibevQuicAsyncUDPSocket*>(w->data);
  CHECK(sock)
      << "Watcher callback does not have a valid LibevQuicAsyncUDPSocket pointer";
  CHECK(sock->getEventBase()) << "Socket does not have an event base attached";
  CHECK(sock->getEventBase()->isInEventBaseThread())
      << "Watcher callback on wrong event base";
  if (events & EV_READ) {
    sock->evHandleSocketRead();
  }
  if (events & EV_WRITE) {
    sock->evHandleSocketWritable();
  }
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::setRcvBuf(
    int rcvBuf) {
  rcvBuf_ = rcvBuf;
  if (fd_ != -1) {
    // Apply immediately if socket exists
    int value = rcvBuf_;
    if (::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) != 0) {
      int errnoCopy = errno;
      std::string errorMsg =
          "failed to set SO_RCVBUF: " + folly::errnoStr(errnoCopy);
      return folly::makeUnexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }
  }
  return folly::unit;
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::setSndBuf(
    int sndBuf) {
  sndBuf_ = sndBuf;
  if (fd_ != -1) {
    // Apply immediately if socket exists
    int value = sndBuf_;
    if (::setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) != 0) {
      int errnoCopy = errno;
      std::string errorMsg =
          "failed to set SO_SNDBUF: " + folly::errnoStr(errnoCopy);
      return folly::makeUnexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }
  }
  return folly::unit;
}

folly::Expected<folly::Unit, QuicError> LibevQuicAsyncUDPSocket::setReuseAddr(
    bool reuseAddr) {
  reuseAddr_ = reuseAddr;
  if (fd_ != -1) {
    int sockOptVal = reuseAddr ? 1 : 0;
    if (::setsockopt(
            fd_, SOL_SOCKET, SO_REUSEADDR, &sockOptVal, sizeof(sockOptVal)) !=
        0) {
      int errnoCopy = errno;
      std::string errorMsg =
          "failed to set SO_REUSEADDR: " + folly::errnoStr(errnoCopy);
      return folly::makeUnexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }
  }
  return folly::unit;
}

bool LibevQuicAsyncUDPSocket::isWritableCallbackSet() const {
  return writeCallback_ != nullptr;
}

} // namespace quic
