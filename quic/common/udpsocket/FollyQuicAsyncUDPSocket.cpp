/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <errno.h> // For errno
#include <folly/Expected.h>
#include <folly/String.h>
#include <folly/Unit.h>
#include <folly/io/async/AsyncSocketException.h>
#include <folly/lang/Exception.h> // For folly::errnoStr
#include <quic/QuicException.h> // For QuicError, QuicErrorCode, TransportErrorCode
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <memory>

namespace quic {
folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::init(
    sa_family_t family) {
  try {
    follySocket_.init(family);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly init failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::bind(
    const folly::SocketAddress& address) {
  try {
    follySocket_.bind(address);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly bind failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

[[nodiscard]] bool FollyQuicAsyncUDPSocket::isBound() const {
  return follySocket_.isBound();
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::connect(
    const folly::SocketAddress& address) {
  try {
    follySocket_.connect(address);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly connect failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::close() {
  try {
    follySocket_.close();
    readCallbackWrapper_.reset(); // Ensure wrapper is cleared on close
    errCallbackWrapper_.reset();
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly close failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

void FollyQuicAsyncUDPSocket::resumeRead(ReadCallback* callback) {
  try {
    // TODO: We could skip this check and rely on the one in AsyncUDPSocket
    CHECK(!readCallbackWrapper_) << "Already registered a read callback";
    readCallbackWrapper_ =
        std::make_unique<FollyReadCallbackWrapper>(callback, this);
    follySocket_.resumeRead(readCallbackWrapper_.get());
    // TODO: This should return Expected<Unit, QuicError>
  } catch (const folly::AsyncSocketException& ex) {
    // TODO: Convert to QuicError and return folly::makeUnexpected
    LOG(ERROR) << "FollyQuicAsyncUDPSocket::resumeRead failed: " << ex.what();
    throw; // Re-throw for now until signature is updated
  }
}

void FollyQuicAsyncUDPSocket::pauseRead() {
  follySocket_.pauseRead();
  readCallbackWrapper_.reset();
}

folly::Expected<folly::Unit, QuicError>
FollyQuicAsyncUDPSocket::setErrMessageCallback(ErrMessageCallback* callback) {
  try {
    if (errCallbackWrapper_) {
      errCallbackWrapper_.reset();
    }
    if (callback) {
      errCallbackWrapper_ = std::make_unique<FollyErrCallbackWrapper>(callback);
      follySocket_.setErrMessageCallback(errCallbackWrapper_.get());
    } else {
      follySocket_.setErrMessageCallback(nullptr);
    }
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setErrMessageCallback failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

ssize_t FollyQuicAsyncUDPSocket::write(
    const folly::SocketAddress& address,
    const struct iovec* vec,
    size_t iovec_len) {
  try {
    folly::AsyncUDPSocket::WriteOptions writeOptions(
        0 /*gsoVal*/, false /* zerocopyVal*/);
    return follySocket_.writev(address, vec, iovec_len, writeOptions);
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    LOG(ERROR) << "FollyQuicAsyncUDPSocket::write failed: " << ex.what();
    return -1;
  }
}

int FollyQuicAsyncUDPSocket::writem(
    folly::Range<folly::SocketAddress const*> addrs,
    iovec* iov,
    size_t* numIovecsInBuffer,
    size_t count) {
  try {
    return follySocket_.writemv(addrs, iov, numIovecsInBuffer, count);
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    LOG(ERROR) << "FollyQuicAsyncUDPSocket::writem failed: " << ex.what();
    return -1;
  }
}

ssize_t FollyQuicAsyncUDPSocket::writeGSO(
    const folly::SocketAddress& address,
    const struct iovec* vec,
    size_t iovec_len,
    WriteOptions options) {
  try {
    folly::AsyncUDPSocket::WriteOptions follyOptions(
        options.gso, options.zerocopy);
    follyOptions.txTime = options.txTime;
    return follySocket_.writev(address, vec, iovec_len, follyOptions);
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    LOG(ERROR) << "FollyQuicAsyncUDPSocket::writeGSO failed: " << ex.what();
    return -1;
  }
}

int FollyQuicAsyncUDPSocket::writemGSO(
    folly::Range<folly::SocketAddress const*> addrs,
    const Buf* bufs,
    size_t count,
    const WriteOptions* options) {
  try {
    std::vector<folly::AsyncUDPSocket::WriteOptions> follyOptions(count);
    for (size_t i = 0; i < count; ++i) {
      follyOptions[i].gso = options[i].gso;
      follyOptions[i].zerocopy = options[i].zerocopy;
      follyOptions[i].txTime = options[i].txTime;
    }
    return follySocket_.writemGSO(addrs, bufs, count, follyOptions.data());
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    LOG(ERROR) << "FollyQuicAsyncUDPSocket::writemGSO(IOBuf) failed: "
               << ex.what();
    return -1;
  }
}

int FollyQuicAsyncUDPSocket::writemGSO(
    folly::Range<folly::SocketAddress const*> addrs,
    iovec* iov,
    size_t* numIovecsInBuffer,
    size_t count,
    const WriteOptions* options) {
  try {
    std::vector<folly::AsyncUDPSocket::WriteOptions> follyOptions(count);
    for (size_t i = 0; i < count; ++i) {
      follyOptions[i].gso = options[i].gso;
      follyOptions[i].zerocopy = options[i].zerocopy;
      follyOptions[i].txTime = options[i].txTime;
    }
    return follySocket_.writemGSOv(
        addrs, iov, numIovecsInBuffer, count, follyOptions.data());
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    LOG(ERROR) << "FollyQuicAsyncUDPSocket::writemGSO(iovec) failed: "
               << ex.what();
    return -1;
  }
}

ssize_t FollyQuicAsyncUDPSocket::recvmsg(struct msghdr* msg, int flags) {
  try {
    return follySocket_.recvmsg(msg, flags);
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    LOG(ERROR) << "FollyQuicAsyncUDPSocket::recvmsg failed: " << ex.what();
    return -1;
  }
}

int FollyQuicAsyncUDPSocket::recvmmsg(
    struct mmsghdr* msgvec,
    unsigned int vlen,
    unsigned int flags,
    struct timespec* timeout) {
  try {
    return follySocket_.recvmmsg(msgvec, vlen, flags, timeout);
  } catch (const folly::AsyncSocketException& ex) {
    // Log the error, set errno, return -1 for syscall-like behavior
    errno = ex.getErrno();
    LOG(ERROR) << "FollyQuicAsyncUDPSocket::recvmmsg failed: " << ex.what();
    return -1;
  }
}

folly::Expected<int, QuicError> FollyQuicAsyncUDPSocket::getGSO() {
  try {
    return follySocket_.getGSO();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly getGSO failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    LOG(ERROR) << "getGSO failed: " << errorMsg;
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<int, QuicError> FollyQuicAsyncUDPSocket::getGRO() {
  try {
    return follySocket_.getGRO();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly getGRO failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::setGRO(
    bool bVal) {
  try {
    if (follySocket_.setGRO(bVal)) {
      return folly::unit;
    } else {
      // Folly's setGRO returns bool, not throwing. Assume failure means error.
      int errnoCopy = errno; // Capture errno immediately after failure
      std::string errorMsg = "Folly setGRO failed";
      if (errnoCopy != 0) {
        errorMsg += ": " + folly::errnoStr(errnoCopy);
      }
      return folly::makeUnexpected(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::move(errorMsg)));
    }
  } catch (const folly::AsyncSocketException& ex) {
    // Catch just in case future folly versions throw
    std::string errorMsg = "Folly setGRO exception: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::setRecvTos(
    bool recvTos) {
  try {
    follySocket_.setRecvTos(recvTos);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setRecvTos failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<bool, QuicError> FollyQuicAsyncUDPSocket::getRecvTos() {
  try {
    return follySocket_.getRecvTos();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly getRecvTos failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError>
FollyQuicAsyncUDPSocket::setTosOrTrafficClass(uint8_t tos) {
  try {
    follySocket_.setTosOrTrafficClass(tos);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setTosOrTrafficClass failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

[[nodiscard]] folly::Expected<folly::SocketAddress, QuicError>
FollyQuicAsyncUDPSocket::address() const {
  try {
    return follySocket_.address();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly address() failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

[[nodiscard]] const folly::SocketAddress& FollyQuicAsyncUDPSocket::addressRef()
    const {
  try {
    return follySocket_.address();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly address() failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    LOG(FATAL) << errorMsg;
  }
}

void FollyQuicAsyncUDPSocket::attachEventBase( // Keep void, attach/detach
                                               // usually don't throw socket
                                               // errors
    std::shared_ptr<QuicEventBase> evb) {
  CHECK(evb != nullptr);
  std::shared_ptr<FollyQuicEventBase> follyEvb =
      std::dynamic_pointer_cast<FollyQuicEventBase>(evb);
  CHECK(follyEvb != nullptr);
  evb_ = follyEvb;
  follySocket_.attachEventBase(follyEvb->getBackingEventBase());
}

void FollyQuicAsyncUDPSocket::detachEventBase() { // Keep void
  follySocket_.detachEventBase();
}

[[nodiscard]] std::shared_ptr<QuicEventBase>
FollyQuicAsyncUDPSocket::getEventBase() const {
  if (evb_) {
    CHECK_EQ(evb_->getBackingEventBase(), follySocket_.getEventBase());
  }
  return evb_;
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::setCmsgs(
    const folly::SocketCmsgMap& cmsgs) {
  try {
    follySocket_.setCmsgs(cmsgs);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setCmsgs failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::appendCmsgs(
    const folly::SocketCmsgMap& cmsgs) {
  try {
    follySocket_.appendCmsgs(cmsgs);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly appendCmsgs failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError>
FollyQuicAsyncUDPSocket::setAdditionalCmsgsFunc(
    folly::Function<Optional<folly::SocketCmsgMap>()>&& additionalCmsgsFunc) {
  try {
    follySocket_.setAdditionalCmsgsFunc(std::move(additionalCmsgsFunc));
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setAdditionalCmsgsFunc failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<int, QuicError> FollyQuicAsyncUDPSocket::getTimestamping() {
  try {
    return follySocket_.getTimestamping();
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly getTimestamping failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::setReuseAddr(
    bool reuseAddr) {
  try {
    follySocket_.setReuseAddr(reuseAddr);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setReuseAddr failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError>
FollyQuicAsyncUDPSocket::setDFAndTurnOffPMTU() {
  try {
    follySocket_.setDFAndTurnOffPMTU();
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setDFAndTurnOffPMTU failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::applyOptions(
    const folly::SocketOptionMap& options,
    folly::SocketOptionKey::ApplyPos pos) {
  try {
    follySocket_.applyOptions(options, pos);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly applyOptions failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::setReusePort(
    bool reusePort) {
  try {
    follySocket_.setReusePort(reusePort);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg =
        "Folly setReusePort failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::setRcvBuf(
    int rcvBuf) {
  try {
    follySocket_.setRcvBuf(rcvBuf);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setRcvBuf failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::setSndBuf(
    int sndBuf) {
  try {
    follySocket_.setSndBuf(sndBuf);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setSndBuf failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

folly::Expected<folly::Unit, QuicError> FollyQuicAsyncUDPSocket::setFD(
    int fd,
    FDOwnership ownership) {
  folly::AsyncUDPSocket::FDOwnership follyOwnership;
  switch (ownership) {
    case FDOwnership::OWNS:
      follyOwnership = folly::AsyncUDPSocket::FDOwnership::OWNS;
      break;
    case FDOwnership::SHARED:
      follyOwnership = folly::AsyncUDPSocket::FDOwnership::SHARED;
      break;
  }
  try {
    follySocket_.setFD(folly::NetworkSocket::fromFd(fd), follyOwnership);
    return folly::unit;
  } catch (const folly::AsyncSocketException& ex) {
    std::string errorMsg = "Folly setFD failed: " + std::string(ex.what());
    if (ex.getErrno() != 0) {
      errorMsg += ": " + folly::errnoStr(ex.getErrno());
    }
    return folly::makeUnexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
  }
}

int FollyQuicAsyncUDPSocket::getFD() {
  return follySocket_.getNetworkSocket().toFd();
}

folly::AsyncUDPSocket& FollyQuicAsyncUDPSocket::getFollySocket() {
  return follySocket_;
}

// FollyReadCallbackWrapper implementation

void FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::getReadBuffer(
    void** buf,
    size_t* len) noexcept {
  return wrappedReadCallback_->getReadBuffer(buf, len);
}

void FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::onDataAvailable(
    const folly::SocketAddress& client,
    size_t len,
    bool truncated,
    folly::AsyncUDPSocket::ReadCallback::OnDataAvailableParams
        params) noexcept {
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  // TODO: Can this be moved to a static compile time check?
  CHECK_EQ(
      QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams::kCmsgSpace,
      folly::AsyncUDPSocket::ReadCallback::OnDataAvailableParams::kCmsgSpace);
#endif
  QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams localParams;
  localParams.gro = params.gro;
  localParams.tos = params.tos;
  if (params.ts) {
    localParams.ts.emplace(*params.ts);
  }

  return wrappedReadCallback_->onDataAvailable(
      client, len, truncated, localParams);
}

void FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::onNotifyDataAvailable(
    folly::AsyncUDPSocket&) noexcept {
  CHECK(parentSocket_ != nullptr);
  return wrappedReadCallback_->onNotifyDataAvailable(*parentSocket_);
}

bool FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::shouldOnlyNotify() {
  return wrappedReadCallback_->shouldOnlyNotify();
}

void FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::onReadError(
    const folly::AsyncSocketException& ex) noexcept {
  return wrappedReadCallback_->onReadError(ex);
}

void FollyQuicAsyncUDPSocket::FollyReadCallbackWrapper::
    onReadClosed() noexcept {
  return wrappedReadCallback_->onReadClosed();
}

// FollyErrMessageCallbackWrapper implementation
void FollyQuicAsyncUDPSocket::FollyErrCallbackWrapper::errMessage(
    const cmsghdr& cmsg) noexcept {
  return wrappedErrorCallback_->errMessage(cmsg);
}

void FollyQuicAsyncUDPSocket::FollyErrCallbackWrapper::errMessageError(
    const folly::AsyncSocketException& ex) noexcept {
  return wrappedErrorCallback_->errMessageError(ex);
}

} // namespace quic
