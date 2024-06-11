/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <memory>

namespace quic {

void FollyQuicAsyncUDPSocket::init(sa_family_t family) {
  follySocket_.init(family);
}

void FollyQuicAsyncUDPSocket::bind(const folly::SocketAddress& address) {
  follySocket_.bind(address);
}
[[nodiscard]] bool FollyQuicAsyncUDPSocket::isBound() const {
  return follySocket_.isBound();
}

void FollyQuicAsyncUDPSocket::connect(const folly::SocketAddress& address) {
  follySocket_.connect(address);
}

void FollyQuicAsyncUDPSocket::close() {
  follySocket_.close();
}

void FollyQuicAsyncUDPSocket::resumeRead(ReadCallback* callback) {
  // TODO: We could skip this check and rely on the one in AsyncUDPSocket
  CHECK(!readCallbackWrapper_) << "Already registered a read callback";
  readCallbackWrapper_ =
      std::make_unique<FollyReadCallbackWrapper>(callback, this);
  follySocket_.resumeRead(readCallbackWrapper_.get());
}

void FollyQuicAsyncUDPSocket::pauseRead() {
  follySocket_.pauseRead();
  readCallbackWrapper_.reset();
}

void FollyQuicAsyncUDPSocket::setErrMessageCallback(
    ErrMessageCallback* callback) {
  if (errCallbackWrapper_) {
    errCallbackWrapper_.reset();
  }
  if (callback) {
    errCallbackWrapper_ = std::make_unique<FollyErrCallbackWrapper>(callback);
    follySocket_.setErrMessageCallback(errCallbackWrapper_.get());
  } else {
    follySocket_.setErrMessageCallback(nullptr);
  }
}

ssize_t FollyQuicAsyncUDPSocket::write(
    const folly::SocketAddress& address,
    const std::unique_ptr<folly::IOBuf>& buf) {
  return follySocket_.write(address, buf);
}

int FollyQuicAsyncUDPSocket::writem(
    folly::Range<folly::SocketAddress const*> addrs,
    const std::unique_ptr<folly::IOBuf>* bufs,
    size_t count) {
  return follySocket_.writem(addrs, bufs, count);
}

ssize_t FollyQuicAsyncUDPSocket::writeGSO(
    const folly::SocketAddress& address,
    const std::unique_ptr<folly::IOBuf>& buf,
    WriteOptions options) {
  folly::AsyncUDPSocket::WriteOptions follyOptions(
      options.gso, options.zerocopy);
  follyOptions.txTime = options.txTime;
  return follySocket_.writeGSO(address, buf, follyOptions);
}

int FollyQuicAsyncUDPSocket::writemGSO(
    folly::Range<folly::SocketAddress const*> addrs,
    const std::unique_ptr<folly::IOBuf>* bufs,
    size_t count,
    const WriteOptions* options) {
  std::vector<folly::AsyncUDPSocket::WriteOptions> follyOptions(count);
  for (size_t i = 0; i < count; ++i) {
    follyOptions[i].gso = options[i].gso;
    follyOptions[i].zerocopy = options[i].zerocopy;
    follyOptions[i].txTime = options[i].txTime;
  }
  return follySocket_.writemGSO(addrs, bufs, count, follyOptions.data());
}

ssize_t FollyQuicAsyncUDPSocket::recvmsg(struct msghdr* msg, int flags) {
  return follySocket_.recvmsg(msg, flags);
}

int FollyQuicAsyncUDPSocket::recvmmsg(
    struct mmsghdr* msgvec,
    unsigned int vlen,
    unsigned int flags,
    struct timespec* timeout) {
  return follySocket_.recvmmsg(msgvec, vlen, flags, timeout);
}

int FollyQuicAsyncUDPSocket::getGSO() {
  return follySocket_.getGSO();
}

int FollyQuicAsyncUDPSocket::getGRO() {
  return follySocket_.getGRO();
}
bool FollyQuicAsyncUDPSocket::setGRO(bool bVal) {
  return follySocket_.setGRO(bVal);
}

void FollyQuicAsyncUDPSocket::setRecvTos(bool recvTos) {
  follySocket_.setRecvTos(recvTos);
}

bool FollyQuicAsyncUDPSocket::getRecvTos() {
  return follySocket_.getRecvTos();
}

void FollyQuicAsyncUDPSocket::setTosOrTrafficClass(uint8_t tos) {
  follySocket_.setTosOrTrafficClass(tos);
}

[[nodiscard]] const folly::SocketAddress& FollyQuicAsyncUDPSocket::address()
    const {
  return follySocket_.address();
}

void FollyQuicAsyncUDPSocket::attachEventBase(
    std::shared_ptr<QuicEventBase> evb) {
  CHECK(evb != nullptr);
  std::shared_ptr<FollyQuicEventBase> follyEvb =
      std::dynamic_pointer_cast<FollyQuicEventBase>(evb);
  CHECK(follyEvb != nullptr);
  evb_ = follyEvb;
  follySocket_.attachEventBase(follyEvb->getBackingEventBase());
}
void FollyQuicAsyncUDPSocket::detachEventBase() {
  follySocket_.detachEventBase();
}
[[nodiscard]] std::shared_ptr<QuicEventBase>
FollyQuicAsyncUDPSocket::getEventBase() const {
  if (evb_) {
    CHECK_EQ(evb_->getBackingEventBase(), follySocket_.getEventBase());
  }
  return evb_;
}

void FollyQuicAsyncUDPSocket::setCmsgs(const folly::SocketCmsgMap& cmsgs) {
  follySocket_.setCmsgs(cmsgs);
}
void FollyQuicAsyncUDPSocket::appendCmsgs(const folly::SocketCmsgMap& cmsgs) {
  follySocket_.appendCmsgs(cmsgs);
}
void FollyQuicAsyncUDPSocket::setAdditionalCmsgsFunc(
    folly::Function<Optional<folly::SocketCmsgMap>()>&& additionalCmsgsFunc) {
  follySocket_.setAdditionalCmsgsFunc(std::move(additionalCmsgsFunc));
}

int FollyQuicAsyncUDPSocket::getTimestamping() {
  return follySocket_.getTimestamping();
}

void FollyQuicAsyncUDPSocket::setReuseAddr(bool reuseAddr) {
  follySocket_.setReuseAddr(reuseAddr);
}

void FollyQuicAsyncUDPSocket::setDFAndTurnOffPMTU() {
  follySocket_.setDFAndTurnOffPMTU();
}

void FollyQuicAsyncUDPSocket::applyOptions(
    const folly::SocketOptionMap& options,
    folly::SocketOptionKey::ApplyPos pos) {
  follySocket_.applyOptions(options, pos);
}

void FollyQuicAsyncUDPSocket::setReusePort(bool reusePort) {
  follySocket_.setReusePort(reusePort);
}

void FollyQuicAsyncUDPSocket::setRcvBuf(int rcvBuf) {
  follySocket_.setRcvBuf(rcvBuf);
}

void FollyQuicAsyncUDPSocket::setSndBuf(int sndBuf) {
  follySocket_.setSndBuf(sndBuf);
}

void FollyQuicAsyncUDPSocket::setFD(int fd, FDOwnership ownership) {
  folly::AsyncUDPSocket::FDOwnership follyOwnership;
  switch (ownership) {
    case FDOwnership::OWNS:
      follyOwnership = folly::AsyncUDPSocket::FDOwnership::OWNS;
      break;
    case FDOwnership::SHARED:
      follyOwnership = folly::AsyncUDPSocket::FDOwnership::SHARED;
      break;
  }
  follySocket_.setFD(folly::NetworkSocket::fromFd(fd), follyOwnership);
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
