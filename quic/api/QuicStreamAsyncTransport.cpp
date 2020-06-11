/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/QuicStreamAsyncTransport.h>

#include <folly/io/Cursor.h>

namespace quic {

QuicStreamAsyncTransport::UniquePtr
QuicStreamAsyncTransport::createWithNewStream(
    std::shared_ptr<quic::QuicSocket> sock) {
  auto streamId = sock->createBidirectionalStream();
  if (!streamId) {
    return nullptr;
  }
  UniquePtr ptr(
      new QuicStreamAsyncTransport(std::move(sock), streamId.value()));
  return ptr;
}

QuicStreamAsyncTransport::UniquePtr
QuicStreamAsyncTransport::createWithExistingStream(
    std::shared_ptr<quic::QuicSocket> sock,
    quic::StreamId streamId) {
  UniquePtr ptr(new QuicStreamAsyncTransport(std::move(sock), streamId));
  return ptr;
}

QuicStreamAsyncTransport::QuicStreamAsyncTransport(
    std::shared_ptr<quic::QuicSocket> sock,
    quic::StreamId id)
    : sock_(std::move(sock)), id_(id) {}

QuicStreamAsyncTransport::~QuicStreamAsyncTransport() {
  sock_->setReadCallback(id_, nullptr);
  closeWithReset();
}

void QuicStreamAsyncTransport::setReadCB(
    AsyncTransport::ReadCallback* callback) {
  readCb_ = callback;
  // It should be ok to do this immediately, rather than in the loop
  handleRead();
}

folly::AsyncTransport::ReadCallback* QuicStreamAsyncTransport::getReadCallback()
    const {
  return readCb_;
}

void QuicStreamAsyncTransport::addWriteCallback(
    AsyncTransport::WriteCallback* callback,
    size_t offset,
    size_t size) {
  writeCallbacks_.emplace_back(offset + size, callback);
  sock_->notifyPendingWriteOnStream(id_, this);
}

void QuicStreamAsyncTransport::handleOffsetError(
    AsyncTransport::WriteCallback* callback,
    LocalErrorCode error) {
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::UNKNOWN,
      folly::to<std::string>("Quic write error: ", toString(error)));
  callback->writeErr(0, ex);
}

void QuicStreamAsyncTransport::write(
    AsyncTransport::WriteCallback* callback,
    const void* buf,
    size_t bytes,
    folly::WriteFlags /*flags*/) {
  auto streamWriteOffset = sock_->getStreamWriteOffset(id_);
  if (streamWriteOffset.hasError()) {
    handleOffsetError(callback, streamWriteOffset.error());
    return;
  }
  writeBuf_.append(folly::IOBuf::wrapBuffer(buf, bytes));
  addWriteCallback(callback, *streamWriteOffset, bytes);
}

void QuicStreamAsyncTransport::writev(
    AsyncTransport::WriteCallback* callback,
    const iovec* vec,
    size_t count,
    folly::WriteFlags /*flags*/) {
  auto streamWriteOffset = sock_->getStreamWriteOffset(id_);
  if (streamWriteOffset.hasError()) {
    handleOffsetError(callback, streamWriteOffset.error());
    return;
  }
  size_t totalBytes = 0;
  for (size_t i = 0; i < count; i++) {
    writeBuf_.append(folly::IOBuf::wrapBuffer(vec[i].iov_base, vec[i].iov_len));
    totalBytes += vec[i].iov_len;
  }
  addWriteCallback(callback, *streamWriteOffset, totalBytes);
}

void QuicStreamAsyncTransport::writeChain(
    AsyncTransport::WriteCallback* callback,
    std::unique_ptr<folly::IOBuf>&& buf,
    folly::WriteFlags /*flags*/) {
  auto streamWriteOffset = sock_->getStreamWriteOffset(id_);
  if (streamWriteOffset.hasError()) {
    handleOffsetError(callback, streamWriteOffset.error());
    return;
  }
  size_t len = buf->computeChainDataLength();
  writeBuf_.append(std::move(buf));
  addWriteCallback(callback, *streamWriteOffset, len);
}

void QuicStreamAsyncTransport::close() {
  sock_->stopSending(id_, quic::GenericApplicationErrorCode::UNKNOWN);
  shutdownWrite();
  if (readCb_ && readEOF_ != EOFState::DELIVERED) {
    // This is such a bizarre operation.  I almost think if we haven't seen
    // a fin then we should readErr instead of readEOF, this mirrors
    // AsyncSocket though
    readEOF_ = EOFState::QUEUED;
    handleRead();
  }
}

void QuicStreamAsyncTransport::closeNow() {
  if (writeBuf_.empty()) {
    close();
  } else {
    sock_->stopSending(id_, quic::GenericApplicationErrorCode::UNKNOWN);
    sock_->resetStream(id_, quic::GenericApplicationErrorCode::UNKNOWN);
    VLOG(4) << "Reset stream from closeNow";
  }
}

void QuicStreamAsyncTransport::closeWithReset() {
  sock_->stopSending(id_, quic::GenericApplicationErrorCode::UNKNOWN);
  sock_->resetStream(id_, quic::GenericApplicationErrorCode::UNKNOWN);
  VLOG(4) << "Reset stream from closeWithReset";
}

void QuicStreamAsyncTransport::shutdownWrite() {
  if (writeEOF_ == EOFState::NOT_SEEN) {
    writeEOF_ = EOFState::QUEUED;
    sock_->notifyPendingWriteOnStream(id_, this);
  }
}

void QuicStreamAsyncTransport::shutdownWriteNow() {
  if (readEOF_ == EOFState::DELIVERED) {
    // writes already shutdown
    return;
  }
  if (writeBuf_.empty()) {
    shutdownWrite();
  } else {
    sock_->resetStream(id_, quic::GenericApplicationErrorCode::UNKNOWN);
    VLOG(4) << "Reset stream from shutdownWriteNow";
  }
}

bool QuicStreamAsyncTransport::good() const {
  return (
      !ex_ &&
      (readEOF_ == EOFState::NOT_SEEN || writeEOF_ == EOFState::NOT_SEEN));
}

bool QuicStreamAsyncTransport::readable() const {
  return !ex_ && readEOF_ == EOFState::NOT_SEEN;
}

bool QuicStreamAsyncTransport::writable() const {
  return !ex_ && writeEOF_ == EOFState::NOT_SEEN;
}

bool QuicStreamAsyncTransport::isPending() const {
  return false;
}

bool QuicStreamAsyncTransport::connecting() const {
  return false;
}

bool QuicStreamAsyncTransport::error() const {
  return bool(ex_);
}

folly::EventBase* QuicStreamAsyncTransport::getEventBase() const {
  return sock_->getEventBase();
}

void QuicStreamAsyncTransport::attachEventBase(
    folly::EventBase* /*eventBase*/) {
  LOG(FATAL) << "Does QUICSocket support this?";
}

void QuicStreamAsyncTransport::detachEventBase() {
  LOG(FATAL) << "Does QUICSocket support this?";
}

bool QuicStreamAsyncTransport::isDetachable() const {
  return false; // ?
}

void QuicStreamAsyncTransport::setSendTimeout(uint32_t /*milliseconds*/) {
  // QuicSocket needs this
}

uint32_t QuicStreamAsyncTransport::getSendTimeout() const {
  // TODO: follow up on getSendTimeout() use, 0 indicates that no timeout is
  // set.
  return 0;
}

void QuicStreamAsyncTransport::getLocalAddress(
    folly::SocketAddress* address) const {
  *address = sock_->getLocalAddress();
}

void QuicStreamAsyncTransport::getPeerAddress(
    folly::SocketAddress* address) const {
  *address = sock_->getPeerAddress();
}

bool QuicStreamAsyncTransport::isEorTrackingEnabled() const {
  return false;
}

void QuicStreamAsyncTransport::setEorTracking(bool /*track*/) {}

size_t QuicStreamAsyncTransport::getAppBytesWritten() const {
  auto res = sock_->getStreamWriteOffset(id_);
  // TODO: track written bytes to have it available after QUIC stream closure
  return res.hasError() ? 0 : res.value();
}

size_t QuicStreamAsyncTransport::getRawBytesWritten() const {
  auto res = sock_->getStreamWriteOffset(id_);
  // TODO: track written bytes to have it available after QUIC stream closure
  return res.hasError() ? 0 : res.value();
}

size_t QuicStreamAsyncTransport::getAppBytesReceived() const {
  auto res = sock_->getStreamReadOffset(id_);
  // TODO: track read bytes to have it available after QUIC stream closure
  return res.hasError() ? 0 : res.value();
}

size_t QuicStreamAsyncTransport::getRawBytesReceived() const {
  auto res = sock_->getStreamReadOffset(id_);
  // TODO: track read bytes to have it available after QUIC stream closure
  return res.hasError() ? 0 : res.value();
}

std::string QuicStreamAsyncTransport::getApplicationProtocol() const noexcept {
  return sock_->getAppProtocol().value_or("");
}

std::string QuicStreamAsyncTransport::getSecurityProtocol() const {
  return "quic/tls1.3";
}

void QuicStreamAsyncTransport::readAvailable(
    quic::StreamId /*streamId*/) noexcept {
  CHECK(readCb_);
  // defer the actual read until the loop callback.  This prevents possible
  // tail recursion with readAvailable -> setReadCallback -> readAvailable
  sock_->getEventBase()->runInLoop(this, true);
}

void QuicStreamAsyncTransport::readError(
    quic::StreamId /*streamId*/,
    std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
        error) noexcept {
  ex_ = folly::AsyncSocketException(
      folly::AsyncSocketException::UNKNOWN,
      folly::to<std::string>("Quic read error: ", toString(error)));
  sock_->getEventBase()->runInLoop(this, true);
  // TODO: RST here?
}

void QuicStreamAsyncTransport::runLoopCallback() noexcept {
  handleRead();
}

void QuicStreamAsyncTransport::handleRead() {
  folly::DelayedDestruction::DestructorGuard dg(this);
  bool emptyRead = false;
  size_t numReads = 0;
  while (readCb_ && !ex_ && readEOF_ == EOFState::NOT_SEEN && !emptyRead &&
         ++numReads < 16 /* max reads per event */) {
    void* buf = nullptr;
    size_t len = 0;
    if (readCb_->isBufferMovable()) {
      len = readCb_->maxBufferSize();
    } else {
      readCb_->getReadBuffer(&buf, &len);
      if (buf == nullptr || len == 0) {
        ex_ = folly::AsyncSocketException(
            folly::AsyncSocketException::BAD_ARGS,
            "ReadCallback::getReadBuffer() returned empty buffer");
        break;
      }
    }
    auto readData = sock_->read(id_, len);
    if (readData.hasError()) {
      ex_ = folly::AsyncSocketException(
          folly::AsyncSocketException::UNKNOWN,
          folly::to<std::string>("Quic read error: ", readData.error()));
    } else {
      if (!readData->first) {
        emptyRead = true;
      } else {
        if (readCb_->isBufferMovable()) {
          readCb_->readBufferAvailable(std::move(readData->first));
        } else {
          size_t readLen = readData->first->computeChainDataLength();
          folly::io::Cursor c(readData->first.get());
          CHECK_NOTNULL(buf);
          c.pull(buf, readLen);
          readCb_->readDataAvailable(readLen);
        }
      }
      if (readData->second && readEOF_ == EOFState::NOT_SEEN) {
        readEOF_ = EOFState::QUEUED;
      }
    }
  }
  if (readCb_) {
    if (ex_) {
      auto cb = readCb_;
      readCb_ = nullptr;
      cb->readErr(*ex_);
    } else if (readEOF_ == EOFState::QUEUED) {
      auto cb = readCb_;
      readCb_ = nullptr;
      cb->readEOF();
      readEOF_ = EOFState::DELIVERED;
    }
  }
  if (readCb_ && readEOF_ == EOFState::NOT_SEEN && !ex_) {
    sock_->setReadCallback(id_, this);
  } else {
    sock_->setReadCallback(id_, nullptr);
  }
}

void QuicStreamAsyncTransport::send(uint64_t maxToSend) {
  // overkill until there are delivery cbs
  folly::DelayedDestruction::DestructorGuard dg(this);
  uint64_t toSend =
      std::min(maxToSend, folly::to<uint64_t>(writeBuf_.chainLength()));
  auto streamWriteOffset = sock_->getStreamWriteOffset(id_);
  if (streamWriteOffset.hasError()) {
    // handle error
    folly::AsyncSocketException ex(
        folly::AsyncSocketException::UNKNOWN,
        folly::to<std::string>(
            "Quic write error: ", toString(streamWriteOffset.error())));
    failWrites(ex);
    return;
  }

  uint64_t sentOffset = *streamWriteOffset + toSend;
  bool writeEOF = (writeEOF_ == EOFState::QUEUED);
  auto res = sock_->writeChain(
      id_,
      writeBuf_.split(toSend),
      writeEOF,
      false,
      nullptr); // no delivery callbacks right now
  if (res.hasError()) {
    folly::AsyncSocketException ex(
        folly::AsyncSocketException::UNKNOWN,
        folly::to<std::string>("Quic write error: ", toString(res.error())));
    failWrites(ex);
  } else {
    if (writeEOF) {
      writeEOF_ = EOFState::DELIVERED;
      VLOG(4) << "Closed stream id_=" << id_;
    }
    // not actually sent.  Mirrors AsyncSocket and invokes when data is in
    // transport buffers
    invokeWriteCallbacks(sentOffset);
  }
}

void QuicStreamAsyncTransport::invokeWriteCallbacks(size_t sentOffset) {
  while (!writeCallbacks_.empty() &&
         writeCallbacks_.front().first <= sentOffset) {
    auto wcb = writeCallbacks_.front().second;
    writeCallbacks_.pop_front();
    wcb->writeSuccess();
  }
}

void QuicStreamAsyncTransport::failWrites(folly::AsyncSocketException& ex) {
  while (!writeCallbacks_.empty()) {
    auto& front = writeCallbacks_.front();
    auto wcb = front.second;
    writeCallbacks_.pop_front();
    // TODO: track bytesWritten, when buffer was split it may not be 0
    wcb->writeErr(0, ex);
  }
}

void QuicStreamAsyncTransport::onStreamWriteReady(
    quic::StreamId /*id*/,
    uint64_t maxToSend) noexcept {
  if (writeEOF_ == EOFState::DELIVERED && writeBuf_.empty()) {
    // nothing left to write
    return;
  }
  send(maxToSend);
}

void QuicStreamAsyncTransport::onStreamWriteError(
    StreamId /*id*/,
    std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
        error) noexcept {
  folly::AsyncSocketException ex(
      folly::AsyncSocketException::UNKNOWN,
      folly::to<std::string>("Quic write error: ", toString(error)));
  failWrites(ex);
}

} // namespace quic
