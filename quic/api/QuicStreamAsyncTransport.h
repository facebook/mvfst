/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/io/Cursor.h>
#include <folly/io/async/AsyncTransport.h>
#include <quic/api/QuicSocket.h>

/**
 * Adaptor for multiplexing over quic an existing use-case that
 * expects and AsyncTransportWrapper
 */

namespace quic {

class QuicStreamAsyncTransport : public folly::AsyncTransportWrapper,
                                 public QuicSocket::ReadCallback,
                                 public QuicSocket::WriteCallback,
                                 public folly::EventBase::LoopCallback {
 public:
  using UniquePtr = std::unique_ptr<
      QuicStreamAsyncTransport,
      folly::DelayedDestruction::Destructor>;

  void setReadCB(AsyncTransportWrapper::ReadCallback* callback) override {
    readCb_ = callback;
    // It should be ok to do this immediately, rather than in the loop
    handleRead();
  }

  AsyncTransportWrapper::ReadCallback* getReadCallback() const override {
    return readCb_;
  }

  void write(
      AsyncTransportWrapper::WriteCallback* callback,
      const void* buf,
      size_t bytes,
      folly::WriteFlags /*flags*/ = folly::WriteFlags::NONE) override {
    // TODO handle cork
    auto streamWriteOffset = sock_->getStreamWriteOffset(id_);
    if (streamWriteOffset.hasError()) {
      folly::AsyncSocketException ex(
          folly::AsyncSocketException::UNKNOWN,
          folly::to<std::string>(
              "Quic write error: ", toString(streamWriteOffset.error())));
      callback->writeErr(0, ex);
      return;
    }

    writeBuf_.append(folly::IOBuf::wrapBuffer(buf, bytes));
    writeCallbacks_.emplace_back(*streamWriteOffset + bytes, callback);
    sock_->notifyPendingWriteOnStream(id_, this);
  }

  void writev(
      AsyncTransportWrapper::WriteCallback* callback,
      const iovec* vec,
      size_t count,
      folly::WriteFlags /*flags*/ = folly::WriteFlags::NONE) override {
    size_t totalBytes = 0;
    for (size_t i = 0; i < count; i++) {
      writeBuf_.append(
          folly::IOBuf::wrapBuffer(vec[i].iov_base, vec[i].iov_len));
      totalBytes += vec[i].iov_len;
    }
    auto streamWriteOffset = sock_->getStreamWriteOffset(id_);
    if (streamWriteOffset.hasError()) {
      folly::AsyncSocketException ex(
          folly::AsyncSocketException::UNKNOWN,
          folly::to<std::string>(
              "Quic write error: ", toString(streamWriteOffset.error())));
      callback->writeErr(0, ex);
      return;
    }

    writeCallbacks_.emplace_back(*streamWriteOffset + totalBytes, callback);
    sock_->notifyPendingWriteOnStream(id_, this);
  }

  void writeChain(
      AsyncTransportWrapper::WriteCallback* callback,
      std::unique_ptr<folly::IOBuf>&& buf,
      folly::WriteFlags /*flags*/ = folly::WriteFlags::NONE) override {
    auto streamWriteOffset = sock_->getStreamWriteOffset(id_);
    if (streamWriteOffset.hasError()) {
      folly::AsyncSocketException ex(
          folly::AsyncSocketException::UNKNOWN,
          folly::to<std::string>(
              "Quic write error: ", toString(streamWriteOffset.error())));
      callback->writeErr(0, ex);
      return;
    }

    writeCallbacks_.emplace_back(
        *streamWriteOffset + buf->computeChainDataLength(), callback);
    writeBuf_.append(std::move(buf));
    sock_->notifyPendingWriteOnStream(id_, this);
  }

  void close() override {
    shutdownWrite();
    if (readCb_ && readEOF_ != EOFState::DELIVERED) {
      // This is such a bizarre operation.  I almost think if we haven't seen
      // a fin then we should readErr instead of readEOF, this mirrors
      // AsyncSocket though
      readEOF_ = EOFState::QUEUED;
      handleRead();
    }
  }

  void closeNow() override {
    if (writeBuf_.empty()) {
      close();
    } else {
      sock_->resetStream(id_, quic::GenericApplicationErrorCode::UNKNOWN);
      VLOG(4) << "Reset stream from closeNow";
    }
  }

  void closeWithReset() override {
    sock_->resetStream(id_, quic::GenericApplicationErrorCode::UNKNOWN);
    VLOG(4) << "Reset stream from closeWithReset";
  }

  void shutdownWrite() override {
    if (writeEOF_ == EOFState::NOT_SEEN) {
      writeEOF_ = EOFState::QUEUED;
      sock_->notifyPendingWriteOnStream(id_, this);
    }
  }

  void shutdownWriteNow() override {
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

  bool good() const override {
    return (
        !ex_ &&
        (readEOF_ == EOFState::NOT_SEEN || writeEOF_ == EOFState::NOT_SEEN));
  }

  bool readable() const override {
    return !ex_ && readEOF_ == EOFState::NOT_SEEN;
  }

  bool writable() const override {
    return !ex_ && writeEOF_ == EOFState::NOT_SEEN;
  }

  bool isPending() const override {
    return false;
  }

  bool connecting() const override {
    return false;
  }

  virtual bool error() const override {
    return bool(ex_);
  }

  folly::EventBase* getEventBase() const override {
    return sock_->getEventBase();
  }

  void attachEventBase(folly::EventBase* /*eventBase*/) override {
    LOG(FATAL) << "Does QUICSocket support this?";
  }

  void detachEventBase() override {
    LOG(FATAL) << "Does QUICSocket support this?";
  }

  bool isDetachable() const override {
    return false; // ?
  }

  void setSendTimeout(uint32_t /*milliseconds*/) override {
    // QuicSocket needs this
  }

  uint32_t getSendTimeout() const override {
    return 0;
  }

  void getLocalAddress(folly::SocketAddress* /*address*/) const override {
    // QuicSocket needs this
  }

  void getPeerAddress(folly::SocketAddress* /*address*/) const override {
    // QuicSocket needs this
  }

  bool isEorTrackingEnabled() const override {
    return false;
  }

  void setEorTracking(bool /*track*/) override {}

  size_t getAppBytesWritten() const override {
    auto res = sock_->getStreamWriteOffset(id_);
    return res.hasError() ? 0 : res.value();
  }

  size_t getRawBytesWritten() const override {
    auto res = sock_->getStreamWriteOffset(id_);
    return res.hasError() ? 0 : res.value();
  }

  size_t getAppBytesReceived() const override {
    auto res = sock_->getStreamReadOffset(id_);
    return res.hasError() ? 0 : res.value();
  }

  size_t getRawBytesReceived() const override {
    auto res = sock_->getStreamReadOffset(id_);
    return res.hasError() ? 0 : res.value();
  }

  std::string getApplicationProtocol() const noexcept override {
    return "h1q";
  }

  std::string getSecurityProtocol() const override {
    return "quic/tls1.3";
  }

  QuicStreamAsyncTransport(
      std::shared_ptr<quic::QuicSocket> sock,
      quic::StreamId id)
      : sock_(std::move(sock)), id_(id) {}

  ~QuicStreamAsyncTransport() {
    sock_->setReadCallback(id_, nullptr);
    closeNow();
  }

 private:
  void readAvailable(quic::StreamId /*streamId*/) noexcept override {
    CHECK(readCb_);
    // defer the actual read until the loop callback.  This prevents possible
    // tail recursion with readAvailable -> setReadCallback -> readAvailable
    sock_->getEventBase()->runInLoop(this, true);
  }

  void readError(
      quic::StreamId /*streamId*/,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
          error) noexcept override {
    ex_ = folly::AsyncSocketException(
        folly::AsyncSocketException::UNKNOWN,
        folly::to<std::string>("Quic read error: ", toString(error)));
    sock_->getEventBase()->runInLoop(this, true);
    // RST here?
  }

  void runLoopCallback() noexcept override {
    handleRead();
  }

  void handleRead() {
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
            folly::to<std::string>("Quic read error: ", (int)readData.error()));
      } else {
        size_t readLen = 0;
        if (readData->first) {
          readLen = readData->first->computeChainDataLength();
          emptyRead = (readLen == 0);
        } else {
          emptyRead = true;
        }
        if (!emptyRead) {
          if (readCb_->isBufferMovable()) {
            readCb_->readBufferAvailable(std::move(readData->first));
          } else {
            folly::io::Cursor c(readData->first.get());
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

  void send(uint64_t maxToSend) {
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
    if (res.hasValue()) {
      if (res.value()) {
        sentOffset -= res.value()->computeChainDataLength();
        auto tail = writeBuf_.move();
        writeBuf_.append(std::move(res.value()));
        writeBuf_.append(std::move(tail));
      } else if (writeEOF) {
        writeEOF_ = EOFState::DELIVERED;
        VLOG(4) << "Closed stream id_=" << id_;
      }
      // not actually sent.  Mirrors AsyncSocket and invokes when data is in
      // transport buffers
      invokeWriteCallbacks(sentOffset);
    } else {
      // handle error
      folly::AsyncSocketException ex(
          folly::AsyncSocketException::UNKNOWN,
          folly::to<std::string>("Quic write error: ", toString(res.error())));
      failWrites(ex);
    }
  }

  void invokeWriteCallbacks(size_t sentOffset) {
    while (!writeCallbacks_.empty() &&
           writeCallbacks_.front().first <= sentOffset) {
      auto wcb = writeCallbacks_.front().second;
      writeCallbacks_.pop_front();
      wcb->writeSuccess();
    }
  }

  void failWrites(folly::AsyncSocketException& ex) {
    while (!writeCallbacks_.empty()) {
      auto& front = writeCallbacks_.front();
      auto wcb = front.second;
      writeCallbacks_.pop_front();
      wcb->writeErr(0, ex);
    }
  }

  void onStreamWriteReady(
      quic::StreamId /*id*/,
      uint64_t maxToSend) noexcept override {
    if (writeEOF_ == EOFState::DELIVERED && writeBuf_.empty()) {
      // nothing left to write
      return;
    }
    send(maxToSend);
  }

  void onStreamWriteError(
      StreamId /*id*/,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
          error) noexcept override {
    folly::AsyncSocketException ex(
        folly::AsyncSocketException::UNKNOWN,
        folly::to<std::string>("Quic write error: ", toString(error)));
    failWrites(ex);
  }

  std::shared_ptr<quic::QuicSocket> sock_;
  quic::StreamId id_;
  enum class EOFState { NOT_SEEN, QUEUED, DELIVERED };
  EOFState readEOF_{EOFState::NOT_SEEN};
  EOFState writeEOF_{EOFState::NOT_SEEN};
  AsyncTransportWrapper::ReadCallback* readCb_{nullptr};
  folly::IOBufQueue writeBuf_{folly::IOBufQueue::cacheChainLength()};
  std::deque<std::pair<size_t, AsyncTransportWrapper::WriteCallback*>>
      writeCallbacks_;
  folly::Optional<folly::AsyncSocketException> ex_;
};
} // namespace quic
