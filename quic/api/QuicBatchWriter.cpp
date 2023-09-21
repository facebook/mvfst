/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriter.h>

namespace quic {
// BatchWriter
bool BatchWriter::needsFlush(size_t /*unused*/) {
  return false;
}

void BatchWriter::setSock(QuicAsyncUDPSocketWrapper* sock) {
  if (sock && !evb_.getBackingEventBase()) {
    fd_ = ::dup(getSocketFd(*sock));
    evb_.setBackingEventBase(sock->getEventBase());
  }
}

QuicEventBase* BatchWriter::evb() {
  return &evb_;
}

int BatchWriter::getAndResetFd() {
  auto ret = fd_;
  fd_ = -1;

  return ret;
}

// SinglePacketBatchWriter
void SinglePacketBatchWriter::reset() {
  buf_.reset();
}

bool SinglePacketBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t /*unused*/,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocketWrapper* /*unused*/) {
  buf_ = std::move(buf);

  // needs to be flushed
  return true;
}

ssize_t SinglePacketBatchWriter::write(
    QuicAsyncUDPSocketWrapper& sock,
    const folly::SocketAddress& address) {
  return sock.write(address, buf_);
}

// SinglePacketInplaceBatchWriter
void SinglePacketInplaceBatchWriter::reset() {
  ScopedBufAccessor scopedBufAccessor(conn_.bufAccessor);
  auto& buf = scopedBufAccessor.buf();
  buf->clear();
}

bool SinglePacketInplaceBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& /* buf */,
    size_t /*unused*/,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocketWrapper* /*unused*/) {
  // Always flush. This should trigger a write afterwards.
  return true;
}

ssize_t SinglePacketInplaceBatchWriter::write(
    QuicAsyncUDPSocketWrapper& sock,
    const folly::SocketAddress& address) {
  ScopedBufAccessor scopedBufAccessor(conn_.bufAccessor);
  auto& buf = scopedBufAccessor.buf();
  CHECK(!buf->isChained());
  auto ret = sock.write(address, buf);
  buf->clear();
  return ret;
}

bool SinglePacketInplaceBatchWriter::empty() const {
  ScopedBufAccessor scopedBufAccessor(conn_.bufAccessor);
  auto& buf = scopedBufAccessor.buf();
  return buf->length() == 0;
}

// SendmmsgPacketBatchWriter
SendmmsgPacketBatchWriter::SendmmsgPacketBatchWriter(size_t maxBufs)
    : maxBufs_(maxBufs) {
  bufs_.reserve(maxBufs);
}

bool SendmmsgPacketBatchWriter::empty() const {
  return !currSize_;
}

size_t SendmmsgPacketBatchWriter::size() const {
  return currSize_;
}

void SendmmsgPacketBatchWriter::reset() {
  bufs_.clear();
  currSize_ = 0;
}

bool SendmmsgPacketBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t size,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocketWrapper* /*unused*/) {
  CHECK_LT(bufs_.size(), maxBufs_);
  bufs_.emplace_back(std::move(buf));
  currSize_ += size;

  // reached max buffers
  if (FOLLY_UNLIKELY(bufs_.size() == maxBufs_)) {
    return true;
  }

  // does not need to be flushed yet
  return false;
}

ssize_t SendmmsgPacketBatchWriter::write(
    QuicAsyncUDPSocketWrapper& sock,
    const folly::SocketAddress& address) {
  CHECK_GT(bufs_.size(), 0);
  if (bufs_.size() == 1) {
    return sock.write(address, bufs_[0]);
  }

  int ret = sock.writem(
      folly::range(&address, &address + 1), bufs_.data(), bufs_.size());

  if (ret <= 0) {
    return ret;
  }

  if (static_cast<size_t>(ret) == bufs_.size()) {
    return currSize_;
  }

  // this is a partial write - we just need to
  // return a different number than currSize_
  return 0;
}

bool useSinglePacketInplaceBatchWriter(
    uint32_t maxBatchSize,
    quic::DataPathType dataPathType) {
  return maxBatchSize == 1 &&
      dataPathType == quic::DataPathType::ContinuousMemory;
}

} // namespace quic
