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

void BatchWriter::setSock(QuicAsyncUDPSocketType* sock) {
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
    QuicAsyncUDPSocketType* /*unused*/) {
  buf_ = std::move(buf);

  // needs to be flushed
  return true;
}

ssize_t SinglePacketBatchWriter::write(
    QuicAsyncUDPSocketType& sock,
    const folly::SocketAddress& address) {
  return sock.write(address, buf_);
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
    QuicAsyncUDPSocketType* /*unused*/) {
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
    QuicAsyncUDPSocketType& sock,
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

} // namespace quic
