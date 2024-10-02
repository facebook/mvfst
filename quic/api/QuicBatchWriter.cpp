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

// SinglePacketBatchWriter
void SinglePacketBatchWriter::reset() {
  buf_.reset();
}

bool SinglePacketBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t /*unused*/,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocket* /*unused*/) {
  buf_ = std::move(buf);

  // needs to be flushed
  return true;
}

ssize_t SinglePacketBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  iovec vec[kNumIovecBufferChains];
  size_t iovec_len = fillIovec(buf_, vec);
  return sock.write(address, vec, iovec_len);
}

// SinglePacketInplaceBatchWriter
void SinglePacketInplaceBatchWriter::reset() {
  conn_.bufAccessor->clear();
}

bool SinglePacketInplaceBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& /* buf */,
    size_t /*unused*/,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocket* /*unused*/) {
  // Always flush. This should trigger a write afterwards.
  return true;
}

ssize_t SinglePacketInplaceBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  auto& buf = conn_.bufAccessor->buf();
  CHECK(!conn_.bufAccessor->isChained());

  iovec vec[kNumIovecBufferChains];
  size_t iovec_len = fillIovec(buf, vec);
  auto ret = sock.write(address, vec, iovec_len);
  conn_.bufAccessor->clear();
  return ret;
}

bool SinglePacketInplaceBatchWriter::empty() const {
  return conn_.bufAccessor->length() == 0;
}

// SinglePacketBackpressureBatchWriter
SinglePacketBackpressureBatchWriter::SinglePacketBackpressureBatchWriter(
    QuicConnectionStateBase& conn)
    : conn_(conn) {
  // If we have a write to retry from a previous attempt, pick that up.
  if (conn_.pendingWriteBatch_.buf) {
    buf_.swap(conn_.pendingWriteBatch_.buf);
    lastWriteSuccessful_ = false;
  }
}

SinglePacketBackpressureBatchWriter::~SinglePacketBackpressureBatchWriter() {
  if (buf_ && !buf_->empty()) {
    conn_.pendingWriteBatch_.buf.swap(buf_);
  }
}

void SinglePacketBackpressureBatchWriter::reset() {
  // Only clear the buffer if it's been written successfully.
  // Otherwise, retain it so it can be retried.
  if (lastWriteSuccessful_) {
    buf_.reset(nullptr);
  }
}

bool SinglePacketBackpressureBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t /* unused */,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocket* /*unused*/) {
  buf_ = std::move(buf);

  // needs to be flushed
  return true;
}

ssize_t SinglePacketBackpressureBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  iovec vec[kNumIovecBufferChains];
  size_t iovec_len = fillIovec(buf_, vec);
  auto written = sock.write(address, vec, iovec_len);
  lastWriteSuccessful_ = written > 0;
  return written;
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
    QuicAsyncUDPSocket* /*unused*/) {
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
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  CHECK_GT(bufs_.size(), 0);
  if (bufs_.size() == 1) {
    iovec vec[kNumIovecBufferChains];
    size_t iovec_len = fillIovec(bufs_.at(0), vec);
    return sock.write(address, vec, iovec_len);
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
